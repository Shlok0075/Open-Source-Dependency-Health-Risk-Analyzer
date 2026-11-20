"""Feature 1: Transitive Dependency Vulnerability Analysis.

For every direct dependency we ask deps.dev (free, no key) for its fully
resolved dependency graph, check every package in it against OSV.dev, and
return a tree that highlights vulnerable nested packages and the parent
packages that pull them in.
"""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import requests

from common import HEADERS, SEV_RANK, fetch_vulns, norm_name
from remediation import suggest_fix

DEPS_DEV = "https://api.deps.dev/v3/systems/%s/packages/%s/versions/%s:dependencies"
SYSTEMS = {"npm": "npm", "PyPI": "pypi"}
MAX_DEPTH = 12
_graph_cache = {}


# ---------------------------------------------------------------- fetching
def fetch_graph(eco, name, version):
    """Resolved dependency graph of one package version (cached), or raise."""
    key = (eco, norm_name(eco, name), version)
    if key in _graph_cache:
        return _graph_cache[key]
    url = DEPS_DEV % (SYSTEMS[eco], quote(norm_name(eco, name), safe=""), quote(version, safe=""))
    last = None
    for _ in range(2):
        try:
            r = requests.get(url, timeout=25, headers=HEADERS)
            if r.status_code == 200:
                _graph_cache[key] = r.json()
                return _graph_cache[key]
            last = "deps.dev returned %s" % r.status_code
            if r.status_code == 404:
                break
        except requests.RequestException as e:
            last = str(e)
    raise RuntimeError(last or "unknown error")


def parse_graph(raw):
    """deps.dev JSON -> nodes [(name, version)], children and parents lists.

    deps.dev leaves out zero values, so node 0 (the package itself) has no
    "fromNode"/"toNode" key in its edges.
    """
    nodes = [((n.get("versionKey") or {}).get("name"), (n.get("versionKey") or {}).get("version"))
             for n in raw.get("nodes", [])]
    kids = [[] for _ in nodes]
    parents = [[] for _ in nodes]
    for e in raw.get("edges", []):
        f, t = e.get("fromNode", 0), e.get("toNode", 0)
        if f != t and t not in kids[f]:
            kids[f].append(t)
            parents[t].append(f)
    return nodes, kids, parents


def osv_has_vulns(keys):
    """{(eco, name, version): bool} using OSV's batch endpoint (500 per call)."""
    out = {}
    for i in range(0, len(keys), 500):
        chunk = keys[i:i + 500]
        try:
            r = requests.post("https://api.osv.dev/v1/querybatch", timeout=60, headers=HEADERS,
                              json={"queries": [{"package": {"name": n, "ecosystem": e}, "version": v}
                                                for e, n, v in chunk]})
            results = r.json().get("results", [])
            for k, res in zip(chunk, results):
                out[k] = bool(res.get("vulns"))
            for k in chunk[len(results):]:
                out[k] = True
        except Exception:
            for k in chunk:            # batch failed -> check each one individually
                out[k] = True
    return out


# ---------------------------------------------------------------- analysis
def _shortest_paths(kids):
    """BFS from the root (node 0): parent pointer for every reachable node."""
    prev, seen, q = {0: None}, {0}, deque([0])
    while q:
        n = q.popleft()
        for c in kids[n]:
            if c not in seen:
                seen.add(c)
                prev[c] = n
                q.append(c)
    return prev


def _path(prev, node, nodes):
    chain = []
    while node is not None:
        chain.append("%s@%s" % nodes[node])
        node = prev[node]
    return chain[::-1]


def analyze_transitive(deps):
    """deps: [{name, version, eco, dev}] -> tree + vulnerable nested packages."""
    deps = [d for d in deps if d.get("version") and d.get("eco") in SYSTEMS]
    errors, roots = [], []

    def load(dep):
        try:
            return dep, parse_graph(fetch_graph(dep["eco"], dep["name"], dep["version"]))
        except Exception as e:
            return dep, str(e)

    with ThreadPoolExecutor(max_workers=10) as ex:
        for dep, res in ex.map(load, deps):
            if isinstance(res, str):
                errors.append({"name": dep["name"], "error": res})
            else:
                roots.append((dep, res))

    # which nested packages are vulnerable? (one batch call for everything)
    keys = sorted({(d["eco"], n, v) for d, (nodes, _, _) in roots for n, v in nodes[1:] if n and v})
    flagged = [k for k, bad in osv_has_vulns(keys).items() if bad]
    def lookup(k):
        try:
            return fetch_vulns(k[1], k[2], k[0], strict=True)
        except Exception as e:
            errors.append({"name": "%s@%s" % (k[1], k[2]), "error": "vulnerability lookup failed: %s" % e})
            return []

    with ThreadPoolExecutor(max_workers=10) as ex:
        found = dict(zip(flagged, ex.map(lookup, flagged)))
    vuln_of = {k: v for k, v in found.items() if v}

    tree, agg = [], {}
    for dep, (nodes, kids, parents) in roots:
        eco = dep["eco"]
        bad = {i for i in range(1, len(nodes)) if (eco, *nodes[i]) in vuln_of}

        tainted, q = set(), deque(bad)     # every ancestor of a vulnerable node
        while q:
            for p in parents[q.popleft()]:
                if p not in tainted:
                    tainted.add(p)
                    q.append(p)

        prev = _shortest_paths(kids)
        for i in bad:
            if i not in prev:
                continue
            a = agg.setdefault((eco, *nodes[i]), {"paths": [], "parents": set(), "affected": set()})
            a["affected"].add(dep["name"])
            a["parents"].update(nodes[p][0] for p in parents[i])
            if len(a["paths"]) < 3:
                a["paths"].append(_path(prev, i, nodes))

        expanded = set()

        def build(i, depth):
            name, version = nodes[i]
            vs = vuln_of.get((eco, name, version), []) if i else []
            node = {"name": name, "version": version, "children": [],
                    "vulns": [{"id": v["id"], "severity": v["severity"]} for v in vs],
                    "has_vuln_below": i in tainted}
            if i in expanded:
                node["dup"] = bool(kids[i])    # already shown elsewhere in this tree
                return node
            expanded.add(i)
            if depth < MAX_DEPTH:
                order = sorted(kids[i], key=lambda c: (c not in tainted and c not in bad, nodes[c][0] or ""))
                node["children"] = [build(c, depth + 1) for c in order]
            return node

        t = build(0, 0)
        t.update(eco=eco, dev=bool(dep.get("dev")), vulnerable_nested=len([i for i in bad if i in prev]),
                 nested_total=len(nodes) - 1)
        tree.append(t)

    vulnerable = []

    def fix_for(item):
        (eco, name, version), a = item
        vs = vuln_of[(eco, name, version)]
        return suggest_fix(name, eco, version, vs)

    items = list(agg.items())
    with ThreadPoolExecutor(max_workers=8) as ex:
        fixes = list(ex.map(fix_for, items))
    for ((eco, name, version), a), fix in zip(items, fixes):
        vs = vuln_of[(eco, name, version)]
        sev = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
        for v in vs:
            sev[v["severity"] if v["severity"] in sev else "MODERATE"] += 1
        vulnerable.append({"name": name, "version": version, "eco": eco, "vulns": vs, "sev": sev,
                           "paths": a["paths"], "parents": sorted(a["parents"]),
                           "affected_direct": sorted(a["affected"]), "fix": fix})
    vulnerable.sort(key=lambda x: (-max(SEV_RANK.get(v["severity"], 2) for v in x["vulns"]),
                                   -len(x["vulns"]), x["name"]))

    tree.sort(key=lambda t: (-t["vulnerable_nested"], t["name"]))
    return {"summary": {"direct_scanned": len(roots),
                        "nested_packages": len(keys),
                        "vulnerable_nested": len(vulnerable),
                        "affected_direct": len({a for v in vulnerable for a in v["affected_direct"]})},
            "tree": tree, "vulnerable": vulnerable, "errors": errors}
