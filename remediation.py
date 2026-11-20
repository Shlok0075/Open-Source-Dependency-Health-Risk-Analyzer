"""Feature 2: Automated Dependency Fix & Remediation.

suggest_fix()  -> picks the smallest safe version for one vulnerable package
apply_fixes()  -> writes an updated package.json / requirements.txt + a diff
"""
import difflib
import json
import re

from common import SEV_RANK, bump_type, fetch_vulns, vt, norm_name


# ------------------------------------------------------------ choosing versions
def _needed(vulns):
    """Smallest version that should clear every vuln that has a known fix."""
    fixes = [min(v["fixed"], key=vt) for v in vulns if v.get("fixed")]
    return max(fixes, key=vt) if fixes else None


def suggest_fix(name, eco, cur, vulns, latest=None):
    """Return a fix suggestion for one package, or None if it has no vulns.

    Strategy: take the highest "fixed in" version from the advisories, check
    that version against OSV again (a fix can still carry other vulns), and
    only fall back to the latest release if that is not enough.
    """
    if not vulns or not cur:
        return None

    tried, best = set(), None          # best = (remaining_vulns, version)
    unchecked = set()                  # versions OSV could not be asked about

    def check(version):
        nonlocal best
        tried.add(version)
        try:
            rem = fetch_vulns(name, version, eco, strict=True)
        except Exception:
            rem = []
            unchecked.add(version)
        if best is None or len(rem) < len(best[0]):
            best = (rem, version)
        return rem

    cand = _needed(vulns)
    for _ in range(3):                  # follow "fixed in X, but X has its own vuln"
        if not cand or cand in tried or vt(cand) <= vt(cur):
            break
        rem = check(cand)
        if not rem:
            break
        nxt = _needed(rem)
        cand = nxt if nxt and vt(nxt) > vt(cand) else None

    if (best is None or best[0]) and latest and latest != "unknown" \
            and latest not in tried and vt(latest) > vt(cur):
        check(latest)

    base = {"name": name, "eco": eco, "current": cur,
            "severity": max((v["severity"] for v in vulns), key=lambda s: SEV_RANK.get(s, 2))}
    if best is None:
        return dict(base, target=None, bump=None, verified=False, remaining=len(vulns),
                    fixes=0, note="No patched version has been published yet - "
                                  "consider an alternative package.")
    rem, target = best
    still = {v["id"] for v in rem}
    notes = []
    if bump_type(cur, target) == "major":
        notes.append("Major upgrade - check the changelog for breaking changes.")
    if target in unchecked:
        notes.append("Could not re-check this version against the vulnerability database.")
    return dict(base, target=target, bump=bump_type(cur, target),
                verified=not rem and target not in unchecked, remaining=len(rem),
                fixes=sum(1 for v in vulns if v["id"] not in still),
                note=" ".join(notes))


# ------------------------------------------------------------ editing the files
def _indent_of(text):
    m = re.search(r'\n([ \t]+)"', text)
    return m.group(1) if m else 2


def _npm_spec(old, target):
    """Keep the user's style: ^ stays ^, ~ stays ~, exact stays exact."""
    if re.match(r"^[\^~]", old):
        return old[0] + target
    if re.match(r"^\d", old):
        return target
    return "^" + target


def _apply_package_json(text, updates):
    data = json.loads(text)
    changes, skipped = [], []
    sections = [s for s in ("dependencies", "devDependencies", "optionalDependencies")
                if isinstance(data.get(s), dict)]
    for u in updates:
        name, target = u["name"], u["target"]
        sec = next((s for s in sections if name in data[s]), None)
        if sec:
            old = str(data[sec][name])
            if re.match(r"^(git|http|file|link|npm:|workspace)", old):
                skipped.append({"name": name, "reason": "Not a registry version (%s)" % old})
                continue
            cv = re.search(r"\d+(?:\.\d+){0,2}", old)
            if cv and vt(cv.group(0)) >= vt(target):
                continue
            data[sec][name] = _npm_spec(old, target)
            changes.append({"name": name, "from": old, "to": data[sec][name], "how": "version"})
        else:                           # nested dependency -> npm "overrides"
            ov = data.setdefault("overrides", {})
            if not isinstance(ov, dict):
                skipped.append({"name": name, "reason": "package.json has a non-object overrides field"})
                continue
            old = ov.get(name)
            if isinstance(old, str) and vt(re.sub(r"^[\^~]", "", old)) >= vt(target):
                continue
            ov[name] = target
            changes.append({"name": name, "from": old or "(nested)", "to": target, "how": "override"})
    out = json.dumps(data, indent=_indent_of(text), ensure_ascii=False)
    nl = "\r\n" if "\r\n" in text else "\n"
    out = out.replace("\n", nl)
    return out + (nl if text.endswith("\n") else ""), changes, skipped


REQ_LINE = re.compile(r"^(\s*)([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([^;#]*?)\s*(;[^#]*?)?\s*(#.*)?$")


def _req_spec(old_spec, target):
    clauses = [c for c in old_spec.split(",") if c.strip()]
    if not clauses:
        return ">=" + target
    m = re.match(r"\s*(==|>=|~=)", clauses[0])
    if len(clauses) == 1 and m:
        return m.group(1) + target
    return "==" + target


def _apply_requirements(text, updates):
    lines = text.splitlines()
    changes, skipped = [], []
    index = {}
    for i, line in enumerate(lines):
        if line.strip().startswith(("#", "-")):
            continue
        m = REQ_LINE.match(line)
        if m:
            index.setdefault(norm_name("PyPI", m.group(2)), i)

    added = []
    for u in updates:
        name, target = u["name"], u["target"]
        i = index.get(norm_name("PyPI", name))
        if i is None:                   # nested dependency -> pin it explicitly
            added.append("%s==%s" % (name, target))
            changes.append({"name": name, "from": "(nested)", "to": "==" + target, "how": "pin"})
            continue
        m = REQ_LINE.match(lines[i])
        ind, nm, extras, spec, marker, comment = m.groups()
        cv = re.search(r"\d+(?:\.\d+){0,2}", spec or "")
        if cv and vt(cv.group(0)) >= vt(target):
            continue
        new_spec = _req_spec(spec or "", target)
        new = "%s%s%s%s" % (ind, nm, extras or "", new_spec)
        if marker:
            new += " " + marker.strip()
        if comment:
            new += "  " + comment
        lines[i] = new
        changes.append({"name": name, "from": (spec or "").strip() or "(unpinned)",
                        "to": new_spec, "how": "version"})
    if added:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("# Pinned to fix vulnerable nested dependencies")
        lines.extend(added)
    nl = "\r\n" if "\r\n" in text else "\n"
    return nl.join(lines) + (nl if text.endswith("\n") or added else ""), changes, skipped


def apply_fixes(files, updates):
    """files: {filename: text}; updates: [{name, eco, target}].

    Returns {filename: {original, updated, diff, changes, skipped}} for every
    file that actually changes.
    """
    best = {}                           # one update per package: the highest target
    for u in updates:
        if not u.get("target"):
            continue
        key = (u["eco"], norm_name(u["eco"], u["name"]))
        if key not in best or vt(u["target"]) > vt(best[key]["target"]):
            best[key] = u

    result = {}
    for fname, text in files.items():
        eco = "npm" if fname.lower().endswith(".json") else "PyPI"
        mine = [u for (e, _), u in best.items() if e == eco]
        if not mine:
            continue
        apply = _apply_package_json if eco == "npm" else _apply_requirements
        updated, changes, skipped = apply(text, mine)
        if not changes and not skipped:     # nothing to change (also avoids reformatting noise)
            continue
        diff = "\n".join(difflib.unified_diff(
            text.splitlines(), updated.splitlines(),
            fromfile=fname, tofile=fname + " (updated)", lineterm=""))
        result[fname] = {"original": text, "updated": updated, "diff": diff,
                         "changes": changes, "skipped": skipped}
    return result
