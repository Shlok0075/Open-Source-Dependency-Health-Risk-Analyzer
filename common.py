"""Small helpers shared by app.py, transitive.py and remediation.py."""
import re
import requests

HEADERS = {"User-Agent": "dependency-health-analyzer"}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1}


def vt(v):
    """'4.17.1' -> (4, 17, 1). Used to compare versions."""
    nums = [int(x) for x in re.findall(r"\d+", v or "")][:3]
    return tuple(nums + [0] * (3 - len(nums)))


def norm_name(eco, name):
    """PyPI names are case/underscore insensitive, npm names are exact."""
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def bump_type(cur, target):
    """Tells how risky an upgrade is: patch (safe), minor, or major (may break)."""
    c, t = vt(cur), vt(target)
    if t[0] != c[0]:
        return "major"
    if t[1] != c[1]:
        return "minor"
    return "patch"


def fixed_versions(vuln, name, eco, version):
    """Versions that fix this OSV record, for the range our version falls in."""
    want, cur, out = norm_name(eco, name), vt(version), set()
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if norm_name(eco, pkg.get("name", "")) != want:
            continue
        if (pkg.get("ecosystem") or "").lower() != eco.lower():
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            intro = (0, 0, 0)
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    intro = vt(ev["introduced"])
                elif "fixed" in ev and intro <= cur < vt(ev["fixed"]):
                    out.add(ev["fixed"])
    return sorted(out, key=vt)


def fetch_vulns(name, version, eco, strict=False):
    """Ask OSV.dev (free) for known vulnerabilities of this exact version.

    strict=True raises when OSV cannot be reached, instead of answering "none".
    """
    if not version:
        return []
    try:
        r = requests.post("https://api.osv.dev/v1/query", timeout=20, headers=HEADERS,
                          json={"version": version, "package": {"name": name, "ecosystem": eco}})
        if r.status_code != 200:
            raise RuntimeError("OSV returned %s" % r.status_code)
        found = []
        for v in r.json().get("vulns", []):
            sev = ((v.get("database_specific") or {}).get("severity") or "MODERATE").upper()
            if sev == "MEDIUM":
                sev = "MODERATE"
            found.append({"id": v.get("id"), "severity": sev,
                          "summary": (v.get("summary") or "")[:120],
                          "fixed": fixed_versions(v, name, eco, version)})
        return found
    except Exception:
        if strict:
            raise
        return []
