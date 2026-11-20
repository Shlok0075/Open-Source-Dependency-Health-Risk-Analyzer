"""Open-Source Dependency Health & Risk Analyzer  (Flask backend)"""
import os, re, json, sqlite3, base64, datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
import requests
from flask import Flask, request, jsonify, send_from_directory

from common import HEADERS, vt, fetch_vulns
from remediation import suggest_fix, apply_fixes
from transitive import analyze_transitive

app = Flask(__name__, static_folder="static")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.db")
MAX_DEPS = 80


# ---------------------------------------------------------------- database
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project TEXT, created TEXT, total INTEGER, outdated INTEGER,
        vulnerable INTEGER, health REAL, risk TEXT, details TEXT)""")
    con.commit(); con.close()

init_db()       # also when started with "flask run" instead of "python app.py"


# ---------------------------------------------------------------- parsing
def clean_version(spec):
    """'^4.17.1' -> '4.17.1'. Returns None if no usable version."""
    if not spec:
        return None
    spec = str(spec).strip()
    # git/url/alias/workspace specs do not point at a registry version
    if re.match(r"^(git|github:|gitlab:|bitbucket:|http|file:|link:|npm:|workspace:|portal:|patch:)", spec) \
            or re.match(r"^[\w.\-]+/[\w.\-]+$", spec):
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", spec)
    if not m:
        return None
    return "%s.%s.%s" % (m.group(1), m.group(2) or 0, m.group(3) or 0)

def parse_package_json(text):
    data = json.loads(text)
    out = []
    for section, dev in (("dependencies", False), ("devDependencies", True)):
        for name, spec in (data.get(section) or {}).items():
            out.append({"name": name, "version": clean_version(spec),
                        "eco": "npm", "dev": dev})
    return out

def parse_requirements(text):
    out = []
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)(\[.*?\])?\s*(===|==|>=|~=|<=)?\s*([\w.\-]*)", line)
        if not m:
            continue
        ver = clean_version(m.group(4)) if m.group(3) else None
        out.append({"name": m.group(1), "version": ver, "eco": "PyPI", "dev": False})
    return out


# ---------------------------------------------------------------- registries
def days_since(iso):
    try:
        d = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - d).days
    except Exception:
        return None

def fetch_latest(name, eco):
    """Return (latest_version, days_since_release) or (None, None)."""
    try:
        if eco == "npm":
            r = requests.get("https://registry.npmjs.org/" + quote(name, safe="@"),
                             timeout=20, headers=HEADERS)
            d = r.json()
            latest = d["dist-tags"]["latest"]
            return latest, days_since(d["time"][latest])
        r = requests.get("https://pypi.org/pypi/%s/json" % quote(name, safe=""), timeout=20, headers=HEADERS)
        d = r.json()
        latest = d["info"]["version"]
        files = d.get("urls") or []
        when = files[0]["upload_time_iso_8601"] if files else None
        return latest, days_since(when) if when else None
    except Exception:
        return None, None

# ---------------------------------------------------------------- scoring
def analyze_dep(dep):
    name, cur, eco = dep["name"], dep["version"], dep["eco"]
    latest, age = fetch_latest(name, eco)
    vulns = fetch_vulns(name, cur or latest, eco)

    sev = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    for v in vulns:
        sev[v["severity"] if v["severity"] in sev else "MODERATE"] += 1

    # 1) Security score
    security = max(0, 100 - sev["CRITICAL"] * 40 - sev["HIGH"] * 25 - sev["MODERATE"] * 12 - sev["LOW"] * 5)

    # 2) Freshness score (how far behind the latest version)
    major_gap = minor_gap = 0
    if cur and latest:
        c, l = vt(cur), vt(latest)
        major_gap = max(0, l[0] - c[0])
        minor_gap = max(0, l[1] - c[1]) if major_gap == 0 else 0
    freshness = {0: 100, 1: 60, 2: 35}.get(major_gap, 10)
    if major_gap == 0:
        freshness = max(70, 100 - minor_gap * 3)
    outdated = bool(cur and latest and vt(cur) < vt(latest))

    # 3) Maintenance score (days since latest release)
    if age is None:
        maintenance = 50
    elif age <= 180: maintenance = 100
    elif age <= 365: maintenance = 80
    elif age <= 730: maintenance = 55
    elif age <= 1095: maintenance = 30
    else: maintenance = 10

    health = round(0.5 * security + 0.25 * freshness + 0.25 * maintenance, 1)
    risk = "Low" if health >= 75 else "Medium" if health >= 50 else "High"
    if sev["CRITICAL"] or sev["HIGH"]:
        risk = "High"

    # Recommendations
    recs = []
    if sev["CRITICAL"] or sev["HIGH"]:
        recs.append("Upgrade to %s immediately - serious vulnerabilities found." % (latest or "a patched version"))
    elif vulns:
        recs.append("Upgrade to %s to fix known vulnerabilities." % (latest or "a patched version"))
    if major_gap >= 1:
        recs.append("%d major version(s) behind - plan an upgrade to %s." % (major_gap, latest))
    elif outdated:
        recs.append("A newer version (%s) is available - safe minor/patch update." % latest)
    if age is not None and age > 730:
        recs.append("No release for %d days - package may be abandoned, consider an alternative." % age)
    if not recs:
        recs.append("Healthy - no action needed.")

    return {"name": name, "eco": eco, "dev": dep["dev"], "current": cur or "unknown",
            "latest": latest or "unknown", "outdated": outdated, "days_since_release": age,
            "vulns": vulns, "sev": sev, "security": security, "freshness": freshness,
            "maintenance": maintenance, "health": health, "risk": risk,
            "priority": round(100 - health, 1), "recommendations": recs,
            "fix": suggest_fix(name, eco, cur, vulns, latest)}


# ---------------------------------------------------------------- GitHub
def github_files(url):
    m = re.search(r"github\.com/([^/\s]+)/([^/\s#?]+)", url)
    if not m:
        raise ValueError("Please enter a valid GitHub repository URL.")
    owner, repo = m.group(1), re.sub(r"\.git$", "", m.group(2))
    deps, sources = [], {}
    headers = dict(HEADERS)
    if os.environ.get("GITHUB_TOKEN"):          # optional: avoids the low anonymous rate limit
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    for fname, parser in (("package.json", parse_package_json), ("requirements.txt", parse_requirements)):
        r = requests.get("https://api.github.com/repos/%s/%s/contents/%s" % (owner, repo, fname),
                         timeout=20, headers=headers)
        if r.status_code in (403, 429) and r.headers.get("X-RateLimit-Remaining") == "0":
            raise ValueError("GitHub rate limit reached. Set a GITHUB_TOKEN environment variable or try again later.")
        if r.status_code == 200:
            text = base64.b64decode(r.json()["content"]).decode("utf-8", "ignore")
            deps += parser(text)
            sources[fname] = text
    if not deps:
        raise ValueError("No package.json or requirements.txt found in the root of that repo (or repo is private / rate limit hit).")
    return repo, deps, sources


# ---------------------------------------------------------------- routes
@app.route("/")
def home():
    built = os.path.join(app.static_folder, "app", "index.html")
    if os.path.exists(built):                      # React UI (cd frontend && npm run build)
        return send_from_directory(os.path.join(app.static_folder, "app"), "index.html")
    return send_from_directory("static", "index.html")   # simple fallback page

@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        project = (request.form.get("project") or "").strip()
        url = (request.form.get("github_url") or "").strip()
        file = request.files.get("file")
        if url:
            repo, deps, sources = github_files(url)
            project = project or repo
        elif file and file.filename:
            text = file.read().decode("utf-8", "ignore")
            fn = file.filename.lower()
            if fn.endswith(".json"):
                deps = parse_package_json(text)
                sources = {os.path.basename(file.filename) or "package.json": text}
            else:
                deps = parse_requirements(text)
                sources = {os.path.basename(file.filename) or "requirements.txt": text}
            project = project or "my-project"
        else:
            return jsonify({"error": "Provide a GitHub URL or upload a file."}), 400
        if not deps:
            return jsonify({"error": "No dependencies found in the input."}), 400

        deps = deps[:MAX_DEPS]
        with ThreadPoolExecutor(max_workers=15) as ex:
            results = list(ex.map(analyze_dep, deps))
        results.sort(key=lambda d: d["priority"], reverse=True)

        total = len(results)
        outdated = sum(d["outdated"] for d in results)
        vulnerable = sum(1 for d in results if d["vulns"])
        health = round(sum(d["health"] for d in results) / total, 1)
        risk = "Low" if health >= 75 else "Medium" if health >= 50 else "High"
        keys = sorted("%s:%s" % (d["name"], v["id"]) for d in results for v in d["vulns"])

        # change detection vs previous scan of same project
        con = db()
        try:
            prev = con.execute("SELECT * FROM scans WHERE project=? ORDER BY id DESC LIMIT 1", (project,)).fetchone()
            changes = None
            if prev:
                pd = json.loads(prev["details"])
                pk = set(pd.get("vuln_keys", []))
                changes = {"previous_health": prev["health"],
                           "health_change": round(health - prev["health"], 1),
                           "new_vulns": sorted(set(keys) - pk),
                           "fixed_vulns": sorted(pk - set(keys)),
                           "previous_date": prev["created"]}
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            con.execute("INSERT INTO scans(project,created,total,outdated,vulnerable,health,risk,details) VALUES(?,?,?,?,?,?,?,?)",
                        (project, now, total, outdated, vulnerable, health, risk,
                         json.dumps({"vuln_keys": keys})))
            con.commit()
        finally:
            con.close()

        return jsonify({"project": project, "scanned_at": now, "total": total,
                        "outdated": outdated, "vulnerable": vulnerable,
                        "health": health, "risk": risk, "dependencies": results,
                        "changes": changes, "sources": sources})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except json.JSONDecodeError:
        return jsonify({"error": "That file is not valid JSON."}), 400
    except Exception as e:
        return jsonify({"error": "Something went wrong: %s" % e}), 500

@app.route("/api/transitive", methods=["POST"])
def transitive():
    """Feature 1: dependency tree + vulnerable nested packages."""
    try:
        deps = (request.get_json(silent=True) or {}).get("deps") or []
        if not deps:
            return jsonify({"error": "No dependencies supplied."}), 400
        return jsonify(analyze_transitive(deps[:MAX_DEPS]))
    except Exception as e:
        return jsonify({"error": "Something went wrong: %s" % e}), 500

@app.route("/api/remediate", methods=["POST"])
def remediate():
    """Feature 2: build the updated dependency file(s) for the chosen fixes."""
    try:
        body = request.get_json(silent=True) or {}
        files, updates = body.get("files") or {}, body.get("updates") or []
        if not files:
            return jsonify({"error": "No dependency file supplied."}), 400
        return jsonify({"files": apply_fixes(files, updates)})
    except json.JSONDecodeError:
        return jsonify({"error": "The dependency file is not valid JSON."}), 400
    except Exception as e:
        return jsonify({"error": "Something went wrong: %s" % e}), 500

@app.route("/api/history")
def history():
    project = request.args.get("project", "")
    con = db()
    try:
        rows = con.execute("SELECT created,total,outdated,vulnerable,health,risk FROM scans WHERE project=? ORDER BY id",
                           (project,)).fetchall()
    finally:
        con.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(debug=False, port=5000)
