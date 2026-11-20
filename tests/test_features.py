"""Tests for transitive analysis and automated remediation.

The network is mocked (deps.dev + OSV), so these run offline:
    python -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import app as app_module                      # noqa: E402
from common import fixed_versions, bump_type   # noqa: E402
from remediation import suggest_fix, apply_fixes  # noqa: E402
from transitive import analyze_transitive, _graph_cache  # noqa: E402


def osv_record(vid, name, eco, intro, fixed, severity="HIGH"):
    return {"id": vid, "summary": vid + " summary", "database_specific": {"severity": severity},
            "affected": [{"package": {"name": name, "ecosystem": eco},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": intro}, {"fixed": fixed}]}]}]}


# (name, version) -> OSV records. qs 6.5.1 is vulnerable, 6.5.3 is clean.
VULNS = {
    ("qs", "6.5.1"): [osv_record("GHSA-qs-1", "qs", "npm", "0", "6.5.3", "HIGH")],
    ("lodash", "4.17.15"): [osv_record("GHSA-lo-1", "lodash", "npm", "0", "4.17.19", "HIGH"),
                            osv_record("GHSA-lo-2", "lodash", "npm", "0", "4.17.21", "MODERATE")],
    ("lodash", "4.17.19"): [osv_record("GHSA-lo-2", "lodash", "npm", "0", "4.17.21", "MODERATE")],
    # a "fix" that has its own vulnerability -> the chain must continue
    ("tough", "1.0.0"): [osv_record("GHSA-t-1", "tough", "npm", "0", "1.1.0")],
    ("tough", "1.1.0"): [osv_record("GHSA-t-2", "tough", "npm", "0", "1.2.0")],
}


def node(name, version, rel):
    return {"versionKey": {"system": "NPM", "name": name, "version": version}, "relation": rel}


# express -> body-parser -> qs(vuln) ; express -> qs(vuln) ; body-parser -> bytes ; cycle bytes -> body-parser
EXPRESS_GRAPH = {
    "nodes": [node("express", "4.16.0", "SELF"), node("body-parser", "1.18.2", "DIRECT"),
              node("qs", "6.5.1", "DIRECT"), node("bytes", "3.0.0", "INDIRECT")],
    # proto3 JSON omits zero values, so edges from node 0 have no fromNode
    "edges": [{"toNode": 1}, {"toNode": 2}, {"fromNode": 1, "toNode": 2}, {"fromNode": 1, "toNode": 3},
              {"fromNode": 3, "toNode": 1}],
}
REACT_GRAPH = {"nodes": [node("react", "17.0.2", "SELF"), node("loose-envify", "1.4.0", "DIRECT")],
               "edges": [{"toNode": 1}]}


def fake_get(url, **kw):
    r = mock.Mock(status_code=200)
    if "/packages/express/" in url:
        r.json.return_value = EXPRESS_GRAPH
    elif "/packages/react/" in url:
        r.json.return_value = REACT_GRAPH
    else:
        r.status_code = 404
    return r


def fake_post(url, json=None, **kw):
    r = mock.Mock(status_code=200)
    if url.endswith("/querybatch"):
        r.json.return_value = {"results": [
            {"vulns": [{"id": v["id"]} for v in VULNS.get((q["package"]["name"], q["version"]), [])]}
            for q in json["queries"]]}
    else:
        r.json.return_value = {"vulns": VULNS.get((json["package"]["name"], json["version"]), [])}
    return r


class Net(unittest.TestCase):
    def setUp(self):
        _graph_cache.clear()
        for target, fake in (("requests.get", fake_get), ("requests.post", fake_post)):
            p = mock.patch(target, side_effect=fake)
            p.start()
            self.addCleanup(p.stop)


class FixedVersions(unittest.TestCase):
    def test_picks_the_range_the_version_is_in(self):
        rec = {"affected": [{"package": {"name": "x", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "1.2.3"}, {"introduced": "2.0.0"}, {"fixed": "2.1.1"}]}]}]}
        self.assertEqual(fixed_versions(rec, "x", "npm", "1.0.0"), ["1.2.3"])
        self.assertEqual(fixed_versions(rec, "x", "npm", "2.0.5"), ["2.1.1"])
        self.assertEqual(fixed_versions(rec, "x", "npm", "3.0.0"), [])

    def test_ignores_other_packages_and_pypi_name_variants(self):
        rec = {"affected": [{"package": {"name": "Django_Rest", "ecosystem": "PyPI"},
                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1"}]}]}]}
        self.assertEqual(fixed_versions(rec, "django-rest", "PyPI", "3.0"), ["3.1"])
        self.assertEqual(fixed_versions(rec, "other", "PyPI", "3.0"), [])

    def test_bump_type(self):
        self.assertEqual(bump_type("4.17.1", "4.17.21"), "patch")
        self.assertEqual(bump_type("4.16.0", "4.19.2"), "minor")
        self.assertEqual(bump_type("0.21.0", "1.6.0"), "major")


class SuggestFix(Net):
    def vulns(self, name, ver):
        from common import fetch_vulns
        return fetch_vulns(name, ver, "npm")

    def test_takes_the_highest_fix_and_verifies_it(self):
        fix = suggest_fix("lodash", "npm", "4.17.15", self.vulns("lodash", "4.17.15"))
        self.assertEqual((fix["target"], fix["bump"], fix["verified"], fix["fixes"]), ("4.17.21", "patch", True, 2))
        self.assertEqual(fix["severity"], "HIGH")

    def test_follows_a_chain_of_fixes(self):
        fix = suggest_fix("tough", "npm", "1.0.0", self.vulns("tough", "1.0.0"))
        self.assertEqual(fix["target"], "1.2.0")
        self.assertTrue(fix["verified"])

    def test_no_vulns_no_fix(self):
        self.assertIsNone(suggest_fix("clean", "npm", "1.0.0", []))

    def test_no_patch_available(self):
        v = [{"id": "X", "severity": "HIGH", "summary": "", "fixed": []}]
        fix = suggest_fix("abandoned", "npm", "1.0.0", v, latest="1.0.0")
        self.assertIsNone(fix["target"])
        self.assertIn("No patched version", fix["note"])


class ApplyFixes(unittest.TestCase):
    PKG = ('{\n  "name": "demo",\n  "dependencies": {\n    "lodash": "^4.17.15",\n'
           '    "express": "4.16.0",\n    "react": "git+https://x/y.git"\n  },\n'
           '  "devDependencies": {\n    "jest": "~26.0.0"\n  }\n}\n')
    REQ = "flask==1.0  # web\nRequests[security]>=2.19.0 ; python_version>'3'\n\n# comment\nnumpy\n"

    def test_package_json_keeps_prefix_and_uses_overrides_for_nested(self):
        out = apply_fixes({"package.json": self.PKG}, [
            {"name": "lodash", "eco": "npm", "target": "4.17.21"},
            {"name": "express", "eco": "npm", "target": "4.19.2"},
            {"name": "jest", "eco": "npm", "target": "26.6.3"},
            {"name": "react", "eco": "npm", "target": "18.0.0"},
            {"name": "qs", "eco": "npm", "target": "6.5.3"}])["package.json"]
        data = json.loads(out["updated"])
        self.assertEqual(data["dependencies"]["lodash"], "^4.17.21")
        self.assertEqual(data["dependencies"]["express"], "4.19.2")
        self.assertEqual(data["devDependencies"]["jest"], "~26.6.3")
        self.assertEqual(data["dependencies"]["react"], "git+https://x/y.git")     # untouched
        self.assertEqual(data["overrides"], {"qs": "6.5.3"})
        self.assertEqual(out["skipped"][0]["name"], "react")
        self.assertTrue(out["updated"].endswith("\n"))
        self.assertIn('-    "lodash": "^4.17.15"', out["diff"])
        self.assertIn('+    "lodash": "^4.17.21"', out["diff"])

    def test_never_downgrades_and_skips_noops(self):
        self.assertEqual(apply_fixes({"package.json": self.PKG},
                                     [{"name": "lodash", "eco": "npm", "target": "4.17.10"}]), {})

    def test_highest_target_wins_when_a_package_is_listed_twice(self):
        out = apply_fixes({"package.json": self.PKG}, [
            {"name": "lodash", "eco": "npm", "target": "4.17.19"},
            {"name": "lodash", "eco": "npm", "target": "4.17.21"}])
        self.assertEqual(json.loads(out["package.json"]["updated"])["dependencies"]["lodash"], "^4.17.21")

    def test_requirements_keep_operators_markers_comments_and_pin_nested(self):
        out = apply_fixes({"requirements.txt": self.REQ}, [
            {"name": "flask", "eco": "PyPI", "target": "2.2.5"},
            {"name": "requests", "eco": "PyPI", "target": "2.32.0"},
            {"name": "numpy", "eco": "PyPI", "target": "1.22.0"},
            {"name": "urllib3", "eco": "PyPI", "target": "1.26.18"}])["requirements.txt"]
        lines = out["updated"].splitlines()
        self.assertEqual(lines[0], "flask==2.2.5  # web")
        self.assertEqual(lines[1], "Requests[security]>=2.32.0 ; python_version>'3'")
        self.assertIn("numpy>=1.22.0", lines)
        self.assertEqual(lines[-1], "urllib3==1.26.18")
        self.assertIn("# Pinned to fix vulnerable nested dependencies", lines)

    def test_files_are_matched_by_ecosystem(self):
        out = apply_fixes({"package.json": self.PKG, "requirements.txt": self.REQ},
                          [{"name": "flask", "eco": "PyPI", "target": "2.2.5"}])
        self.assertEqual(list(out), ["requirements.txt"])


class Transitive(Net):
    DEPS = [{"name": "express", "version": "4.16.0", "eco": "npm", "dev": False},
            {"name": "react", "version": "17.0.2", "eco": "npm", "dev": False},
            {"name": "ghost", "version": "1.0.0", "eco": "npm", "dev": False}]   # deps.dev 404

    def setUp(self):
        super().setUp()
        self.res = analyze_transitive(self.DEPS)

    def test_summary_and_errors(self):
        s = self.res["summary"]
        self.assertEqual((s["direct_scanned"], s["vulnerable_nested"], s["affected_direct"]), (2, 1, 1))
        self.assertEqual([e["name"] for e in self.res["errors"]], ["ghost"])

    def test_vulnerable_nested_package_reports_path_parents_and_fix(self):
        v = self.res["vulnerable"][0]
        self.assertEqual((v["name"], v["version"]), ("qs", "6.5.1"))
        self.assertEqual(v["affected_direct"], ["express"])
        self.assertEqual(v["parents"], ["body-parser", "express"])
        self.assertEqual(v["paths"][0], ["express@4.16.0", "qs@6.5.1"])   # shortest path
        self.assertEqual((v["fix"]["target"], v["fix"]["verified"]), ("6.5.3", True))

    def test_tree_marks_affected_parents_and_survives_cycles(self):
        express = next(t for t in self.res["tree"] if t["name"] == "express")
        self.assertEqual(self.res["tree"][0]["name"], "express")          # riskiest direct dep first
        self.assertTrue(express["has_vuln_below"])
        self.assertEqual(express["vulnerable_nested"], 1)
        names = {c["name"]: c for c in express["children"]}
        self.assertTrue(names["body-parser"]["has_vuln_below"])
        self.assertEqual(names["qs"]["vulns"][0]["id"], "GHSA-qs-1")
        bytes_node = next(c for c in names["body-parser"]["children"] if c["name"] == "bytes")
        self.assertTrue(bytes_node["children"][0].get("dup") is not None)  # cycle cut, no infinite loop
        react = next(t for t in self.res["tree"] if t["name"] == "react")
        self.assertFalse(react["has_vuln_below"])


class Routes(Net):
    def setUp(self):
        super().setUp()
        self.c = app_module.app.test_client()

    def test_transitive_route(self):
        r = self.c.post("/api/transitive", json={"deps": Transitive.DEPS[:1]})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["vulnerable"][0]["name"], "qs")
        self.assertEqual(self.c.post("/api/transitive", json={}).status_code, 400)

    def test_remediate_route(self):
        r = self.c.post("/api/remediate", json={
            "files": {"package.json": ApplyFixes.PKG},
            "updates": [{"name": "lodash", "eco": "npm", "target": "4.17.21"}]})
        self.assertEqual(r.status_code, 200)
        self.assertIn("^4.17.21", r.get_json()["files"]["package.json"]["updated"])
        self.assertEqual(self.c.post("/api/remediate", json={"updates": []}).status_code, 400)

    def test_analyze_returns_fix_and_sources(self):
        import io
        pkg = json.dumps({"dependencies": {"lodash": "4.17.15"}})
        con = mock.MagicMock()
        con.execute.return_value.fetchone.return_value = None      # no previous scan, no real DB
        with mock.patch.object(app_module, "fetch_latest", return_value=("4.17.21", 100)), \
             mock.patch.object(app_module, "db", return_value=con):
            r = self.c.post("/api/analyze", data={"file": (io.BytesIO(pkg.encode()), "package.json")},
                            content_type="multipart/form-data")
        body = r.get_json()
        self.assertEqual(r.status_code, 200, body)
        dep = body["dependencies"][0]
        self.assertEqual(dep["fix"]["target"], "4.17.21")
        self.assertEqual(body["sources"], {"package.json": pkg})


class RegressionFixes(Net):
    def test_clean_version_ignores_non_registry_specs(self):
        for spec in ("npm:other@1.2.3", "github:user/repo2", "user/repo", "workspace:*", "git+https://x/y.git#v1"):
            self.assertIsNone(app_module.clean_version(spec), spec)
        self.assertEqual(app_module.clean_version("^4.17.1"), "4.17.1")

    def test_github_repo_name_keeps_dots(self):
        seen = []
        def fake(url, **kw):
            seen.append(url)
            return mock.Mock(status_code=404, headers={})
        with mock.patch("app.requests.get", side_effect=fake):
            with self.assertRaises(ValueError):
                app_module.github_files("https://github.com/me/my.github.io.git")
        self.assertIn("/repos/me/my.github.io/contents/package.json", seen[0])

    def test_no_change_means_no_diff(self):
        pkg = '{\n  "dependencies": {"a": "^2.0.0"},\n  "x": [1,2]\n}\n'
        self.assertEqual(apply_fixes({"package.json": pkg}, [{"name": "a", "eco": "npm", "target": "1.0.0"}]), {})

    def test_crlf_is_preserved(self):
        txt = "flask==1.0\r\nrequests==2.0\r\n"
        out = apply_fixes({"requirements.txt": txt}, [{"name": "flask", "eco": "PyPI", "target": "2.0.0"}])
        self.assertEqual(out["requirements.txt"]["updated"], "flask==2.0.0\r\nrequests==2.0\r\n")

    def test_fix_is_not_marked_verified_when_osv_is_down(self):
        vulns = [{"id": "X", "severity": "HIGH", "summary": "", "fixed": ["1.1.0"]}]
        with mock.patch("remediation.fetch_vulns", side_effect=RuntimeError("down")):
            fix = suggest_fix("tough", "npm", "1.0.0", vulns)
        self.assertEqual(fix["target"], "1.1.0")
        self.assertFalse(fix["verified"])
        self.assertIn("Could not re-check", fix["note"])


if __name__ == "__main__":
    unittest.main()
