1. Install Python 3.9+ from python.org (tick "Add to PATH").
2. Open this folder in VS Code -> Terminal -> New Terminal.
3. pip install -r requirements.txt
4. python app.py
5. Open http://127.0.0.1:5000 in your browser.

New features
------------
1. Transitive Dependency Vulnerability Analysis
   Resolves the full dependency tree of every package (deps.dev), checks every nested
   package against OSV.dev, and shows: the tree, the vulnerable nested packages, how
   each one got in, and which parent packages are affected.
2. Automated Dependency Fix & Remediation
   Picks the smallest safe version for each vulnerable package (and re-checks that version),
   compares current vs safe version (patch / minor / major), builds an updated
   package.json or requirements.txt, and lets you preview the diff and download it.
   Nested packages are fixed with npm "overrides" or a pinned line in requirements.txt.

Both are in the page served by app.py and in the React UI (cd frontend, npm install, npm run dev).
Run the tests (no internet needed):  python -m unittest discover -s tests -v
