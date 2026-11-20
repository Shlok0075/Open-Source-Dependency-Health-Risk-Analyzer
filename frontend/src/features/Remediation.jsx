import { useEffect, useMemo, useState } from "react";
import { CopyButton, download } from "../ui.jsx";

const BUMP = {
  patch: "bg-emerald-100 text-emerald-700",
  minor: "bg-amber-100 text-amber-700",
  major: "bg-red-100 text-red-700",
};

const newer = (a, b) => {
  const n = (v) => (v.match(/\d+/g) || []).slice(0, 3).map(Number);
  const [x, y] = [n(a), n(b)];
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0);
  return false;
};

/* Merge direct and nested fixes into one list (one row per package). */
function buildPlan(data, trans) {
  const map = new Map();
  const add = (it) => {
    const key = `${it.eco}:${it.name}`;
    const prev = map.get(key);
    if (!prev) return map.set(key, it);
    const best = it.target && (!prev.target || newer(it.target, prev.target)) ? it : prev;
    map.set(key, { ...best, kind: prev.kind === "Direct" || it.kind === "Direct" ? "Direct" : "Nested" });
  };
  data.dependencies.forEach((d) => {
    if (d.fix) add({ ...d.fix, kind: "Direct", via: [] });
  });
  (trans?.vulnerable ?? []).forEach((v) => {
    if (v.fix) add({ ...v.fix, kind: "Nested", via: v.affected_direct });
  });
  return [...map.values()].sort((a, b) => (b.target ? 1 : 0) - (a.target ? 1 : 0) || a.name.localeCompare(b.name));
}

function Diff({ text }) {
  return (
    <pre className="max-h-80 overflow-auto rounded-lg bg-slate-900 p-3 text-xs leading-5">
      {text.split("\n").map((line, i) => {
        const color = line.startsWith("+++") || line.startsWith("---")
          ? "text-slate-400"
          : line.startsWith("+")
          ? "bg-emerald-900/40 text-emerald-300"
          : line.startsWith("-")
          ? "bg-red-900/40 text-red-300"
          : line.startsWith("@@")
          ? "text-sky-300"
          : "text-slate-300";
        return <div key={i} className={color}>{line || " "}</div>;
      })}
    </pre>
  );
}

export default function Remediation({ data, trans, transLoading }) {
  const plan = useMemo(() => buildPlan(data, trans), [data, trans]);
  const fixable = plan.filter((p) => p.target);
  const unfixable = plan.filter((p) => !p.target);

  const [skipped, setSkipped] = useState(() => new Set());   // rows the user unticked
  const [out, setOut] = useState(null);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState(null);

  const key = (p) => `${p.eco}:${p.name}`;
  const chosen = fixable.filter((p) => !skipped.has(key(p)));
  const chosenKey = chosen.map((p) => `${key(p)}@${p.target}`).join("|");

  // Ask the backend to rewrite the dependency file(s) whenever the selection changes.
  useEffect(() => {
    if (!chosen.length) { setOut({}); return; }
    let stale = false;
    fetch("/api/remediate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        files: data.sources,
        updates: chosen.map((p) => ({ name: p.name, eco: p.eco, target: p.target })),
      }),
    })
      .then((r) => r.json().then((j) => ({ ok: r.ok, j })))
      .then(({ ok, j }) => {
        if (stale) return;
        if (!ok) throw new Error(j.error || "Could not build the updated file");
        setErr("");
        setOut(j.files);
      })
      .catch((e) => !stale && setErr(e.message));
    return () => { stale = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [chosenKey, data.sources]);

  const names = Object.keys(out ?? {});
  const active = out?.[tab] ? tab : names[0];
  const file = out?.[active];

  const counts = chosen.reduce((c, p) => ({ ...c, [p.bump]: (c[p.bump] || 0) + 1 }), {});
  const toggle = (p) =>
    setSkipped((s) => {
      const n = new Set(s);
      n.has(key(p)) ? n.delete(key(p)) : n.add(key(p));
      return n;
    });

  return (
    <section className="rounded-2xl bg-white p-6 shadow-sm">
      <h3 className="font-semibold">Automated fix plan</h3>
      <p className="mb-4 text-sm text-slate-500">
        Smallest safe version for each vulnerable package, checked against the vulnerability database. Untick anything you want to skip.
      </p>

      {fixable.length === 0 && unfixable.length === 0 && (
        <p className="text-sm text-emerald-600">
          {transLoading ? "Waiting for the nested dependency check..." : "No vulnerable packages, so there is nothing to fix."}
        </p>
      )}

      {fixable.length > 0 && (
        <>
          <div className="overflow-x-auto rounded-xl border border-slate-200">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="w-10 px-3 py-2"></th>
                  <th className="px-3 py-2 font-medium">Package</th>
                  <th className="px-3 py-2 font-medium">Current</th>
                  <th className="px-3 py-2 font-medium">Safe version</th>
                  <th className="px-3 py-2 font-medium">Change</th>
                  <th className="px-3 py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {fixable.map((p) => (
                  <tr key={key(p)} className={skipped.has(key(p)) ? "opacity-40" : ""}>
                    <td className="px-3 py-2">
                      <input type="checkbox" checked={!skipped.has(key(p))} onChange={() => toggle(p)} />
                    </td>
                    <td className="px-3 py-2">
                      <span className="font-semibold">{p.name}</span>
                      <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-500">
                        {p.kind}{p.kind === "Nested" && p.via.length ? ` via ${p.via.slice(0, 2).join(", ")}${p.via.length > 2 ? "…" : ""}` : ""}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-red-600 line-through decoration-red-300">{p.current}</td>
                    <td className="px-3 py-2 font-semibold tabular-nums text-emerald-700">{p.target}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${BUMP[p.bump]}`}>{p.bump}</span>
                    </td>
                    <td className="px-3 py-2 text-xs">
                      {p.verified ? (
                        <span className="font-medium text-emerald-700">Fixes {p.fixes} {p.fixes === 1 ? "vulnerability" : "vulnerabilities"}</span>
                      ) : (
                        <span className="font-medium text-amber-700">Fixes {p.fixes}, {p.remaining} still open</span>
                      )}
                      {p.note && <div className="text-slate-500">{p.note}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="mt-2 text-xs text-slate-500">
            {chosen.length} of {fixable.length} fixes selected
            {["patch", "minor", "major"].filter((b) => counts[b]).map((b) => ` · ${counts[b]} ${b}`).join("")}.
            {counts.major ? " Major upgrades can break your code, so test after applying." : ""}
          </p>
        </>
      )}

      {unfixable.length > 0 && (
        <div className="mt-4 rounded-lg bg-amber-50 p-3 text-sm text-amber-800">
          <p className="font-medium">No patched version exists yet for:</p>
          <ul className="mt-1 list-disc pl-5 text-xs">
            {unfixable.map((p) => <li key={key(p)}>{p.name} {p.current}. {p.note}</li>)}
          </ul>
        </div>
      )}

      {err && <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{err}</p>}

      {fixable.length > 0 && names.length > 0 && file && (
        <div className="mt-6">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div className="flex gap-1">
              {names.map((n) => (
                <button
                  key={n} onClick={() => setTab(n)}
                  className={`rounded-md px-3 py-1 text-xs font-semibold ${n === active ? "bg-indigo-600 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}
                >
                  {n}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <CopyButton text={file.updated} label="Copy file" />
              <button
                onClick={() => download(active, file.updated, "text/plain")}
                className="rounded-md bg-emerald-600 px-3 py-1 text-xs font-semibold text-white hover:bg-emerald-700"
              >
                Download updated {active}
              </button>
            </div>
          </div>

          <p className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-500">Preview of changes</p>
          <Diff text={file.diff} />

          {file.changes.some((c) => c.how === "override") && (
            <p className="mt-2 text-xs text-slate-500">
              Nested packages are fixed with an <code>overrides</code> entry (npm 8.3 or newer). With yarn use <code>resolutions</code>.
              Run <code>npm install</code> afterwards to refresh your lock file.
            </p>
          )}
          {file.changes.some((c) => c.how === "pin") && (
            <p className="mt-2 text-xs text-slate-500">
              Nested packages are fixed by pinning them at the bottom of the file. Run <code>pip install -r</code> afterwards.
            </p>
          )}
          {file.skipped.map((s) => (
            <p key={s.name} className="mt-1 text-xs text-amber-700">Skipped {s.name}: {s.reason}</p>
          ))}
        </div>
      )}
      {fixable.length > 0 && chosen.length > 0 && names.length === 0 && !err && out && (
        <p className="mt-4 text-sm text-slate-500">These versions are already in your file, so there is nothing to change.</p>
      )}
    </section>
  );
}
