import { useState } from "react";
import { SEV_CHIP, SevChips } from "../ui.jsx";

const sevCounts = (vulns) =>
  vulns.reduce((c, v) => ({ ...c, [v.severity]: (c[v.severity] || 0) + 1 }), {});

function Stat({ label, value, bg, fg }) {
  return (
    <div className="rounded-xl p-3" style={{ background: bg, color: fg }}>
      <div className="text-2xl font-bold tabular-nums">{value}</div>
      <div className="text-xs font-medium opacity-80">{label}</div>
    </div>
  );
}

/* One package in the tree. Branches that lead to a vulnerable package start open. */
function TreeNode({ node, depth, onlyRisky }) {
  const [open, setOpen] = useState(node.has_vuln_below);
  const vulnerable = node.vulns.length > 0;
  const kids = onlyRisky ? node.children.filter((c) => c.has_vuln_below || c.vulns.length) : node.children;
  const tone = vulnerable
    ? "bg-red-50 ring-1 ring-red-200"
    : node.has_vuln_below
    ? "bg-amber-50"
    : "hover:bg-slate-50";

  return (
    <div>
      <div
        onClick={() => kids.length && setOpen(!open)}
        className={`flex flex-wrap items-center gap-2 rounded px-2 py-1 text-sm ${tone} ${kids.length ? "cursor-pointer" : ""}`}
        style={{ marginLeft: depth * 18 }}
      >
        <span className="w-3 text-xs text-slate-400">{kids.length ? (open ? "▼" : "▶") : "·"}</span>
        <span className={vulnerable ? "font-semibold text-red-700" : "font-medium"}>{node.name}</span>
        <span className="text-xs tabular-nums text-slate-500">{node.version}</span>
        {vulnerable && <SevChips sev={sevCounts(node.vulns)} />}
        {!vulnerable && node.has_vuln_below && (
          <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-semibold text-amber-700">
            affected parent
          </span>
        )}
        {node.dup && <span className="text-[11px] text-slate-400">↺ dependencies shown above</span>}
      </div>
      {open && kids.map((c, i) => <TreeNode key={c.name + c.version + i} node={c} depth={depth + 1} onlyRisky={onlyRisky} />)}
    </div>
  );
}

function VulnerableCard({ v }) {
  const worst = Object.keys(SEV_CHIP).find((s) => v.sev[s]) || "MODERATE";
  return (
    <div className="rounded-xl border border-slate-200 p-4" style={{ borderLeft: "4px solid #ef4444" }}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-lg font-semibold">{v.name}</span>
        <span className="text-sm tabular-nums text-slate-500">{v.version}</span>
        <span className={`rounded px-1.5 py-0.5 text-[11px] font-bold ${SEV_CHIP[worst]}`}>{worst}</span>
        <SevChips sev={v.sev} />
      </div>

      <div className="mt-3 grid gap-4 text-sm md:grid-cols-2">
        <div>
          <p className="mb-1 text-xs font-bold uppercase tracking-wide text-slate-500">How it got in</p>
          {v.paths.map((p, i) => (
            <p key={i} className="font-mono text-xs leading-6 text-slate-700">
              {p.map((step, j) => (
                <span key={j}>
                  {j > 0 && <span className="text-slate-400"> → </span>}
                  <span className={j === p.length - 1 ? "font-bold text-red-700" : ""}>{step}</span>
                </span>
              ))}
            </p>
          ))}
        </div>
        <div>
          <p className="mb-1 text-xs font-bold uppercase tracking-wide text-slate-500">Affected packages</p>
          <div className="flex flex-wrap gap-1.5">
            {v.affected_direct.map((a) => (
              <span key={a} className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-semibold text-amber-800">
                {a}
              </span>
            ))}
          </div>
          <p className="mt-2 text-xs text-slate-500">
            Required directly by: <span className="font-medium text-slate-700">{v.parents.join(", ")}</span>
          </p>
        </div>
      </div>

      <ul className="mt-3 space-y-1">
        {v.vulns.map((x) => (
          <li key={x.id} className="flex items-center gap-2 text-xs">
            <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${SEV_CHIP[x.severity] || SEV_CHIP.MODERATE}`}>
              {x.severity}
            </span>
            <a href={`https://osv.dev/vulnerability/${x.id}`} target="_blank" rel="noreferrer" className="font-mono text-indigo-700 hover:underline">
              {x.id}
            </a>
            <span className="truncate text-slate-500">{x.summary}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function TransitiveAnalysis({ trans, loading, error }) {
  const [onlyRisky, setOnlyRisky] = useState(true);

  return (
    <section className="rounded-2xl bg-white p-6 shadow-sm">
      <h3 className="font-semibold">Hidden risks in nested dependencies</h3>
      <p className="mb-4 text-sm text-slate-500">
        Packages you never installed on purpose but that come along with the ones you did.
      </p>

      {loading && <p className="text-sm text-slate-500">Resolving the full dependency tree and checking every nested package...</p>}
      {error && <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}

      {trans && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Direct packages scanned" value={trans.summary.direct_scanned} bg="#e0f2fe" fg="#0369a1" />
            <Stat label="Nested packages" value={trans.summary.nested_packages} bg="#ede9fe" fg="#6d28d9" />
            <Stat label="Vulnerable nested" value={trans.summary.vulnerable_nested} bg="#fee2e2" fg="#b91c1c" />
            <Stat label="Parents affected" value={trans.summary.affected_direct} bg="#fef3c7" fg="#b45309" />
          </div>

          {trans.errors.length > 0 && (
            <p className="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">
              Could not resolve the tree for: {trans.errors.map((e) => e.name).join(", ")}.
            </p>
          )}

          {trans.vulnerable.length === 0 ? (
            <p className="text-sm text-emerald-600">No known vulnerabilities in any nested package.</p>
          ) : (
            <div className="space-y-3">
              <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Vulnerable nested packages</p>
              {trans.vulnerable.map((v) => <VulnerableCard key={v.eco + v.name + v.version} v={v} />)}
            </div>
          )}

          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Dependency tree</p>
              <label className="flex cursor-pointer items-center gap-2 text-xs text-slate-600">
                <input type="checkbox" checked={onlyRisky} onChange={(e) => setOnlyRisky(e.target.checked)} />
                Only show branches with vulnerabilities
              </label>
            </div>
            <div className="max-h-[28rem] space-y-0.5 overflow-y-auto rounded-xl border border-slate-200 p-2">
              {trans.tree
                .filter((t) => !onlyRisky || t.has_vuln_below)
                .map((t) => (
                  <TreeNode key={t.eco + t.name} node={t} depth={0} onlyRisky={onlyRisky} />
                ))}
              {onlyRisky && !trans.tree.some((t) => t.has_vuln_below) && (
                <p className="p-3 text-sm text-slate-500">Nothing to show. Untick the box to see the whole tree.</p>
              )}
            </div>
            <p className="mt-2 text-xs text-slate-400">
              Red = vulnerable package, amber = parent that pulls one in. The tree shows what each package would install
              on its own, so a real lockfile may pick slightly different versions.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}
