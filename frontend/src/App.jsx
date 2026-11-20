import { Fragment, useMemo, useRef, useState } from "react";
import {
  CartesianGrid, Cell, Line, LineChart, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { CopyButton, SEV_CHIP, SevChips, download } from "./ui.jsx";
import TransitiveAnalysis from "./features/TransitiveAnalysis.jsx";
import Remediation from "./features/Remediation.jsx";

const RISK = {
  Low: { hex: "#10b981", chip: "bg-emerald-100 text-emerald-700" },
  Medium: { hex: "#f59e0b", chip: "bg-amber-100 text-amber-700" },
  High: { hex: "#ef4444", chip: "bg-red-100 text-red-700" },
};
const scoreColor = (s) => (s >= 75 ? "#10b981" : s >= 50 ? "#f59e0b" : "#ef4444");
const GRADIENT = "linear-gradient(120deg, #4f46e5 0%, #7c3aed 50%, #db2777 100%)";

const DEMO = {
  name: "demo-app",
  dependencies: { express: "4.16.0", lodash: "4.17.15", react: "^17.0.2", axios: "0.21.0", moment: "2.29.1" },
};

const upgradeCmd = (d) =>
  d.latest === "unknown"
    ? null
    : d.eco === "npm"
    ? `npm install ${d.name}@${d.latest}`
    : `pip install --upgrade ${d.name}==${d.latest}`;

function RiskBadge({ risk }) {
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold ${RISK[risk].chip}`}>
      {risk}
    </span>
  );
}

function Meter({ label, value }) {
  return (
    <div>
      <div className="mb-1 flex justify-between text-xs text-slate-600">
        <span>{label}</span><span className="font-semibold">{value}</span>
      </div>
      <div className="h-2 rounded-full bg-slate-200">
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: scoreColor(value) }} />
      </div>
    </div>
  );
}

function ScoreRing({ value }) {
  const r = 52, c = 2 * Math.PI * r;
  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#e2e8f0" strokeWidth="11" />
        <circle
          cx="60" cy="60" r={r} fill="none" strokeWidth="11" strokeLinecap="round"
          stroke={scoreColor(value)} strokeDasharray={c} strokeDashoffset={c * (1 - value / 100)}
          style={{ transition: "stroke-dashoffset 0.8s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold tabular-nums" style={{ color: scoreColor(value) }}>{Math.round(value)}</span>
        <span className="text-xs text-slate-500">health score</span>
      </div>
    </div>
  );
}

function EmptyState({ onDemo }) {
  const steps = [
    ["1", "Scan", "Paste a GitHub repo or upload package.json / requirements.txt.", "#4f46e5"],
    ["2", "Understand", "See health scores, outdated packages and vulnerabilities, including nested ones.", "#7c3aed"],
    ["3", "Fix", "Get the smallest safe versions and download the updated file.", "#db2777"],
  ];
  return (
    <section className="rise rounded-2xl bg-white p-8 shadow-sm">
      <h2 className="text-xl font-bold">How it works</h2>
      <div className="mt-5 grid gap-4 md:grid-cols-3">
        {steps.map(([n, title, text, color]) => (
          <div key={n} className="rounded-xl border border-slate-200 p-5 transition hover:-translate-y-0.5 hover:shadow-md">
            <span className="flex h-8 w-8 items-center justify-center rounded-full text-sm font-bold text-white" style={{ background: color }}>{n}</span>
            <p className="mt-3 font-semibold">{title}</p>
            <p className="mt-1 text-sm text-slate-500">{text}</p>
          </div>
        ))}
      </div>
      <button onClick={onDemo} className="mt-6 rounded-lg px-5 py-2.5 text-sm font-semibold text-white shadow hover:opacity-90" style={{ background: GRADIENT }}>
        Try it with a demo project
      </button>
    </section>
  );
}

function Skeleton() {
  const bar = "animate-pulse rounded-lg bg-slate-200";
  return (
    <div className="space-y-6" aria-busy="true">
      <section className="flex items-center gap-6 rounded-2xl bg-white p-6 shadow-sm">
        <div className={`${bar} h-36 w-36 rounded-full`} />
        <div className="flex-1 space-y-3">
          <div className={`${bar} h-7 w-1/3`} />
          <div className={`${bar} h-4 w-2/3`} />
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {[0, 1, 2, 3].map((i) => <div key={i} className={`${bar} h-16`} />)}
          </div>
        </div>
      </section>
      <div className={`${bar} h-56 bg-white`} />
    </div>
  );
}

export default function App() {
  const [mode, setMode] = useState("github");
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [project, setProject] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(null);
  const [sort, setSort] = useState({ key: "health", dir: "asc" });
  const [trans, setTrans] = useState(null);
  const [transLoading, setTransLoading] = useState(false);
  const [transError, setTransError] = useState("");
  const transRun = useRef(0);   // ignores answers from an older scan

  const canSubmit = !loading && (mode === "github" ? url.trim() : file);

  async function loadTransitive(result) {
    const id = ++transRun.current;
    setTrans(null);
    setTransError("");
    setTransLoading(true);
    const deps = result.dependencies
      .map((d) => ({
        name: d.name, eco: d.eco, dev: d.dev,
        version: d.current !== "unknown" ? d.current : d.latest !== "unknown" ? d.latest : null,
      }))
      .filter((d) => d.version);
    try {
      const res = await fetch("/api/transitive", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ deps }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "Nested dependency check failed");
      if (id === transRun.current) setTrans(json);
    } catch (err) {
      if (id === transRun.current) setTransError(err.message);
    } finally {
      if (id === transRun.current) setTransLoading(false);
    }
  }

  async function run(fd) {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/analyze", { method: "POST", body: fd });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || "Analysis failed");
      try {
        const h = await fetch(`/api/history?project=${encodeURIComponent(json.project)}`);
        setHistory(await h.json());
      } catch {
        setHistory([]);
      }
      setData(json);
      setFilter("All");
      setQuery("");
      setOpen(null);
      loadTransitive(json);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function submit(e) {
    e.preventDefault();
    const fd = new FormData();
    fd.append("project", project);
    if (mode === "github") fd.append("github_url", url);
    else fd.append("file", file);
    run(fd);
  }

  function runDemo() {
    const fd = new FormData();
    fd.append("project", "demo-app");
    fd.append("file", new File([JSON.stringify(DEMO, null, 2) + "\n"], "package.json", { type: "application/json" }));
    run(fd);
  }

  const counts = useMemo(() => {
    const c = { Low: 0, Medium: 0, High: 0 };
    data?.dependencies.forEach((d) => c[d.risk]++);
    return c;
  }, [data]);

  const pieData = Object.entries(counts).map(([name, value]) => ({ name, value })).filter((x) => x.value > 0);

  const topFixes = useMemo(
    () => (data?.dependencies ?? []).filter((d) => d.risk !== "Low" || d.vulns.length).slice(0, 3),
    [data]
  );

  const rows = useMemo(() => {
    const get = {
      name: (d) => d.name.toLowerCase(),
      health: (d) => d.health,
      vulns: (d) => d.vulns.length,
    }[sort.key];
    return (data?.dependencies ?? [])
      .filter((d) => (filter === "All" || d.risk === filter) && d.name.toLowerCase().includes(query.toLowerCase()))
      .sort((a, b) => (get(a) > get(b) ? 1 : get(a) < get(b) ? -1 : 0) * (sort.dir === "asc" ? 1 : -1));
  }, [data, filter, query, sort]);

  const toggleSort = (key) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "name" ? "asc" : "asc" }));

  const arrow = (key) => (sort.key === key ? (sort.dir === "asc" ? " ↑" : " ↓") : "");

  function exportCsv() {
    const head = ["Package", "Ecosystem", "Installed", "Latest", "Outdated", "Vulnerabilities", "Health", "Risk", "Recommendation"];
    const body = data.dependencies.map((d) => [
      d.name, d.eco, d.current, d.latest, d.outdated, d.vulns.length, d.health, d.risk, d.recommendations.join(" | "),
    ]);
    const csv = [head, ...body].map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    download(`${data.project}-report.csv`, csv, "text/csv");
  }

  const stats = data && [
    { label: "Dependencies", value: data.total, bg: "#e0f2fe", fg: "#0369a1" },
    { label: "Outdated", value: data.outdated, bg: "#fef3c7", fg: "#b45309" },
    { label: "Vulnerable", value: data.vulnerable, bg: "#fee2e2", fg: "#b91c1c" },
    { label: "Healthy", value: counts.Low, bg: "#d1fae5", fg: "#047857" },
  ];

  const summary =
    data &&
    (topFixes.length
      ? `${data.vulnerable} of ${data.total} packages have known vulnerabilities. Start with ${topFixes[0].name}, it has the highest priority.`
      : "No urgent problems found. Your dependencies look healthy.");

  return (
    <div className="min-h-screen pb-16">
      {/* Hero */}
      <header style={{ background: GRADIENT }} className="relative overflow-hidden px-6 pb-28 pt-12 text-white">
        <div className="pointer-events-none absolute -right-24 -top-24 h-80 w-80 rounded-full bg-white/10 blur-2xl" />
        <div className="pointer-events-none absolute -bottom-32 left-1/3 h-72 w-72 rounded-full bg-fuchsia-300/20 blur-3xl" />
        <div className="relative mx-auto max-w-6xl">
          <span className="rounded-full bg-white/15 px-3 py-1 text-xs font-semibold tracking-wide backdrop-blur">
            Open-source supply-chain health
          </span>
          <h1 className="mt-4 text-4xl font-extrabold tracking-tight md:text-5xl">Dependency Analyzer</h1>
          <p className="mt-3 max-w-xl text-lg text-white/85">
            Find risky, outdated and neglected packages, including the hidden ones nested deep in your tree, and fix them in one click.
          </p>
        </div>
      </header>

      <main className="mx-auto -mt-16 max-w-6xl space-y-6 px-6">
        {/* Input */}
        <section className="rise rounded-2xl bg-white p-5 shadow-lg shadow-indigo-900/10">
          <div className="mb-4 flex items-center justify-between">
            <div className="inline-flex rounded-lg bg-slate-100 p-1 text-sm">
              {[["github", "GitHub repository"], ["file", "Upload file"]].map(([key, label]) => (
                <button
                  key={key} type="button" onClick={() => setMode(key)}
                  className={`rounded-md px-3 py-1.5 font-medium transition ${
                    mode === key ? "bg-white text-indigo-700 shadow-sm" : "text-slate-500 hover:text-slate-700"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <button
              type="button" onClick={runDemo} disabled={loading}
              className="rounded-lg border border-violet-200 bg-violet-50 px-3 py-1.5 text-sm font-medium text-violet-700 hover:bg-violet-100 disabled:opacity-40"
            >
              Try demo
            </button>
          </div>

          <form onSubmit={submit} className="flex flex-col gap-3 md:flex-row">
            {mode === "github" ? (
              <input
                value={url} onChange={(e) => setUrl(e.target.value)}
                placeholder="https://github.com/owner/repository"
                className="flex-1 rounded-lg border border-slate-300 px-3 py-2.5 text-sm outline-none focus:border-violet-500 focus:ring-2 focus:ring-violet-200"
              />
            ) : (
              <label className="flex flex-1 cursor-pointer items-center gap-3 rounded-lg border border-dashed border-slate-300 px-3 py-2 text-sm hover:border-violet-400">
                <span className="rounded bg-violet-100 px-2 py-1 font-medium text-violet-700">Choose file</span>
                <span className="truncate text-slate-500">{file ? file.name : "package.json or requirements.txt"}</span>
                <input type="file" className="hidden" onChange={(e) => setFile(e.target.files[0])} />
              </label>
            )}
            <input
              value={project} onChange={(e) => setProject(e.target.value)} placeholder="Project name (optional)"
              className="rounded-lg border border-slate-300 px-3 py-2.5 text-sm outline-none focus:border-violet-500 focus:ring-2 focus:ring-violet-200 md:w-56"
            />
            <button
              disabled={!canSubmit} style={{ background: GRADIENT }}
              className="rounded-lg px-6 py-2.5 text-sm font-semibold text-white shadow hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {loading ? "Analyzing..." : "Analyze"}
            </button>
          </form>

          {loading && <p className="mt-3 text-sm text-slate-500">Checking registries and the vulnerability database. This can take up to a minute.</p>}
          {error && <p className="mt-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>}
        </section>

        {!data && !loading && <EmptyState onDemo={runDemo} />}
        {!data && loading && <Skeleton />}

        {data && (
          <div className="rise space-y-6">
            {/* Summary */}
            <section className="rounded-2xl bg-white p-6 shadow-sm">
              <div className="flex flex-col gap-6 lg:flex-row lg:items-center">
                <ScoreRing value={data.health} />
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <h2 className="text-2xl font-bold">{data.project}</h2>
                    <RiskBadge risk={data.risk} />
                    <span className="text-sm text-slate-400">Scanned {data.scanned_at}</span>
                  </div>
                  <p className="mt-2 text-sm text-slate-600">{summary}</p>
                  <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
                    {stats.map((s) => (
                      <div key={s.label} className="rounded-xl p-3" style={{ background: s.bg, color: s.fg }}>
                        <div className="text-2xl font-bold tabular-nums">{s.value}</div>
                        <div className="text-xs font-medium opacity-80">{s.label}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="relative h-40 w-40 shrink-0 self-center">
                  <ResponsiveContainer>
                    <PieChart>
                      <Pie data={pieData} dataKey="value" innerRadius={48} outerRadius={70} paddingAngle={3} stroke="none">
                        {pieData.map((p) => <Cell key={p.name} fill={RISK[p.name].hex} />)}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-xl font-bold">{data.total}</span>
                    <span className="text-[11px] text-slate-500">packages</span>
                  </div>
                </div>
              </div>

              <div className="mt-5 flex flex-wrap gap-2 border-t border-slate-100 pt-4">
                <button onClick={exportCsv} className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50">Export CSV</button>
                <button onClick={() => download(`${data.project}-report.json`, JSON.stringify(data, null, 2), "application/json")} className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50">Export JSON</button>
                <button onClick={() => window.print()} className="rounded-lg border border-slate-300 px-3 py-1.5 text-sm hover:bg-slate-50">Print / PDF</button>
              </div>
            </section>

            {/* Top fixes */}
            <section className="rounded-2xl bg-white p-6 shadow-sm">
              <h3 className="mb-4 font-semibold">Fix these first</h3>
              {topFixes.length === 0 ? (
                <p className="text-sm text-emerald-600">Nothing urgent. Great work.</p>
              ) : (
                <div className="grid gap-4 md:grid-cols-3">
                  {topFixes.map((d, i) => (
                    <div key={d.name} className="rounded-xl border border-slate-200 p-4" style={{ borderTop: `4px solid ${RISK[d.risk].hex}` }}>
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-slate-400">#{i + 1}</span>
                        <RiskBadge risk={d.risk} />
                      </div>
                      <p className="mt-1 text-lg font-semibold">{d.name}</p>
                      <p className="text-xs text-slate-500">{d.current} to {d.latest}</p>
                      <div className="my-3"><SevChips sev={d.sev} /></div>
                      <p className="mb-3 text-sm text-slate-600">{d.recommendations[0]}</p>
                      {upgradeCmd(d) && (
                        <div className="flex items-center justify-between gap-2 rounded-lg bg-slate-100 p-2">
                          <code className="truncate text-xs">{upgradeCmd(d)}</code>
                          <CopyButton text={upgradeCmd(d)} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </section>

            <TransitiveAnalysis key={data.scanned_at} trans={trans} loading={transLoading} error={transError} />

            <Remediation key={data.scanned_at} data={data} trans={trans} transLoading={transLoading} />

            {/* History + changes */}
            <section className="grid gap-6 md:grid-cols-2">
              <div className="rounded-2xl bg-white p-5 shadow-sm">
                <h3 className="mb-3 font-semibold">Health over time</h3>
                {history.length < 2 ? (
                  <p className="text-sm text-slate-500">Scan this project again later to see the trend.</p>
                ) : (
                  <div className="h-48">
                    <ResponsiveContainer>
                      <LineChart data={history}>
                        <CartesianGrid stroke="#e2e8f0" vertical={false} />
                        <XAxis dataKey="created" tick={{ fontSize: 11 }} />
                        <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} width={30} />
                        <Tooltip />
                        <Line type="monotone" dataKey="health" stroke="#7c3aed" strokeWidth={3} dot={{ r: 4, fill: "#7c3aed" }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>

              <div className="rounded-2xl bg-white p-5 text-sm shadow-sm">
                <h3 className="mb-3 font-semibold">Changes since last scan</h3>
                {!data.changes ? (
                  <p className="text-slate-500">This is the first scan of this project.</p>
                ) : (
                  <div className="space-y-3">
                    <div
                      className="inline-block rounded-lg px-3 py-2 text-lg font-bold"
                      style={{
                        background: data.changes.health_change >= 0 ? "#d1fae5" : "#fee2e2",
                        color: data.changes.health_change >= 0 ? "#047857" : "#b91c1c",
                      }}
                    >
                      {data.changes.health_change >= 0 ? "▲ +" : "▼ "}{data.changes.health_change} points
                    </div>
                    <p className="text-slate-600">Health went from {data.changes.previous_health} to {data.health}.</p>
                    <p><span className="font-medium text-red-600">{data.changes.new_vulns.length}</span> new vulnerabilities, <span className="font-medium text-emerald-600">{data.changes.fixed_vulns.length}</span> fixed.</p>
                    <p className="text-xs text-slate-400">Compared with scan from {data.changes.previous_date}</p>
                  </div>
                )}
              </div>
            </section>

            {/* Table */}
            <section className="rounded-2xl bg-white shadow-sm">
              <div className="flex flex-col gap-3 border-b border-slate-100 p-4 md:flex-row md:items-center md:justify-between">
                <h3 className="font-semibold">All dependencies</h3>
                <div className="flex items-center gap-2">
                  {["All", "High", "Medium", "Low"].map((f) => (
                    <button
                      key={f} onClick={() => setFilter(f)}
                      className={`rounded-full px-3 py-1 text-xs font-semibold ${
                        filter === f ? "bg-indigo-600 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                  <input
                    value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search"
                    className="w-32 rounded-lg border border-slate-300 px-2 py-1 text-xs outline-none focus:border-violet-500"
                  />
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="cursor-pointer px-4 py-2 font-medium hover:text-indigo-600" onClick={() => toggleSort("name")}>Package{arrow("name")}</th>
                      <th className="px-4 py-2 font-medium">Installed</th>
                      <th className="px-4 py-2 font-medium">Latest</th>
                      <th className="cursor-pointer px-4 py-2 font-medium hover:text-indigo-600" onClick={() => toggleSort("vulns")}>Vulnerabilities{arrow("vulns")}</th>
                      <th className="cursor-pointer px-4 py-2 font-medium hover:text-indigo-600" onClick={() => toggleSort("health")}>Health{arrow("health")}</th>
                      <th className="px-4 py-2 font-medium">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {rows.map((d) => (
                      <Fragment key={d.name + d.eco}>
                        <tr onClick={() => setOpen(open === d.name ? null : d.name)} className="cursor-pointer hover:bg-indigo-50/50">
                          <td className="px-4 py-3">
                            <span className="font-semibold">{d.name}</span>
                            <span className="ml-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-slate-500">{d.eco}{d.dev ? " dev" : ""}</span>
                          </td>
                          <td className="px-4 py-3 tabular-nums">{d.current}</td>
                          <td className="px-4 py-3 tabular-nums">
                            {d.latest}
                            {d.outdated && <span className="ml-1.5 rounded bg-amber-100 px-1.5 py-0.5 text-[11px] font-semibold text-amber-700">update</span>}
                          </td>
                          <td className="px-4 py-3"><SevChips sev={d.sev} /></td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className="w-9 font-semibold tabular-nums" style={{ color: scoreColor(d.health) }}>{d.health}</span>
                              <div className="h-1.5 w-16 rounded-full bg-slate-100">
                                <div className="h-full rounded-full" style={{ width: `${d.health}%`, background: scoreColor(d.health) }} />
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3"><RiskBadge risk={d.risk} /></td>
                        </tr>

                        {open === d.name && (
                          <tr className="bg-slate-50">
                            <td colSpan={6} className="px-4 py-5">
                              <div className="grid gap-6 md:grid-cols-3">
                                <div className="space-y-3">
                                  <p className="text-xs font-bold uppercase tracking-wide text-slate-500">Score breakdown</p>
                                  <Meter label="Security" value={d.security} />
                                  <Meter label="Freshness" value={d.freshness} />
                                  <Meter label="Maintenance" value={d.maintenance} />
                                  {d.days_since_release != null && (
                                    <p className="text-xs text-slate-500">Last release {d.days_since_release} days ago</p>
                                  )}
                                </div>
                                <div>
                                  <p className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-500">Recommended actions</p>
                                  <ul className="list-disc space-y-1 pl-5 text-slate-700">
                                    {d.recommendations.map((r) => <li key={r}>{r}</li>)}
                                  </ul>
                                  {upgradeCmd(d) && (
                                    <div className="mt-3 flex items-center justify-between gap-2 rounded-lg bg-white p-2 ring-1 ring-slate-200">
                                      <code className="truncate text-xs">{upgradeCmd(d)}</code>
                                      <CopyButton text={upgradeCmd(d)} />
                                    </div>
                                  )}
                                </div>
                                <div>
                                  <p className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-500">Known vulnerabilities</p>
                                  {d.vulns.length === 0 ? (
                                    <p className="text-slate-500">None found for this version.</p>
                                  ) : (
                                    <ul className="max-h-44 space-y-1.5 overflow-y-auto pr-2">
                                      {d.vulns.map((v) => (
                                        <li key={v.id} className="flex items-center gap-2">
                                          <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${SEV_CHIP[v.severity] || SEV_CHIP.MODERATE}`}>{v.severity}</span>
                                          <a href={`https://osv.dev/vulnerability/${v.id}`} target="_blank" rel="noreferrer" className="font-mono text-xs text-indigo-700 hover:underline">{v.id}</a>
                                        </li>
                                      ))}
                                    </ul>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                    {rows.length === 0 && (
                      <tr><td colSpan={6} className="px-4 py-8 text-center text-slate-500">No dependencies match.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}