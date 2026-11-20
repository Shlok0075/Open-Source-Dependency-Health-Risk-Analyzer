import { useState } from "react";

export const SEV_CHIP = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-red-100 text-red-700",
  MODERATE: "bg-amber-100 text-amber-700",
  LOW: "bg-sky-100 text-sky-700",
};

export function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
}

export function SevChips({ sev }) {
  const items = Object.entries(sev).filter(([, n]) => n > 0);
  if (!items.length) return <span className="text-xs text-emerald-600">Clean</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map(([k, n]) => (
        <span key={k} className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${SEV_CHIP[k]}`}>
          {n} {k.toLowerCase()}
        </span>
      ))}
    </div>
  );
}

export function CopyButton({ text, label = "Copy command" }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      }}
      className="rounded-md bg-slate-900 px-2.5 py-1 text-xs font-medium text-white hover:bg-slate-700"
    >
      {done ? "Copied" : label}
    </button>
  );
}
