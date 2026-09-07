"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { readHistory, Snapshot } from "./history-store";
import { ResultCards } from "./result-cards";
function assessment(item?: Snapshot): Record<string, unknown> {
  return (item?.data.security as { assessment?: Record<string, unknown> })?.assessment ?? {};
}
export function HistoryPanel({ compare = false }: { compare?: boolean }) {
  const [items, setItems] = useState<Snapshot[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  useEffect(() => { const timer = setTimeout(() => setItems(readHistory()), 0); return () => clearTimeout(timer); }, []);
  const pair = selected.map(id => items.find(item => item.id === id));
  const scores = pair.map(item => assessment(item).score);
  const findings = pair.map(item => {
    const records = assessment(item).findings;
    return Array.isArray(records) ? records as Array<{RuleID?: string; Title?: string; Recommendation?: string}> : [];
  });
  const changes = pair.length === 2 ? {
    "Findings present only in first selection": findings[0].filter(f => !findings[1].some(other => other.RuleID === f.RuleID)),
    "Findings present only in second selection": findings[1].filter(f => !findings[0].some(other => other.RuleID === f.RuleID)),
  } : undefined;
  return <section className="mt-8 space-y-5"><p className="text-sm text-white/60">{compare ? "Select two analyses. A higher security score is better; compare evidence coverage and capture mode before drawing conclusions." : "The latest 20 result snapshots are saved in this browser only. They remain readable after Core restarts. Clearing browser storage removes this history."}</p>{items.length === 0 && <p>No saved analyses yet. Complete an analysis and open its dashboard.</p>}{items.map(item => <article key={item.id} className="border border-teal-200/20 p-4"><div className="flex flex-wrap items-center gap-4">{compare && <input type="checkbox" aria-label={`Compare ${item.id}`} checked={selected.includes(item.id)} disabled={selected.length === 2 && !selected.includes(item.id)} onChange={e => setSelected(ids => e.target.checked ? [...ids, item.id] : ids.filter(id => id !== item.id))}/>}<time>{new Date(item.time).toLocaleString()}</time><Link className="text-teal-200 underline" href={`/dashboard?analysis=${encodeURIComponent(item.id)}`}>{item.id.slice(0, 8)} · Open results</Link><span>Security score: {String(assessment(item).score ?? "Unavailable")}</span></div></article>)}{pair.length === 2 && <div className="space-y-5"><article className="border border-white/15 p-4"><h2 className="mb-4">What differs</h2><ResultCards value={changes}/></article><p className="border border-teal-200/30 p-4">{scores.every(v => typeof v === "number") ? scores[0] === scores[1] ? "Both analyses have the same security score." : `${Number(scores[0]) > Number(scores[1]) ? "First" : "Second"} selected analysis scores ${Math.abs(Number(scores[0]) - Number(scores[1]))} points higher. This is not proof of better security when coverage differs.` : "Scores are unavailable; a winner cannot be determined."}</p><div className="grid gap-5 lg:grid-cols-2">{pair.map(item => <article key={item?.id} className="border border-white/20 p-4"><h2 className="mb-5">{item?.id.slice(0, 8)} · Findings, fixes and coverage</h2><ResultCards value={{assessment: assessment(item), summary: item?.data.summary}}/></article>)}</div></div>}</section>;
}
