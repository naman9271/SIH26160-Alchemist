"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { readHistory, Snapshot } from "./history-store";
import { securityScorePresentation, SecurityScorePresentation } from "./security-score";

type Finding = { id: string; title: string; severity: string; description?: string; recommendation?: string };

function assessment(item?: Snapshot): Record<string, unknown> {
  return (item?.data.security as { assessment?: Record<string, unknown> })?.assessment ?? {};
}

function findingsFor(item?: Snapshot): Finding[] {
  const value = assessment(item).findings;
  if (!Array.isArray(value)) return [];
  return value.map((raw, index) => {
    const finding = (raw ?? {}) as Record<string, unknown>;
    const text = (key: string) => typeof finding[key] === "string" ? finding[key] : undefined;
    return {
      id: text("RuleID") ?? text("rule_id") ?? text("ruleId") ?? `finding-${index}`,
      title: text("Title") ?? text("title") ?? "Unnamed finding",
      severity: text("Severity") ?? text("severity") ?? "Unrated",
      description: text("Description") ?? text("description"),
      recommendation: text("Recommendation") ?? text("recommendation"),
    };
  });
}

function scoreText(score: SecurityScorePresentation) {
  if (score.assessedScore === undefined) return "Score unavailable";
  return score.isProvisional ? `${score.assessedScore}/100 · incomplete evidence` : `${score.assessedScore}/100 · verified`;
}

function SnapshotChoice({ item, selected, disabled, onChange, selectable = true }: { item: Snapshot; selected: boolean; disabled: boolean; onChange: () => void; selectable?: boolean }) {
  const score = securityScorePresentation(assessment(item));
  return <div className={`flex flex-wrap items-center gap-x-4 gap-y-2 border p-4 ${selected ? "border-teal-200/60 bg-teal-200/[.08]" : "border-teal-200/20"}`}>
    {selectable && <input type="checkbox" aria-label={`Compare analysis ${item.id}`} checked={selected} disabled={disabled} onChange={onChange} className="h-4 w-4 accent-teal-300" />}
    <span className="min-w-40 font-semibold text-white">{new Date(item.time).toLocaleString()}</span>
    <span className="text-sm text-teal-100">{scoreText(score)}</span>
    <Link className="ml-auto text-sm text-teal-200 underline" href={`/dashboard?analysis=${encodeURIComponent(item.id)}`}>Open analysis</Link>
  </div>;
}

function FindingList({ title, findings, tone }: { title: string; findings: Finding[]; tone: "new" | "gone" }) {
  const empty = tone === "new" ? "No new findings in the second analysis." : "No findings were resolved in the second analysis.";
  return <section className="border border-white/15 p-4"><h3 className="text-base font-bold">{title} <span className="text-sm font-normal text-white/50">({findings.length})</span></h3>
    {findings.length === 0 ? <p className="mt-3 text-sm text-white/55">{empty}</p> : <ul className="mt-3 grid gap-3">{findings.map(finding => <li key={finding.id} className="border-l-2 border-teal-200/60 bg-white/[.03] px-3 py-3"><p className="text-sm font-semibold text-white">{finding.title} <span className="font-normal text-white/55">· {finding.severity}</span></p><p className="mt-1 text-xs text-white/45">{finding.id}</p>{finding.description && <p className="mt-2 text-sm text-white/70">{finding.description}</p>}{finding.recommendation && <p className="mt-2 text-sm text-teal-100"><span className="font-semibold">Recommended action:</span> {finding.recommendation}</p>}</li>)}</ul>}
  </section>;
}

function ComparisonSummary({ first, second }: { first: Snapshot; second: Snapshot }) {
  const firstScore = securityScorePresentation(assessment(first));
  const secondScore = securityScorePresentation(assessment(second));
  const firstFindings = findingsFor(first);
  const secondFindings = findingsFor(second);
  const resolved = firstFindings.filter(finding => !secondFindings.some(other => other.id === finding.id));
  const newFindings = secondFindings.filter(finding => !firstFindings.some(other => other.id === finding.id));
  const scoreChange = firstScore.assessedScore !== undefined && secondScore.assessedScore !== undefined ? secondScore.assessedScore - firstScore.assessedScore : undefined;
  const scoreMessage = scoreChange === undefined ? "A score change cannot be calculated because one analysis has no score." : scoreChange === 0 ? "The security score did not change." : `Security score ${scoreChange > 0 ? "increased" : "decreased"} by ${Math.abs(scoreChange)} points.`;
  return <div className="space-y-5">
    <section className="border border-teal-200/30 bg-teal-200/[.04] p-5"><h2 className="text-lg font-bold">Comparison summary</h2><p className="mt-2 text-sm text-white/70">Changes are shown from the first selected analysis to the second selected analysis.</p><div className="mt-4 grid gap-3 sm:grid-cols-3"><div><p className="text-xs uppercase tracking-wide text-white/50">Score change</p><p className="mt-1 text-lg font-semibold text-teal-100">{scoreChange === undefined ? "Unavailable" : `${scoreChange > 0 ? "+" : ""}${scoreChange} points`}</p></div><div><p className="text-xs uppercase tracking-wide text-white/50">Resolved findings</p><p className="mt-1 text-lg font-semibold text-teal-100">{resolved.length}</p></div><div><p className="text-xs uppercase tracking-wide text-white/50">New findings</p><p className="mt-1 text-lg font-semibold text-teal-100">{newFindings.length}</p></div></div><p className="mt-4 border-t border-white/10 pt-3 text-sm text-white/75">{scoreMessage}</p>{firstScore.isProvisional || secondScore.isProvisional ? <p className="mt-2 text-sm text-amber-100">Score confidence is limited: one or both analyses have incomplete configuration evidence.</p> : null}</section>
    <div className="grid gap-5 lg:grid-cols-2"><FindingList title="Resolved since the first analysis" findings={resolved} tone="gone" /><FindingList title="New in the second analysis" findings={newFindings} tone="new" /></div>
  </div>;
}

export function HistoryPanel({ compare = false }: { compare?: boolean }) {
  const [items, setItems] = useState<Snapshot[]>([]);
  const [selected, setSelected] = useState<string[]>([]);
  useEffect(() => { const timer = setTimeout(() => setItems(readHistory()), 0); return () => clearTimeout(timer); }, []);
  const pair = selected.map(id => items.find(item => item.id === id)).filter((item): item is Snapshot => Boolean(item));
  const toggle = (id: string) => setSelected(ids => ids.includes(id) ? ids.filter(value => value !== id) : [...ids, id].slice(0, 2));

  if (!compare) return <section className="mt-8 space-y-5"><p className="text-sm text-white/60">The latest 20 result snapshots are saved in this browser only. They remain readable after Core restarts. Clearing browser storage removes this history.</p>{items.length === 0 ? <p>No saved analyses yet. Complete an analysis and open its dashboard.</p> : items.map(item => <SnapshotChoice key={item.id} item={item} selected={false} disabled={false} selectable={false} onChange={() => undefined} />)}</section>;

  return <section className="mt-8 space-y-5"><div><p className="text-sm text-white/70">Choose an earlier analysis first, then a later one. The page will show what was resolved and what is new.</p><p className="mt-1 text-xs text-white/45">{pair.length === 2 ? "Two analyses selected — comparison ready." : `${2 - pair.length} more analysis${pair.length === 1 ? "" : "es"} needed.`}</p></div>{items.length === 0 ? <p>No saved analyses yet. Complete an analysis and open its dashboard.</p> : <div className="grid gap-3">{items.map(item => <SnapshotChoice key={item.id} item={item} selected={selected.includes(item.id)} disabled={selected.length === 2 && !selected.includes(item.id)} onChange={() => toggle(item.id)} />)}</div>}{pair.length === 2 ? <ComparisonSummary first={pair[0]} second={pair[1]} /> : null}</section>;
}
