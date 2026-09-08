"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import { readHistory, saveSnapshot } from "./history-store";
import { coreURL } from "@/lib/core-url";
import { ResultCards } from "./result-cards";
import { ClassificationCards } from "./classification-cards";
import { RiskCards } from "./risk-cards";

type RecordValue = Record<string, unknown>;
type Insight = RecordValue & { analysis?: { state?: string; stage?: string; source_id?: string } };
type Report = { report_id: string; state: string; download_url?: string; failure_reason?: string };

const sectionsForView: Record<string, Array<[string, string[]]>> = {
  overview: [["Analysis summary", ["summary"]], ["Security posture", ["security", "assessment"]], ["Risk score", ["security", "risk_score"]], ["Fusion coverage", ["fusion", "summary"]]],
  upload: [["Core capabilities", ["system", "capabilities"]], ["Local input availability", ["system", "local_sensor", "mode_availability"]]],
  progress: [["Pipeline progress", ["progress"]], ["Analysis summary", ["summary"]]],
  sessions: [["VPN sessions", ["protocol", "sessions"]], ["IKE exchanges", ["protocol", "ike_exchanges"]], ["Security associations", ["protocol", "security_associations"]], ["NAT traversal", ["protocol", "nat_traversal"]]],
  flows: [["Observed flow telemetry", ["flows", "items"]], ["Traffic summary", ["summary", "traffic"]]],
  classification: [["ML worker", ["ml", "worker"]], ["Traffic predictions", ["ml", "predictions"]], ["Prediction explanations", ["ml", "explanations"]]],
  evidence: [["Protocol evidence", ["protocol", "evidence"]], ["Fused conclusions", ["fusion", "conclusions"]], ["Fusion status", ["fusion", "status"]]],
  findings: [["Assessment and findings", ["security", "assessment"]], ["Recommendations", ["security", "assessment", "recommendations"]]],
  risk: [["Risks and remediation", ["security", "assessment"]], ["Risk score", ["security", "risk_score"]], ["Risk breakdown", ["security", "risk_breakdown"]], ["Critical overrides", ["security", "critical_overrides"]]],
  gateway: [["Local deep-assessment availability", ["system", "local_sensor", "mode_availability"]], ["Source availability", ["fusion", "summary"]], ["Pipeline progress", ["progress"]]],
  health: [["Core readiness", ["system", "readiness"]], ["Core capabilities", ["system", "capabilities"]], ["Local sensor", ["system", "local_sensor"]], ["ML worker", ["ml", "worker"]]],
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(coreURL(path), { ...init, cache: "no-store" });
  const contentType = response.headers.get("content-type") ?? "";
  const body: (T & { error?: string }) | undefined = contentType.includes("application/json") ? await response.json() : undefined;
  if (!response.ok) throw new Error(body?.error ?? `Go Server request failed (${response.status}).`);
  if (!body) throw new Error("Go Server returned an unexpected response.");
  return body;
}

function atPath(source: unknown, path: string[]): unknown {
  return path.reduce<unknown>((value, key) => value && typeof value === "object" && !Array.isArray(value) ? (value as RecordValue)[key] : undefined, source);
}

function count(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  return value && typeof value === "object" ? Object.keys(value).length : 0;
}

function DataBlock({ title, value }: { title: string; value: unknown }) {
  if (value === undefined || value === null || (Array.isArray(value) && value.length === 0) || (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0)) return null;
  return <details className="border border-white/15 bg-black/20 p-4" open={title === "Analysis summary" || title === "Pipeline progress"}>
    <summary className="cursor-pointer text-[10px] font-bold tracking-[.13em] text-teal-100">{title.toUpperCase()} <span className="ml-2 text-white/45">{Array.isArray(value) ? `${value.length} RECORDS` : "AVAILABLE"}</span></summary>
    <div className="mt-4 border-t border-white/10 pt-4"><ResultCards value={value}/></div>
  </details>;
}

export function LiveAnalysisPanel({ view = "overview" }: { view?: string }) {
  const search = useSearchParams();
  const analysisId = search.get("analysis");
  const [health, setHealth] = useState<"CHECKING" | "READY" | "UNAVAILABLE">("CHECKING");
  const [insights, setInsights] = useState<Insight>();
  const [system, setSystem] = useState<RecordValue>();
  const [error, setError] = useState<string>();
  const [report, setReport] = useState<Report>();
  const [archived, setArchived] = useState(false);

  const refresh = useCallback(async () => {
    setError(undefined);
    try {
      const [, systemData, analysisData] = await Promise.all([
        request("/health"),
        request<RecordValue>("/api/v1/system/overview"),
        analysisId ? request<Insight>(`/api/v1/analyses/${encodeURIComponent(analysisId)}/insights`) : Promise.resolve(undefined),
      ]);
      setHealth("READY");
      setSystem(systemData);
      if (analysisData) {
        setArchived(false);
        setInsights(analysisData);
        if (analysisData.analysis?.state === "ANALYSIS_STATE_COMPLETED" && analysisId) {
          try { saveSnapshot(analysisId, analysisData); } catch { setError("Browser history is full or unavailable. Results are still available."); }
        }
      }
    } catch (requestError) {
      setHealth("UNAVAILABLE");
      const saved = readHistory().find(item => item.id === analysisId);
      if (saved) { setInsights(saved.data as Insight); setArchived(true); }
      setError(requestError instanceof Error ? requestError.message : "Unable to reach Go Server.");
    }
  }, [analysisId]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);
  useEffect(() => {
    const state = insights?.analysis?.state;
    if (!analysisId || !state || !["ANALYSIS_STATE_QUEUED", "ANALYSIS_STATE_RUNNING"].includes(state)) return;
    const timer = window.setInterval(() => { void refresh(); }, 1500);
    return () => window.clearInterval(timer);
  }, [analysisId, insights?.analysis?.state, refresh]);
  useEffect(() => {
    if (!report || !report.report_id || ["READY", "FAILED"].includes(report.state)) return;
    const timer = window.setInterval(async () => {
      try { setReport(await request<Report>(`/api/v1/reports/${encodeURIComponent(report.report_id)}`)); }
      catch (requestError) { setError(requestError instanceof Error ? requestError.message : "Report status failed."); }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [report]);

  async function generateReport() {
    if (!analysisId || report?.state === "GENERATING") return;
    try {
      setError(undefined);
      setReport({ report_id: "", state: "GENERATING" });
      setReport(await request<Report>(`/api/v1/analyses/${encodeURIComponent(analysisId)}/report`, { method: "POST" }));
    }
    catch (requestError) { setError(requestError instanceof Error ? requestError.message : "Report generation failed."); }
  }

  const dashboardData = useMemo(() => ({ ...insights, system }), [insights, system]);
  const dataBlocks = useMemo(() => (sectionsForView[view] ?? sectionsForView.overview).map(([title, path]) => [title, atPath(dashboardData, path)] as const), [dashboardData, view]);
  const analysis = insights?.analysis;
  const availableSections = ["protocol", "flows", "fusion", "security", "ml"].reduce((total, key) => total + count(insights?.[key]), 0);

  return <section className="mt-7 border border-white/15 bg-white/[.025] p-5 sm:p-6">
    {archived && <p className="mb-5 border border-amber-200/25 p-4 text-sm text-amber-100">Showing the saved browser snapshot. The server copy is unavailable; existing downloaded PDFs remain valid.</p>}
    {["overview", "risk", "findings"].includes(view) && <RiskCards value={atPath(insights, ["security", "assessment"])}/>}
    {view === "classification" && <ClassificationCards value={atPath(insights, ["ml", "predictions"])}/>}
    <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-[10px] font-bold tracking-[.14em] text-sky-200">LIVE GO SERVER DATA</p><p className="mt-2 text-xs text-white/55">Each value below is fetched from the completed analysis through the same-origin Core proxy.</p></div><button onClick={() => void refresh()} className="border border-white/30 px-3 py-2 text-[9px] font-bold tracking-[.12em] transition hover:bg-white hover:text-black">REFRESH</button></div>
    {!analysisId && !["health", "gateway", "upload"].includes(view) ? <div className="mt-5 border-t border-white/10 pt-5 text-sm leading-7 text-white/60">No analysis is selected. <Link className="text-teal-200 underline underline-offset-4" href="/workspace">Upload a PCAP</Link>, then open the completed analysis dashboard.</div> : <><div className="mt-5 grid gap-2 border-t border-white/10 pt-5 sm:grid-cols-4"><div><p className="text-[9px] text-white/40">GO SERVER</p><p className={`mt-2 text-xs font-bold ${health === "READY" ? "text-teal-200" : "text-red-200"}`}>{health}</p></div><div><p className="text-[9px] text-white/40">ANALYSIS STATE</p><p className="mt-2 text-xs font-bold text-white">{analysis?.state ?? "NOT SELECTED"}</p></div><div><p className="text-[9px] text-white/40">OPERATIONAL STAGE</p><p className="mt-2 text-xs font-bold text-white">{analysis?.stage ?? "—"}</p></div><div><p className="text-[9px] text-white/40">AVAILABLE RECORD GROUPS</p><p className="mt-2 text-xs font-bold text-white">{availableSections}</p></div></div>{view === "overview" && <div className="relative z-10 mt-5 flex flex-wrap items-center gap-3"><button onClick={() => void generateReport()} disabled={archived || analysis?.state !== "ANALYSIS_STATE_COMPLETED" || report?.state === "GENERATING"} className="border border-teal-200 bg-teal-200 px-3 py-2 text-[9px] font-bold tracking-[.12em] text-slate-950 transition-colors duration-200 hover:bg-transparent hover:text-teal-100 active:translate-y-px active:bg-teal-100 disabled:translate-y-0 disabled:cursor-not-allowed disabled:opacity-40">{report?.state === "GENERATING" ? "GENERATING PDF…" : "GENERATE EXECUTIVE PDF"}</button>{report && <span className="text-[10px] text-white/55" role="status" aria-live="polite">REPORT: {report.state}{report.failure_reason ? ` · ${report.failure_reason}` : ""}</span>}{report?.state === "GENERATING" && <button type="button" disabled className="pointer-events-none inline-flex min-w-32 items-center justify-center border border-white/20 bg-white/[.03] px-3 py-2 text-[9px] font-bold tracking-[.12em] text-white/35">PREPARING PDF…</button>}{report?.state === "READY" && report.download_url && <a href={`/api/core${report.download_url}`} download className="group relative isolate inline-flex min-w-32 cursor-pointer overflow-hidden border border-white/50 bg-transparent px-3 py-2 text-[9px] font-bold tracking-[.12em] text-white shadow-[0_0_28px_rgba(255,255,255,.12)] transition-all duration-300 hover:border-teal-200 hover:bg-teal-200/15 hover:text-teal-100 hover:shadow-[0_0_38px_rgba(94,234,212,.28)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-200 active:translate-y-px active:bg-teal-100 active:shadow-none"><span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-teal-100/25 to-transparent transition-transform duration-700 group-hover:translate-x-full" /><span className="absolute -left-1 -top-1 hidden h-3 w-3 border-l border-t border-white/70 group-hover:border-teal-100 lg:block" /><span className="absolute -bottom-1 -right-1 hidden h-3 w-3 border-b border-r border-white/70 group-hover:border-teal-100 lg:block" /><span className="relative">DOWNLOAD PDF</span></a>}{report?.state === "FAILED" && <button type="button" disabled className="inline-flex min-w-32 items-center justify-center border border-red-200/25 px-3 py-2 text-[9px] font-bold tracking-[.12em] text-red-100/45">PDF UNAVAILABLE</button>}</div>}<div className="mt-5 grid gap-3">{dataBlocks.map(([title, value]) => <DataBlock key={title} title={title} value={value} />)}{dataBlocks.every(([, value]) => value === undefined || value === null || (Array.isArray(value) && value.length === 0) || (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0)) && <p className="border border-dashed border-white/20 p-4 text-xs leading-6 text-white/55">This section has no records yet. The analysis may still be running, the capture may not contain this protocol data, or the optional service may be unavailable.</p>}</div></>}
    {error && <p className="mt-5 border border-red-300/50 bg-red-300/10 p-3 text-xs text-red-100">{error}</p>}
  </section>;
}
