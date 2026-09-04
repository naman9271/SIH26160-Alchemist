"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

type Insight = Record<string, unknown> & { analysis?: { state?: string; stage?: string } };
type Report = { report_id: string; state: string; download_url?: string; failure_reason?: string };

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/core${path}`, { ...init, cache: "no-store" });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(body.error ?? "Go Server request failed.");
  return body;
}

function sectionCount(insights: Insight | undefined, key: string) {
  const section = insights?.[key];
  return section && typeof section === "object" ? Object.keys(section as object).length : 0;
}

export function LiveAnalysisPanel() {
  const search = useSearchParams();
  const analysisId = search.get("analysis");
  const [health, setHealth] = useState<"CHECKING" | "READY" | "UNAVAILABLE">("CHECKING");
  const [insights, setInsights] = useState<Insight>();
  const [error, setError] = useState<string>();
  const [report, setReport] = useState<Report>();

  const refresh = useCallback(async () => {
    setError(undefined);
    try {
      await request("/health");
      setHealth("READY");
      if (analysisId) setInsights(await request<Insight>(`/api/v1/analyses/${analysisId}/insights`));
    } catch (requestError) {
      setHealth("UNAVAILABLE");
      setError(requestError instanceof Error ? requestError.message : "Unable to reach Go Server.");
    }
  }, [analysisId]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  useEffect(() => {
    if (!report || ["READY", "FAILED"].includes(report.state)) return;
    const timer = window.setInterval(async () => {
      try { setReport(await request<Report>(`/api/v1/reports/${report.report_id}`)); }
      catch (requestError) { setError(requestError instanceof Error ? requestError.message : "Report status failed."); }
    }, 1500);
    return () => window.clearInterval(timer);
  }, [report]);

  async function generateReport() {
    if (!analysisId) return;
    try { setReport(await request<Report>(`/api/v1/analyses/${analysisId}/report`, { method: "POST" })); }
    catch (requestError) { setError(requestError instanceof Error ? requestError.message : "Report generation failed."); }
  }

  const analysis = insights?.analysis;
  return <section className="mt-7 border border-white/15 bg-white/[.025] p-5 sm:p-6">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-[10px] font-bold tracking-[.14em] text-sky-200">LIVE GO SERVER DATA</p><p className="mt-2 text-xs text-white/55">Health and aggregate analysis insights are fetched through the Next.js Go Server proxy.</p></div><button onClick={() => void refresh()} className="border border-white/30 px-3 py-2 text-[9px] font-bold tracking-[.12em] transition hover:bg-white hover:text-black">REFRESH</button></div>
    {!analysisId ? <div className="mt-5 border-t border-white/10 pt-5 text-sm leading-7 text-white/60">No analysis is selected. <Link className="text-teal-200 underline underline-offset-4" href="/workspace">Upload a PCAP</Link>, then open the completed analysis dashboard.</div> : <><div className="mt-5 grid gap-2 border-t border-white/10 pt-5 sm:grid-cols-4"><div><p className="text-[9px] text-white/40">GO SERVER</p><p className={`mt-2 text-xs font-bold ${health === "READY" ? "text-teal-200" : "text-red-200"}`}>{health}</p></div><div><p className="text-[9px] text-white/40">ANALYSIS STATE</p><p className="mt-2 text-xs font-bold text-white">{analysis?.state ?? "LOADING"}</p></div><div><p className="text-[9px] text-white/40">OPERATIONAL STAGE</p><p className="mt-2 text-xs font-bold text-white">{analysis?.stage ?? "—"}</p></div><div><p className="text-[9px] text-white/40">AVAILABLE SECTIONS</p><p className="mt-2 text-xs font-bold text-white">{sectionCount(insights, "protocol") + sectionCount(insights, "fusion") + sectionCount(insights, "security") + sectionCount(insights, "ml")}</p></div></div><div className="mt-5 flex flex-wrap items-center gap-3"><button onClick={() => void generateReport()} className="border border-teal-200 bg-teal-200 px-3 py-2 text-[9px] font-bold tracking-[.12em] text-slate-950 transition hover:bg-transparent hover:text-teal-100">GENERATE EXECUTIVE PDF</button>{report && <span className="text-[10px] text-white/55">REPORT: {report.state}</span>}{report?.download_url && <a href={`/api/core${report.download_url}`} className="border border-white/40 px-3 py-2 text-[9px] font-bold tracking-[.12em] hover:bg-white hover:text-black">DOWNLOAD PDF</a>}</div></>}
    {error && <p className="mt-5 border border-red-300/50 bg-red-300/10 p-3 text-xs text-red-100">{error}</p>}
  </section>;
}
