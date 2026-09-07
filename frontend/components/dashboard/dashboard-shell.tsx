"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { LandingFooter } from "@/components/ui/site-chrome";
import { LiveAnalysisPanel } from "./live-analysis-panel";
import { HistoryPanel } from "./history-panel";
import { ReportChat } from "./report-chat";

const navigation = [
  ["overview", "Overview"], ["upload", "New capture"], ["progress", "Progress"],
  ["sessions", "VPN sessions"], ["flows", "Flows"], ["classification", "Traffic classification"],
  ["evidence", "Evidence"], ["findings", "Security findings"], ["risk", "Risk & fixes"],
  ["reports", "Reports"], ["health", "System health"], ["history", "History"],
  ["compare", "Compare analyses"], ["chat", "Report assistant"],
];

export function DashboardShell({ view = "overview" }: { view?: string }) {
  const search = useSearchParams();
  const id = search.get("analysis");
  const title = navigation.find(([slug]) => slug === view)?.[1] ?? "Overview";
  function href(slug: string) {
    if (slug === "upload") return "/workspace";
    return (slug === "overview" ? "/dashboard" : "/dashboard/" + slug) + (id ? "?analysis=" + encodeURIComponent(id) : "");
  }
  return <div className="min-h-svh bg-black font-mono text-white">
    <div className="mx-auto grid max-w-[1600px] lg:grid-cols-[240px_minmax(0,1fr)]">
      <aside className="border-r border-teal-200/15 bg-[#05090f] p-4 lg:sticky lg:top-16 lg:h-[calc(100vh-4rem)] lg:overflow-y-auto">
        <p className="mb-5 text-xs tracking-widest text-teal-200">ANALYSIS WORKSPACE</p>
        <nav className="flex gap-2 overflow-x-auto lg:grid" aria-label="Dashboard navigation">{navigation.map(([slug, name]) => <Link key={slug} href={href(slug)} className={"shrink-0 border px-3 py-2.5 text-xs " + (slug === view ? "border-teal-200/40 bg-teal-200/10 text-teal-100" : "border-transparent text-white/55 hover:bg-white/5")}>{name}</Link>)}</nav>
      </aside>
      <main className="min-w-0 p-5 sm:p-8"><h1 className="text-3xl font-bold">{title}</h1>
        {id && <p className="mt-3 break-all text-xs text-white/40">Analysis {id}</p>}
        {view === "history" || view === "compare" ? <HistoryPanel compare={view === "compare"}/> : view === "chat" ? <ReportChat/> : <LiveAnalysisPanel key={id ?? "none"} view={view}/>}
      </main>
    </div><LandingFooter/>
  </div>;
}
