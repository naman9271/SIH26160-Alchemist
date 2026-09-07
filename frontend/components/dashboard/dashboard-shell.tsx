"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { LandingFooter } from "@/components/ui/site-chrome";
import { LiveAnalysisPanel } from "./live-analysis-panel";
import { HistoryPanel } from "./history-panel";
import { ReportChat } from "./report-chat";

const navigation = [
  { slug: "overview", name: "Overview", description: "See the analysis, evidence coverage, security score, and risk at a glance." },
  { slug: "upload", name: "New capture", description: "Upload a PCAP or start an authorized live or deep capture." },
  { slug: "progress", name: "Progress flow", description: "Follow the current analysis stage and optional-source availability." },
  { slug: "sessions", name: "VPN sessions", description: "Inspect observed IKE, ESP, AH, NAT-T, and security-association records." },
  { slug: "flows", name: "Flows", description: "Review metadata-only traffic flows and their measured statistics." },
  { slug: "classification", name: "Traffic classifier", description: "Interpret inferred traffic classes, confidence, and UNKNOWN results." },
  { slug: "evidence", name: "Evidence", description: "Trace observations, derived facts, fused conclusions, and missing sources." },
  { slug: "findings", name: "Security findings", description: "Read deterministic findings and the evidence behind each one." },
  { slug: "risk", name: "Risk & fixes", description: "Understand score drivers and prioritized remediation guidance." },
  { slug: "reports", name: "Generate report", description: "Create and download the professional analysis PDF." },
  { slug: "chat", name: "Report assistant", description: "Ask plain-language questions about a saved analysis snapshot." },
  { slug: "health", name: "System health", description: "Check Core, local sensor, gateway, and ML readiness." },
  { slug: "history", name: "History", description: "Reopen analysis snapshots stored in this browser." },
  { slug: "compare", name: "Compare analyses", description: "Compare two saved snapshots without changing their original data." },
];

export function DashboardShell({ view = "overview" }: { view?: string }) {
  const search = useSearchParams();
  const id = search.get("analysis");
  const title = navigation.find((item) => item.slug === view)?.name ?? "Overview";
  function href(slug: string) {
    if (slug === "upload") return "/workspace";
    return (slug === "overview" ? "/dashboard" : "/dashboard/" + slug) + (id ? "?analysis=" + encodeURIComponent(id) : "");
  }
  return <div className="min-h-svh bg-black font-mono text-white">
    <div className="dashboard-shell-grid mx-auto grid max-w-[1600px]">
      <aside className="dashboard-sidebar relative z-20 border-r border-teal-200/15 bg-[#05090f] p-3 lg:sticky lg:top-0 lg:h-svh lg:overflow-x-hidden lg:overflow-y-auto">
        <div className="dashboard-sidebar-brand grid min-h-12 items-center gap-3 px-2">
          <span className="grid h-9 w-9 place-items-center border border-teal-200/40 bg-teal-200/[.06] text-teal-100 shadow-[0_0_20px_rgba(94,234,212,.1)]" aria-hidden="true">
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3 19 6v5c0 4.6-2.8 8-7 10-4.2-2-7-5.4-7-10V6l7-3Z" />
              <path d="M8.5 12h7M10 9.5l-1.5 2.5L10 14.5M14 9.5l1.5 2.5-1.5 2.5" />
            </svg>
          </span>
          <p className="dashboard-sidebar-label whitespace-nowrap text-xs font-bold tracking-widest text-teal-200">ANALYSIS WORKSPACE</p>
        </div>
        <nav className="dashboard-sidebar-nav mt-3 flex gap-2 overflow-x-auto lg:grid" aria-label="Dashboard navigation">{navigation.map((item) => <Link key={item.slug} href={href(item.slug)} title={`${item.name}: ${item.description}`} aria-current={item.slug === view ? "page" : undefined} className={"dashboard-sidebar-link group/link block shrink-0 overflow-hidden border px-3 py-3 transition-[background-color,border-color,color,box-shadow] duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-200 " + (item.slug === view ? "border-teal-200/40 bg-teal-200/10 text-teal-100 shadow-[inset_2px_0_0_rgba(94,234,212,.8)]" : "border-transparent text-white/55 hover:border-white/15 hover:bg-white/5 hover:text-white")}>
          <span className="block text-xs font-bold leading-[1.15rem] tracking-[.055em]">{item.name}</span>
          <span className="dashboard-sidebar-description block max-h-0 overflow-hidden text-[10px] leading-[1.15rem] text-white/42 opacity-0 transition-[max-height,margin,opacity,color] duration-300 group-hover/link:mt-2 group-hover/link:max-h-14 group-hover/link:text-white/62 group-hover/link:opacity-100 group-focus-visible/link:mt-2 group-focus-visible/link:max-h-14 group-focus-visible/link:text-white/62 group-focus-visible/link:opacity-100">{item.description}</span>
        </Link>)}</nav>
      </aside>
      <main className="min-w-0 p-5 sm:p-8"><h1 className="text-3xl font-bold">{title}</h1>
        {id && <p className="mt-3 break-all text-xs text-white/40">Analysis {id}</p>}
        {view === "history" || view === "compare" ? <HistoryPanel compare={view === "compare"}/> : view === "chat" ? <ReportChat/> : <LiveAnalysisPanel key={id ?? "none"} view={view}/>}
      </main>
    </div><LandingFooter/>
  </div>;
}
