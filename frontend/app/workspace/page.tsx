"use client";

import Link from "next/link";
import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import { LandingFooter } from "@/components/ui/site-chrome";

type Health = { status?: string };
type Upload = { source_id: string; filename: string; packets: number; esp_packets: number };
type Analysis = { analysis_id: string; state: string; stage: string; failure_reason?: string };
type WorkspaceMode = "pcap" | "live" | "deep";

const workspaceSteps = [
  ["01", "MODE", "Choose PCAP, live, or deep assessment."],
  ["02", "SOURCE", "Attach a classic capture file."],
  ["03", "ANALYSE", "Run evidence-first processing."],
  ["04", "RESULTS", "Open the dashboard report."],
];

async function coreRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/core${path}`, { ...init, cache: "no-store" });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(body.error ?? "The Go Server could not complete this request.");
  return body;
}

export default function WorkspacePage() {
  const [file, setFile] = useState<File>();
  const [mode, setMode] = useState<WorkspaceMode>("pcap");
  const [enableMl, setEnableMl] = useState(true);
  const [health, setHealth] = useState<"checking" | "ready" | "unavailable">("checking");
  const [phase, setPhase] = useState<"idle" | "uploading" | "starting" | "running" | "complete" | "failed">("idle");
  const [upload, setUpload] = useState<Upload>();
  const [analysis, setAnalysis] = useState<Analysis>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    coreRequest<Health>("/health").then(() => setHealth("ready")).catch(() => setHealth("unavailable"));
  }, []);

  useEffect(() => {
    if (!analysis || !["QUEUED", "RUNNING"].includes(analysis.state)) return;
    const interval = window.setInterval(async () => {
      try {
        const next = await coreRequest<Analysis>(`/api/v1/analyses/${encodeURIComponent(analysis.analysis_id)}`);
        setAnalysis(next);
        if (next.state === "COMPLETED") setPhase("complete");
        if (["FAILED", "CANCELLED"].includes(next.state)) {
          setPhase("failed");
          setError(next.failure_reason ?? "The analysis did not complete.");
        }
      } catch (pollError) {
        setPhase("failed");
        setError(pollError instanceof Error ? pollError.message : "Analysis polling failed.");
      }
    }, 1500);
    return () => window.clearInterval(interval);
  }, [analysis]);

  function selectFile(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0]);
    setUpload(undefined);
    setAnalysis(undefined);
    setError(undefined);
    setPhase("idle");
  }

  async function startWorkflow(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mode !== "pcap") {
      setError(mode === "live" ? "Live capture is not exposed by the current browser API. Use a trusted client or add a Go Server HTTP adapter." : "Deep Assessment requires explicit authorization and a browser adapter for VICI/XFRM readiness.");
      return;
    }
    if (!file) return;
    if (!/\.(pcap|cap)$/i.test(file.name)) {
      setError("Use a classic .pcap or .cap file. Convert PCAPNG before upload.");
      return;
    }
    setError(undefined);
    setPhase("uploading");
    try {
      const form = new FormData();
      form.set("pcap", file);
      const uploaded = await coreRequest<Upload>("/api/v1/pcap", { method: "POST", body: form });
      setUpload(uploaded);
      setPhase("starting");
      const started = await coreRequest<Analysis>("/api/v1/analyses", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ source_id: uploaded.source_id, enable_ml: enableMl }),
      });
      setAnalysis(started);
      setPhase(started.state === "COMPLETED" ? "complete" : "running");
    } catch (requestError) {
      setPhase("failed");
      setError(requestError instanceof Error ? requestError.message : "The workflow could not start.");
    }
  }

  const busy = ["uploading", "starting", "running"].includes(phase);
  const action = phase === "uploading" ? "UPLOADING PCAP…" : phase === "starting" ? "STARTING ANALYSIS…" : phase === "running" ? "ANALYSIS IN PROGRESS" : mode === "pcap" ? "UPLOAD AND START" : mode === "live" ? "LIVE CAPTURE ADAPTER REQUIRED" : "DEEP ASSESSMENT ADAPTER REQUIRED";

  return (
    <div className="min-h-svh bg-black font-mono text-white">
      <div className="workspace-sidebar-shell mx-auto grid max-w-[1600px]">
        <aside className="workspace-sidebar group/sidebar relative z-20 overflow-hidden border-b border-white/15 bg-[#060910] px-5 py-6 transition-shadow duration-300 lg:sticky lg:top-0 lg:h-svh lg:w-full lg:border-b-0 lg:border-r lg:px-3 lg:py-2 lg:hover:shadow-[18px_0_46px_rgba(0,0,0,.42)]">
          <div aria-hidden="true" className="absolute inset-0 opacity-25 [background-image:linear-gradient(rgba(94,234,212,.14)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.14)_1px,transparent_1px)] [background-size:34px_34px]" />
          <div aria-hidden="true" className="absolute inset-0 bg-[radial-gradient(circle_at_20%_0,rgba(94,234,212,.18),transparent_0_18rem),linear-gradient(180deg,rgba(0,0,0,.18),rgba(0,0,0,.86))]" />
          <div className="relative z-10 flex min-h-full flex-col">
            <div className="flex items-center gap-3">
              <div className="grid h-11 w-11 shrink-0 place-items-center border border-teal-200/45 bg-teal-200/[.08] text-xs font-bold tracking-[.16em] text-teal-100 shadow-[0_0_24px_rgba(94,234,212,.12)]">IP</div>
              <div className="min-w-0 opacity-100 transition-opacity duration-300 lg:w-0 lg:overflow-hidden lg:opacity-0 lg:group-hover/sidebar:w-auto lg:group-hover/sidebar:opacity-100">
                <p className="whitespace-nowrap text-[9px] font-bold tracking-[.18em] text-teal-100/70">IPSEC SENTINEL TWIN</p>
                <p className="mt-1 whitespace-nowrap text-[9px] tracking-[.14em] text-white/35">WORKSPACE CONTROL</p>
              </div>
            </div>

            <div className="mt-4 border-y border-white/10 py-4 opacity-100 transition-opacity duration-300 lg:opacity-0 lg:group-hover/sidebar:opacity-100">
              <p className="whitespace-nowrap text-[10px] tracking-[.16em] text-white/40">WORKSPACE STATE</p>
              <div className="mt-4 grid gap-3 text-[10px]">
                <div className="flex items-center justify-between gap-4">
                  <span className="text-white/45">CORE</span>
                  <span className={health === "ready" ? "text-teal-200" : health === "checking" ? "text-amber-200" : "text-red-200"}>{health.toUpperCase()}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-white/45">MODE</span>
                  <span className="text-white/75">{mode.toUpperCase()}</span>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <span className="text-white/45">PHASE</span>
                  <span className="text-white/75">{phase.toUpperCase()}</span>
                </div>
              </div>
            </div>

            <nav className="mt-4 grid gap-2" aria-label="Workspace steps">
              {workspaceSteps.map(([number, label, detail]) => (
                <a key={label} href={label === "RESULTS" ? "#analysis-state" : "#workspace-input"} className="group block overflow-hidden border border-white/10 bg-black/30 p-3 transition-all duration-300 hover:border-teal-200/60 hover:bg-teal-200/[.055]">
                  <span className="flex min-h-8 items-center gap-3">
                    <span className="min-w-0 whitespace-nowrap text-[10px] font-bold tracking-[.12em] text-teal-100/70 transition group-hover:text-teal-100">{label}</span>
                    <span className="hidden whitespace-nowrap text-[9px] tracking-[.12em] text-white/30 opacity-0 transition-opacity duration-300 lg:inline lg:group-hover/sidebar:opacity-100">{number}</span>
                  </span>
                  <span className="block max-h-0 overflow-hidden text-[10px] leading-5 text-white/45 opacity-0 transition-all duration-300 group-hover:mt-2 group-hover:max-h-16 group-hover:text-white/65 group-hover:opacity-100">{detail}</span>
                </a>
              ))}
            </nav>

            <div className="mt-auto hidden border border-dashed border-teal-200/25 bg-teal-200/[.035] p-4 text-[10px] leading-5 text-white/48 opacity-0 transition-opacity duration-300 lg:block lg:group-hover/sidebar:opacity-100">
              <p className="font-bold tracking-[.14em] text-teal-100/75">NO PAYLOAD DECRYPTION</p>
              <p className="mt-3">Workspace actions stay limited to passive capture evidence unless Deep Assessment is explicitly authorized.</p>
            </div>
          </div>
        </aside>

        <main className="min-w-0 px-5 py-16 lg:px-8 lg:py-24">
          <div className="max-w-3xl border-l border-dashed border-white/40 pl-5">
            <p className="text-[10px] font-bold tracking-[.18em] text-white/50">OFFLINE PCAP WORKSPACE · 001</p>
            <h1 className="mt-5 text-3xl font-bold leading-tight tracking-[.06em] sm:text-5xl">START WITH THE CAPTURE.</h1>
            <p className="mt-5 max-w-2xl text-sm leading-7 text-white/65">Upload a classic PCAP to begin passive analysis. Protocol evidence, deterministic assessment, and optional metadata-only ML remain clearly separated.</p>
          </div>

          <div id="workspace-input" className="mt-14 grid scroll-mt-24 border-l border-t border-white/20 lg:grid-cols-[1.3fr_.7fr]">
            <form className="border-b border-r border-white/20 p-6 sm:p-9" onSubmit={startWorkflow}>
            <p className="text-[10px] tracking-[.16em] text-white/45">ANALYSIS MODE</p>
            <div className="mt-5 grid gap-2 sm:grid-cols-3">
              {([['pcap', 'PASSIVE PCAP', 'Upload an offline capture.'], ['live', 'PASSIVE LIVE', 'Observe an authorized interface.'], ['deep', 'DEEP ASSESSMENT', 'Verify authorized gateway facts.']] as const).map(([value, label, detail]) => <label key={value} className={`cursor-pointer border p-3 transition ${mode === value ? "border-teal-200 bg-teal-200/10" : "border-white/20 hover:border-white/55"}`}><input className="sr-only" type="radio" name="mode" value={value} checked={mode === value} onChange={() => { setMode(value); setError(undefined); }} /><span className="block text-[10px] font-bold tracking-[.1em]">{label}</span><span className="mt-2 block text-[10px] leading-4 text-white/50">{detail}</span></label>)}
            </div>
            <p className="mt-7 text-[10px] tracking-[.16em] text-white/45">SOURCE / CLASSIC PCAP OR CAP</p>
            <label className={`group relative mt-6 block cursor-pointer overflow-hidden border p-7 transition duration-300 sm:p-9 ${file ? "border-teal-200/70 bg-teal-200/[.055]" : "border-dashed border-white/35 bg-white/[.018] hover:border-teal-200/70 hover:bg-teal-200/[.04]"}`} htmlFor="pcap-upload">
              <input id="pcap-upload" className="sr-only" type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" onChange={selectFile} />
              <span aria-hidden="true" className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100 [background-image:linear-gradient(rgba(94,234,212,.11)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.11)_1px,transparent_1px)] [background-size:28px_28px]" />
              <span aria-hidden="true" className="absolute right-5 top-5 h-10 w-10 border-r border-t border-teal-200/45" />
              <span aria-hidden="true" className="absolute bottom-5 left-5 h-10 w-10 border-b border-l border-teal-200/25" />
              <span className="relative z-10 grid gap-6 sm:grid-cols-[auto_1fr] sm:items-center">
                <span className="grid h-16 w-16 place-items-center border border-teal-200/45 bg-black/50 text-sm font-bold tracking-[.16em] text-teal-100 shadow-[0_0_30px_rgba(94,234,212,.14)]">
                  PCAP
                </span>
                <span>
                  <span className="block text-lg font-bold tracking-[.08em] text-white sm:text-2xl">{file ? file.name : "SELECT A CAPTURE FILE"}</span>
                  <span className="mt-3 block max-w-xl text-xs leading-6 text-white/55">
                    {file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB selected · ready for passive evidence analysis` : "Drop in a classic packet capture or click this panel to browse. ESP payload remains sealed; only protocol metadata is analysed."}
                  </span>
                  <span className="mt-5 flex flex-wrap gap-2 text-[9px] font-bold tracking-[.12em]">
                    <span className="border border-white/15 px-2.5 py-1 text-white/45">.PCAP</span>
                    <span className="border border-white/15 px-2.5 py-1 text-white/45">.CAP</span>
                    <span className="border border-amber-200/30 px-2.5 py-1 text-amber-100/65">PCAPNG CONVERT FIRST</span>
                    <span className="border border-teal-200/30 px-2.5 py-1 text-teal-100/70">MAX 4 GIB</span>
                  </span>
                </span>
              </span>
            </label>
            <label className="mt-6 flex cursor-pointer gap-3 border-y border-white/15 py-5 text-xs text-white/65">
              <input className="mt-0.5 h-4 w-4 accent-white" type="checkbox" checked={enableMl} onChange={(event) => setEnableMl(event.target.checked)} />
              <span><b className="block text-white">ENABLE METADATA-ONLY ML</b><span className="mt-2 block leading-6">Classification is INFERRED, never protocol truth. Unavailable and low-confidence results remain visible as UNAVAILABLE or UNKNOWN.</span></span>
            </label>
            <button className="mt-7 w-full border border-white bg-white px-6 py-3 text-xs font-bold tracking-[.14em] text-black transition hover:bg-black hover:text-white disabled:cursor-not-allowed disabled:opacity-35" type="submit" disabled={!file || busy || health !== "ready" || mode !== "pcap"}>{action}</button>
            {error && <p className="mt-5 border border-red-300/60 bg-red-300/10 p-4 text-xs leading-6 text-red-100">{error}</p>}
            </form>

            <aside className="border-b border-r border-white/20 p-6 sm:p-9">
            <p className="text-[10px] tracking-[.16em] text-white/45">SYSTEM COVERAGE</p>
            <dl className="mt-6 space-y-5 text-xs">
              <div className="border-b border-white/15 pb-5"><dt className="text-white">GO SERVER</dt><dd className="mt-2 text-white/55">{health === "ready" ? "READY · browser API reachable" : health === "checking" ? "CHECKING…" : "UNAVAILABLE · start Core or set CORE_HTTP_URL"}</dd></div>
              <div className="border-b border-white/15 pb-5"><dt className="text-sky-300">OBSERVED + DERIVED</dt><dd className="mt-2 text-white/55">Packet facts and deterministic flow metadata are included in passive analysis.</dd></div>
              <div className="border-b border-white/15 pb-5"><dt className="text-amber-300">INFERRED</dt><dd className="mt-2 text-white/55">{enableMl ? "Requested when the ML worker is available." : "Not requested for this analysis."}</dd></div>
              <div><dt className="text-white/50">VERIFIED GATEWAY</dt><dd className="mt-2 text-white/55">UNAVAILABLE in Passive PCAP mode. Authorized Deep Assessment is required.</dd></div>
            </dl>
            <div className="mt-7 border border-dashed border-sky-300/35 bg-sky-300/[.04] p-4">
              <p className="text-[10px] font-bold tracking-[.14em] text-sky-200">LIVE CAPTURE CONSOLE</p>
              <div className="mt-4 flex items-center justify-between border-y border-white/10 py-3 text-[10px]"><span className="text-white/55">INTERFACE</span><span className="text-white/35">NO BROWSER ADAPTER</span></div>
              <div className="mt-3 flex items-center justify-between text-[10px]"><span className="text-white/55">PACKET RATE</span><span className="text-white/35">— PKTS/S</span></div>
              <button className="mt-5 w-full border border-white/20 px-3 py-2 text-[10px] tracking-[.12em] text-white/35" type="button" disabled>START LIVE CAPTURE</button>
              <p className="mt-3 text-[10px] leading-5 text-white/45">Live capture needs the Go Server browser adapter; the current HTTP contract intentionally does not start or stop capture.</p>
            </div>
            </aside>
          </div>

          <section id="analysis-state" className="mt-10 scroll-mt-24 border border-white/20 p-6 sm:p-9">
          <div className="flex flex-col gap-3 border-b border-white/15 pb-5 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-[10px] tracking-[.16em] text-white/45">ANALYSIS STATE</p><h2 className="mt-3 text-lg font-bold tracking-[.08em]">{analysis ? analysis.state.replaceAll("_", " ") : "AWAITING SOURCE"}</h2></div><span className="text-xs text-white/50">{analysis ? `OPERATIONAL STAGE: ${analysis.stage.replaceAll("_", " ")}` : "NO ACTIVE ANALYSIS"}</span></div>
          {upload ? <p className="mt-5 text-xs leading-6 text-white/60">SOURCE ACCEPTED: {upload.filename} · {upload.packets.toLocaleString()} packets received · {upload.esp_packets.toLocaleString()} ESP packets observed. These counters are not security conclusions.</p> : <p className="mt-5 text-xs leading-6 text-white/50">Upload a PCAP to create a workspace and begin the browser-supported workflow.</p>}
          {phase === "complete" && analysis && <Link href={`/dashboard?analysis=${encodeURIComponent(analysis.analysis_id)}`} className="mt-6 inline-block border border-white px-4 py-2 text-[10px] font-bold tracking-[.12em] transition hover:bg-white hover:text-black">OPEN LIVE RESULTS DASHBOARD</Link>}
          </section>
        </main>
      </div>
      <LandingFooter />
    </div>
  );
}
