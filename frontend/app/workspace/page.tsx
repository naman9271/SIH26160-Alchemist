"use client";

import Link from "next/link";
import { ChangeEvent, FormEvent, useEffect, useState, useRef, useCallback } from "react";
import { LandingFooter } from "@/components/ui/site-chrome";
import { saveSnapshot } from "@/components/dashboard/history-store";
import { coreURL } from "@/lib/core-url";
import { analysisPhase } from "./analysis-state";

type Health = { status?: string };
type Upload = { source_id: string; filename: string; packets: number; esp_packets: number };
type Analysis = { analysis_id: string; state: string; stage: string; failure_reason?: string };
type WorkspaceMode = "pcap" | "live" | "deep";
type CaptureInterface = { name: string; addresses: string[]; up: boolean; loopback: boolean; capture_supported: boolean };
type LiveCapture = { source_id: string; capture_id: string; state: string; interface_name: string; packets_total: number; esp_packets: number; packets_per_second?: number; active_flows: number; packet_drops: number; analysis_id?: string; analysis_state?: string; stage?: string; snapshot_version?: number; feature_stream?: { dropped_feature_windows?: number; dropped_retained_windows?: number }; gateway?: { authorized: boolean; vici_error?: string; xfrm_error?: string } };

const workspaceSteps = [
  ["01", "MODE", "Choose PCAP, live, or deep assessment."],
  ["02", "SOURCE", "Attach a classic capture file."],
  ["03", "ANALYSE", "Run evidence-first processing."],
  ["04", "RESULTS", "Open the dashboard report."],
];

async function coreRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(coreURL(path), { ...init, cache: "no-store" });
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
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [interfaceName, setInterfaceName] = useState("");
  const [deepAuthorized, setDeepAuthorized] = useState(false);
  const stopping = useRef(false);
  const [permissionPrompt, setPermissionPrompt] = useState(false);
  const [liveCapture, setLiveCapture] = useState<LiveCapture>();
  const [error, setError] = useState<string>();

  const stopCapture = useCallback(async () => {
    if (!liveCapture || stopping.current) return;
    stopping.current = true;
    try {
      const stopped = await coreRequest<LiveCapture & { analysis_id?: string; analysis_state?: string; stage?: string }>(`/api/v1/live-captures/${encodeURIComponent(liveCapture.source_id)}/stop`, { method: "POST" });
      setLiveCapture((current) => current ? { ...current, ...stopped } : current);
      if (stopped.analysis_id) {
        setAnalysis({ analysis_id: stopped.analysis_id, state: stopped.analysis_state ?? "ANALYSIS_STATE_RUNNING", stage: stopped.stage ?? "INITIALIZING" });
        setPhase("running");
      } else setPhase("complete");
    } catch (stopError) {
      setError(stopError instanceof Error ? stopError.message : "The capture could not be stopped.");
    } finally { stopping.current = false; }
  }, [liveCapture]);

  useEffect(() => {
    coreRequest<Health>("/health").then(() => setHealth("ready")).catch(() => setHealth("unavailable"));
    coreRequest<{ interfaces: CaptureInterface[] }>("/api/v1/live-capture/interfaces").then((result) => {
      const available = result.interfaces.filter((item) => item.capture_supported);
      setInterfaces(available);
      setInterfaceName(available.find(item => /^(wl|en|eth)/.test(item.name) && item.addresses.length > 0)?.name ?? available[0]?.name ?? "");
    }).catch(() => setInterfaces([]));
  }, []);

  useEffect(() => {
    if (!analysis || phase !== "running") return;
    const interval = window.setInterval(async () => {
      try {
        const next = await coreRequest<Analysis>(`/api/v1/analyses/${encodeURIComponent(analysis.analysis_id)}`);
        setAnalysis(next);
        const nextPhase = analysisPhase(next.state);
        setPhase(nextPhase);
        if (nextPhase === "complete") {
          try { saveSnapshot(next.analysis_id, await coreRequest<Record<string, unknown>>(`/api/v1/analyses/${encodeURIComponent(next.analysis_id)}/insights`)); } catch { setError("Analysis completed, but browser history could not be saved. Open the dashboard to retry."); }
        }
        if (nextPhase === "failed") {
          setError(next.failure_reason ?? "The analysis did not complete.");
        }
      } catch (pollError) {
        setPhase("failed");
        setError(pollError instanceof Error ? pollError.message : "Analysis polling failed.");
      }
    }, 1500);
    return () => window.clearInterval(interval);
  }, [analysis, phase]);

  useEffect(() => {
    if (!liveCapture || liveCapture.state !== "CAPTURING" || phase !== "running") return;
    const interval = window.setInterval(async () => {
      try {
        const next = await coreRequest<LiveCapture>(`/api/v1/live-captures/${encodeURIComponent(liveCapture.source_id)}`);
        setLiveCapture(next);
        if (next.state === "FAILED") { setPhase("failed"); setError("Capture failed. Check interface permissions and retry."); }
        if (next.state === "STOPPED") { await stopCapture(); }
      } catch (captureError) {
        setError(captureError instanceof Error ? captureError.message : "Live capture polling failed.");
      }
    }, 1500);
    return () => window.clearInterval(interval);
  }, [liveCapture, phase, stopCapture]);

  function selectFile(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0]);
    setUpload(undefined);
    setAnalysis(undefined);
    setLiveCapture(undefined);
    setError(undefined);
    setPhase("idle");
  }

  async function beginLiveCapture() {
    if (!interfaceName) { setError("Select a capture-capable network interface."); return; }
    if (mode === "deep" && !deepAuthorized) { setError("Confirm authorization before starting Deep Assessment."); return; }
    setError(undefined);
    setAnalysis(undefined);
    setPhase("starting");
    try {
      const started = await coreRequest<LiveCapture>("/api/v1/live-captures", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ interface_name: interfaceName, mode, consent: true, authorized: deepAuthorized, enable_vici: mode === "deep", enable_xfrm: mode === "deep", enable_ml: enableMl, save_pcap: true }) });
      setLiveCapture(started);
      if (started.analysis_id) setAnalysis({ analysis_id: started.analysis_id, state: started.analysis_state ?? "ANALYSIS_STATE_RUNNING", stage: started.stage ?? "ACQUIRING" });
      setPhase("running");
    } catch (requestError) {
      setPhase("failed");
      setError(requestError instanceof Error ? requestError.message : "The live capture could not start.");
    }
  }

  async function startWorkflow(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mode !== "pcap") {
      setPermissionPrompt(true);
      return;
    }
    if (!file) return;
    if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
      setError("Use a .pcap, .pcapng, or .cap capture file.");
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
      const startedPhase = analysisPhase(started.state);
      setPhase(startedPhase);
      if (startedPhase === "failed") {
        setError(started.failure_reason ?? "The analysis did not complete.");
      }
    } catch (requestError) {
      setPhase("failed");
      setError(requestError instanceof Error ? requestError.message : "The workflow could not start.");
    }
  }


  const busy = ["uploading", "starting", "running"].includes(phase);
  const action = phase === "uploading" ? "UPLOADING PCAP…" : phase === "starting" ? mode === "pcap" ? "STARTING ANALYSIS…" : "STARTING CAPTURE…" : phase === "running" ? (mode === "pcap" || analysis) ? "ANALYSIS IN PROGRESS" : "CAPTURE RUNNING" : mode === "pcap" ? "UPLOAD AND START" : mode === "live" ? "START LIVE CAPTURE" : "START DEEP ASSESSMENT";

  return (
    <div className="min-h-svh bg-[var(--landing-canvas)] font-mono text-white">
      <div className="workspace-sidebar-shell mx-auto grid max-w-[1600px]">
        <aside className="workspace-sidebar group/sidebar relative z-20 overflow-hidden border-b border-white/15 bg-[#060910] px-5 py-6 transition-shadow duration-300 lg:sticky lg:top-0 lg:h-svh lg:w-full lg:border-b-0 lg:border-r lg:px-3 lg:py-2 lg:hover:shadow-[18px_0_46px_rgba(0,0,0,.42)]">
          <div aria-hidden="true" className="absolute inset-0 opacity-25 [background-image:linear-gradient(rgba(94,234,212,.14)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.14)_1px,transparent_1px)] [background-size:34px_34px]" />
          <div aria-hidden="true" className="absolute inset-0 bg-[radial-gradient(circle_at_20%_0,rgba(94,234,212,.18),transparent_0_18rem),linear-gradient(180deg,rgba(0,0,0,.18),rgba(0,0,0,.86))]" />
          <div className="relative z-10 flex min-h-full flex-col">
            <div className="border-y border-white/10 py-4 opacity-100 transition-opacity duration-300 lg:opacity-0 lg:group-hover/sidebar:opacity-100">
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
            <p className="text-[10px] font-bold tracking-[.18em] text-white/50">CAPTURE WORKSPACE</p>
            <h1 className="mt-5 text-3xl font-bold leading-tight tracking-[.06em] sm:text-5xl">START WITH THE CAPTURE.</h1>
            <p className="mt-5 max-w-2xl text-sm leading-7 text-white/65">Upload a PCAP or PCAPNG to begin passive analysis. Protocol evidence, deterministic assessment, and optional metadata-only ML remain clearly separated.</p>
          </div>

          <div id="workspace-input" className="mt-14 grid scroll-mt-24 border-l border-t border-white/20 lg:grid-cols-[1.3fr_.7fr]">
            <form className="border-b border-r border-white/20 p-6 sm:p-9" onSubmit={startWorkflow}>
            <p className="text-[10px] tracking-[.16em] text-white/45">ANALYSIS MODE</p>
            <div className="mt-5 grid gap-2 sm:grid-cols-3">
              {([['pcap', 'PASSIVE PCAP', 'Upload an offline capture.'], ['live', 'PASSIVE LIVE', 'Observe an authorized interface.'], ['deep', 'DEEP ASSESSMENT', 'Verify authorized gateway facts.']] as const).map(([value, label, detail]) => <label key={value} className={`cursor-pointer border p-3 transition ${mode === value ? "border-teal-200 bg-teal-200/10" : "border-white/20 hover:border-white/55"}`}><input className="sr-only" disabled={busy} type="radio" name="mode" value={value} checked={mode === value} onChange={() => { setMode(value); setAnalysis(undefined); setUpload(undefined); setLiveCapture(undefined); setPhase("idle"); setError(undefined); }} /><span className="block text-[10px] font-bold tracking-[.1em]">{label}</span><span className="mt-2 block text-[10px] leading-4 text-white/50">{detail}</span></label>)}
            </div>
            {mode === "pcap" ? <>
            <p className="mt-7 text-[10px] tracking-[.16em] text-white/45">SOURCE / PCAP, PCAPNG, OR CAP</p>
            <label className={`group relative mt-6 block cursor-pointer overflow-hidden border p-7 transition duration-300 sm:p-9 ${file ? "border-teal-200/70 bg-teal-200/[.055]" : "border-dashed border-white/35 bg-white/[.018] hover:border-teal-200/70 hover:bg-teal-200/[.04]"}`} htmlFor="pcap-upload">
              <input id="pcap-upload" className="sr-only" type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/x-pcapng" onChange={selectFile} />
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
                    {file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB selected · ready for passive evidence analysis` : "Drop in a packet capture or click this panel to browse. ESP payload remains sealed; only protocol metadata is analysed."}
                  </span>
                  <span className="mt-5 flex flex-wrap gap-2 text-[9px] font-bold tracking-[.12em]">
                    <span className="border border-white/15 px-2.5 py-1 text-white/45">.PCAP</span>
                    <span className="border border-white/15 px-2.5 py-1 text-white/45">.CAP</span>
                    <span className="border border-teal-200/30 px-2.5 py-1 text-teal-100/70">.PCAPNG</span>
                    <span className="border border-teal-200/30 px-2.5 py-1 text-teal-100/70">MAX 4 GIB</span>
                  </span>
                </span>
              </span>
            </label>
            <label className="mt-6 flex cursor-pointer gap-3 border-y border-white/15 py-5 text-xs text-white/65">
              <input className="mt-0.5 h-4 w-4 accent-white" type="checkbox" checked={enableMl} onChange={(event) => setEnableMl(event.target.checked)} />
              <span><b className="block text-white">ENABLE METADATA-ONLY ML</b><span className="mt-2 block leading-6">Classification is INFERRED, never protocol truth. Unavailable and low-confidence results remain visible as UNAVAILABLE or UNKNOWN.</span></span>
            </label>
            </> : <div className="mt-7 border-y border-white/15 py-5">
              <label className="block text-[10px] tracking-[.16em] text-white/45">CAPTURE INTERFACE
                <select value={interfaceName} onChange={(event) => setInterfaceName(event.target.value)} className="mt-3 block w-full border border-teal-200/30 bg-black px-3 py-3 text-xs text-white outline-none focus:border-teal-200" disabled={busy}>
                  {interfaces.length === 0 ? <option value="">NO CAPTURE-CAPABLE INTERFACE FOUND</option> : interfaces.map((item) => <option key={item.name} value={item.name}>{item.name}{item.addresses.length ? ` · ${item.addresses[0]}` : ""}</option>)}
                </select>
              </label>
              {mode === "deep" && <label className="mt-5 flex cursor-pointer gap-3 text-xs leading-6 text-white/65"><input className="mt-1 h-4 w-4 accent-teal-200" type="checkbox" checked={deepAuthorized} onChange={(event) => setDeepAuthorized(event.target.checked)} /><span><b className="block text-teal-100">I AM AUTHORIZED TO ASSESS THIS GATEWAY</b>Read-only VICI/XFRM gateway telemetry will be requested. This never decrypts traffic or changes gateway configuration.</span></label>}
              <p className="mt-4 text-[10px] leading-5 text-white/45">The capture uses the fixed IPsec metadata filter: IKE, NAT-T, ESP, and AH. Capture stops automatically after 5 minutes or 64 MiB.</p>
            </div>}
            <button className="mt-7 w-full border border-white bg-white px-6 py-3 text-xs font-bold tracking-[.14em] text-black transition hover:bg-black hover:text-white disabled:cursor-not-allowed disabled:opacity-35" type="submit" disabled={busy || health !== "ready" || (mode === "pcap" ? !file : !interfaceName) || (mode === "deep" && !deepAuthorized)}>{action}</button>
            {error && <p className="mt-5 border border-red-300/60 bg-red-300/10 p-4 text-xs leading-6 text-red-100">{error}</p>}
            </form>

            <aside className="border-b border-r border-white/20 p-6 sm:p-9">
            <p className="text-[10px] tracking-[.16em] text-white/45">SYSTEM COVERAGE</p>
            <dl className="mt-6 space-y-5 text-xs">
              <div className="border-b border-white/15 pb-5"><dt className="text-white">GO SERVER</dt><dd className="mt-2 text-white/55">{health === "ready" ? "READY · browser API reachable" : health === "checking" ? "CHECKING…" : "UNAVAILABLE · start Core or set CORE_HTTP_URL"}</dd></div>
              <div className="border-b border-white/15 pb-5"><dt className="text-sky-300">OBSERVED + DERIVED</dt><dd className="mt-2 text-white/55">Packet facts and deterministic flow metadata are included in passive analysis.</dd></div>
              <div className="border-b border-white/15 pb-5"><dt className="text-amber-300">INFERRED</dt><dd className="mt-2 text-white/55">{enableMl ? "Requested when the ML worker is available." : "Not requested for this analysis."}</dd></div>
              <div><dt className="text-white/50">VERIFIED GATEWAY</dt><dd className="mt-2 text-white/55">{liveCapture?.gateway?.authorized ? "AUTHORIZED · read-only gateway telemetry requested" : "UNAVAILABLE in Passive PCAP mode. Authorized Deep Assessment is required."}</dd></div>
            </dl>
            <div className="mt-7 border border-dashed border-sky-300/35 bg-sky-300/[.04] p-4">
              <div className="flex items-center justify-between gap-3"><p className="text-[10px] font-bold tracking-[.14em] text-sky-200">LIVE CAPTURE CONSOLE</p>{(phase === "starting" || liveCapture?.state === "CAPTURING") && <span className="relative flex h-6 w-12 items-center justify-center" aria-label="Capture active"><i className="absolute h-5 w-5 animate-ping rounded-full border border-teal-200/70" /><i className="absolute h-3 w-3 animate-spin rounded-full border-2 border-teal-200 border-t-transparent" /><i className="absolute h-1.5 w-1.5 rounded-full bg-teal-100 shadow-[0_0_12px_3px_rgba(94,234,212,.65)]" /></span>}</div>
              <div className="mt-4 flex items-center justify-between border-y border-white/10 py-3 text-[10px]"><span className="text-white/55">INTERFACE</span><span className={liveCapture ? "text-teal-100" : "text-white/35"}>{liveCapture?.interface_name ?? "NOT STARTED"}</span></div>
              <div className="mt-3 flex items-center justify-between text-[10px]"><span className="text-white/55">PACKETS / RATE</span><span className={liveCapture ? "text-teal-100" : "text-white/35"}>{liveCapture ? `${liveCapture.packets_total.toLocaleString()} · ${(liveCapture.packets_per_second ?? 0).toFixed(1)} PKTS/S` : "— PKTS/S"}</span></div>
              <div className="mt-3 flex items-center justify-between text-[10px]"><span className="text-white/55">ESP / FLOWS</span><span className={liveCapture ? "text-teal-100" : "text-white/35"}>{liveCapture ? `${liveCapture.esp_packets.toLocaleString()} · ${liveCapture.active_flows}` : "—"}</span></div>
              <div className="mt-3 flex items-center justify-between text-[10px]"><span className="text-white/55">CAPTURE / WINDOW DROPS</span><span className={liveCapture ? "text-teal-100" : "text-white/35"}>{liveCapture ? `${liveCapture.packet_drops} · ${(liveCapture.feature_stream?.dropped_feature_windows ?? 0) + (liveCapture.feature_stream?.dropped_retained_windows ?? 0)}` : "—"}</span></div>
              {liveCapture?.state === "CAPTURING" ? <button className="mt-5 w-full border border-red-200/60 px-3 py-2 text-[10px] tracking-[.12em] text-red-100 transition hover:bg-red-300/10" type="button" onClick={() => void stopCapture()}>STOP & ANALYSE</button> : <p className="mt-5 border border-teal-200/20 px-3 py-2 text-[10px] leading-5 text-white/50">Select PASSIVE LIVE or DEEP ASSESSMENT, choose an interface, then start the capture.</p>}
              {liveCapture?.state === "CAPTURING" && analysis && <Link href={`/dashboard?analysis=${encodeURIComponent(analysis.analysis_id)}`} className="mt-3 block border border-teal-200/45 px-3 py-2 text-center text-[10px] tracking-[.12em] text-teal-100 transition hover:bg-teal-200/10">OPEN LIVE RESULTS · SNAPSHOT {liveCapture.snapshot_version ?? 0}</Link>}
              {liveCapture?.gateway && <p className="mt-3 text-[10px] leading-5 text-white/45">{liveCapture.gateway.vici_error ? `VICI: ${liveCapture.gateway.vici_error}` : "VICI telemetry available when configured."}{liveCapture.gateway.xfrm_error ? ` XFRM: ${liveCapture.gateway.xfrm_error}` : ""}</p>}
            </div>
            </aside>
          </div>

          <section id="analysis-state" className="mt-10 scroll-mt-24 border border-white/20 p-6 sm:p-9">
          <div className="flex flex-col gap-3 border-b border-white/15 pb-5 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-[10px] tracking-[.16em] text-white/45">{liveCapture ? "LIVE CAPTURE STATE" : "ANALYSIS STATE"}</p><h2 className="mt-3 text-lg font-bold tracking-[.08em]">{liveCapture ? liveCapture.state : analysis ? analysis.state.replaceAll("_", " ") : "AWAITING SOURCE"}</h2></div><span className="text-xs text-white/50">{liveCapture ? `${liveCapture.interface_name} · ${liveCapture.packet_drops} DROPS` : analysis ? `OPERATIONAL STAGE: ${analysis.stage.replaceAll("_", " ")}` : "NO ACTIVE ANALYSIS"}</span></div>
          {liveCapture ? <p className="mt-5 text-xs leading-6 text-white/60">{liveCapture.state === "CAPTURING" ? "CAPTURING IPSEC TRAFFIC." : analysis ? `ANALYSIS: ${analysis.state.replace("ANALYSIS_STATE_", "")}.` : "CAPTURE STOPPED."} Only IPsec packet metadata is observed; ESP payloads are never decrypted. Stop the capture when collection is complete.</p> : upload ? <p className="mt-5 text-xs leading-6 text-white/60">SOURCE ACCEPTED: {upload.filename} · {upload.packets.toLocaleString()} packets received · {upload.esp_packets.toLocaleString()} ESP packets observed. These counters are not security conclusions.</p> : <p className="mt-5 text-xs leading-6 text-white/50">Upload a PCAP or select a live capture mode to begin.</p>}
          {phase === "complete" && analysis && <Link href={`/dashboard?analysis=${encodeURIComponent(analysis.analysis_id)}`} className="group relative mt-6 inline-flex overflow-hidden border border-white/70 bg-white/10 px-6 py-3 text-[10px] font-bold tracking-[.12em] text-white shadow-[0_0_28px_rgba(255,255,255,.12)] transition-all duration-300 hover:border-teal-200 hover:bg-teal-200/15 hover:text-teal-100 hover:shadow-[0_0_38px_rgba(94,234,212,.28)] focus-visible:border-teal-200 focus-visible:bg-teal-200/15 focus-visible:text-teal-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-100/70"><span aria-hidden="true" className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-teal-100/25 to-transparent transition-transform duration-700 group-hover:translate-x-full" /><span aria-hidden="true" className="absolute -left-1 -top-1 hidden h-3 w-3 border-l border-t border-white/70 group-hover:border-teal-100 lg:block" /><span aria-hidden="true" className="absolute -bottom-1 -right-1 hidden h-3 w-3 border-b border-r border-white/70 group-hover:border-teal-100 lg:block" /><span className="relative">OPEN LIVE RESULTS DASHBOARD</span></Link>}
          </section>
        </main>
      </div>
      {permissionPrompt && <div className="fixed inset-0 z-50 grid place-items-center bg-black/75 p-5 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="capture-permission-title"><div className="w-full max-w-lg border border-teal-200/35 bg-[#070b10] p-6 shadow-[0_0_50px_rgba(94,234,212,.14)]"><p className="text-[10px] font-bold tracking-[.16em] text-teal-200">CAPTURE PERMISSION REQUIRED</p><h2 id="capture-permission-title" className="mt-4 text-xl font-bold tracking-[.06em]">ALLOW PASSIVE {mode === "deep" ? "DEEP ASSESSMENT" : "LIVE CAPTURE"}?</h2><p className="mt-4 text-sm leading-7 text-white/65">This will ask the Core service to capture IPsec packet metadata from <b className="text-white">{interfaceName}</b>. ESP payloads are never decrypted. {mode === "deep" ? "Read-only VICI/XFRM gateway telemetry will also be requested; no gateway configuration is changed." : ""}</p><div className="mt-6 flex flex-wrap justify-end gap-3"><button type="button" className="border border-white/25 px-4 py-2 text-[10px] font-bold tracking-[.12em] text-white/70" onClick={() => setPermissionPrompt(false)}>CANCEL</button><button type="button" className="border border-teal-200 bg-teal-200 px-4 py-2 text-[10px] font-bold tracking-[.12em] text-slate-950" onClick={() => { setPermissionPrompt(false); void beginLiveCapture(); }}>ALLOW & START</button></div></div></div>}
      <LandingFooter />
    </div>
  );
}
