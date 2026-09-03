"use client";

import Link from "next/link";
import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import { LandingFooter, LandingNavigation } from "@/components/ui/site-chrome";

type Health = { status?: string };
type Upload = { source_id: string; filename: string; packets: number; esp_packets: number };
type Analysis = { analysis_id: string; state: string; stage: string; failure_reason?: string };

async function coreRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/core${path}`, { ...init, cache: "no-store" });
  const body = (await response.json()) as T & { error?: string };
  if (!response.ok) throw new Error(body.error ?? "The Go Server could not complete this request.");
  return body;
}

export default function WorkspacePage() {
  const [file, setFile] = useState<File>();
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
        const next = await coreRequest<Analysis>(`/api/v1/analyses/${analysis.analysis_id}`);
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
  const action = phase === "uploading" ? "UPLOADING PCAP…" : phase === "starting" ? "STARTING ANALYSIS…" : phase === "running" ? "ANALYSIS IN PROGRESS" : "UPLOAD AND START";

  return (
    <div className="min-h-svh bg-black font-mono text-white">
      <LandingNavigation />
      <main className="mx-auto max-w-7xl px-5 py-16 lg:px-8 lg:py-24">
        <div className="max-w-3xl border-l border-dashed border-white/40 pl-5">
          <p className="text-[10px] font-bold tracking-[.18em] text-white/50">OFFLINE PCAP WORKSPACE · 001</p>
          <h1 className="mt-5 text-3xl font-bold leading-tight tracking-[.06em] sm:text-5xl">START WITH THE CAPTURE.</h1>
          <p className="mt-5 max-w-2xl text-sm leading-7 text-white/65">Upload a classic PCAP to begin passive analysis. Protocol evidence, deterministic assessment, and optional metadata-only ML remain clearly separated.</p>
        </div>

        <div className="mt-14 grid border-l border-t border-white/20 lg:grid-cols-[1.3fr_.7fr]">
          <form className="border-b border-r border-white/20 p-6 sm:p-9" onSubmit={startWorkflow}>
            <p className="text-[10px] tracking-[.16em] text-white/45">SOURCE / CLASSIC PCAP OR CAP</p>
            <label className="mt-6 block cursor-pointer border border-dashed border-white/45 p-8 transition hover:border-white hover:bg-white/[.04]" htmlFor="pcap-upload">
              <input id="pcap-upload" className="sr-only" type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" onChange={selectFile} />
              <span className="block text-sm font-bold tracking-[.08em]">{file ? file.name : "SELECT A CAPTURE FILE"}</span>
              <span className="mt-3 block text-xs leading-6 text-white/50">{file ? `${(file.size / 1024 / 1024).toFixed(2)} MiB selected` : "Classic PCAP only · maximum upload 4 GiB · PCAPNG must be converted"}</span>
            </label>
            <label className="mt-6 flex cursor-pointer gap-3 border-y border-white/15 py-5 text-xs text-white/65">
              <input className="mt-0.5 h-4 w-4 accent-white" type="checkbox" checked={enableMl} onChange={(event) => setEnableMl(event.target.checked)} />
              <span><b className="block text-white">ENABLE METADATA-ONLY ML</b><span className="mt-2 block leading-6">Classification is INFERRED, never protocol truth. Unavailable and low-confidence results remain visible as UNAVAILABLE or UNKNOWN.</span></span>
            </label>
            <button className="mt-7 w-full border border-white bg-white px-6 py-3 text-xs font-bold tracking-[.14em] text-black transition hover:bg-black hover:text-white disabled:cursor-not-allowed disabled:opacity-35" type="submit" disabled={!file || busy || health !== "ready"}>{action}</button>
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
          </aside>
        </div>

        <section className="mt-10 border border-white/20 p-6 sm:p-9">
          <div className="flex flex-col gap-3 border-b border-white/15 pb-5 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-[10px] tracking-[.16em] text-white/45">ANALYSIS STATE</p><h2 className="mt-3 text-lg font-bold tracking-[.08em]">{analysis ? analysis.state.replaceAll("_", " ") : "AWAITING SOURCE"}</h2></div><span className="text-xs text-white/50">{analysis ? `OPERATIONAL STAGE: ${analysis.stage.replaceAll("_", " ")}` : "NO ACTIVE ANALYSIS"}</span></div>
          {upload ? <p className="mt-5 text-xs leading-6 text-white/60">SOURCE ACCEPTED: {upload.filename} · {upload.packets.toLocaleString()} packets received · {upload.esp_packets.toLocaleString()} ESP packets observed. These counters are not security conclusions.</p> : <p className="mt-5 text-xs leading-6 text-white/50">Upload a PCAP to create a workspace and begin the browser-supported workflow.</p>}
          {phase === "complete" && <Link href="/" className="mt-6 inline-block border border-white px-4 py-2 text-[10px] font-bold tracking-[.12em] transition hover:bg-white hover:text-black">RETURN TO LANDING</Link>}
        </section>
      </main>
      <LandingFooter />
    </div>
  );
}
