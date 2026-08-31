"use client";

import { ChangeEvent, useCallback, useEffect, useState } from "react";

type Health = { live: boolean; ready: boolean; status: string; dependencies: Record<string, string> };
type Upload = { source_id: string; filename: string; packets: number; bytes: number; ike_packets: number; esp_packets: number; ah_packets: number; nat_t_packets: number };
type Analysis = { analysis_id: string; state: string; stage: string; failure_reason?: string; progress?: { percent?: number; evidence_count?: string; packets_processed?: string; flows_processed?: string; sas_found?: string; findings_generated?: string }; summary?: { ipsec_detected?: boolean; protocols?: string[]; traffic_classes?: string[]; flow_count?: string; session_count?: string; sa_count?: string; evidence_count?: string; packet_count?: string; byte_count?: string; protocol?: { ike_version?: string; data_protocol?: string; vpn_mode?: string }; security?: { score?: number; risk_level?: string; state?: number } } };
type Report = { report_id: string; state: string; failure_reason?: string; download_url: string };

async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/core${url}`, { ...init, cache: "no-store" });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? "Request failed");
  return payload as T;
}

function bytes(value?: number | string) { const numeric = Number(value ?? 0); if (!numeric) return "0 B"; const units = ["B", "KB", "MB", "GB"]; const index = Math.min(Math.floor(Math.log(numeric) / Math.log(1024)), units.length - 1); return `${(numeric / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`; }
function value(v?: number | string) { return Number(v ?? 0).toLocaleString(); }

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [upload, setUpload] = useState<Upload | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("Choose a classic PCAP file to begin.");

  const refreshHealth = useCallback(async () => { try { setHealth(await (await fetch("/api/backend-status", { cache: "no-store" })).json()); } catch { setHealth(null); } }, []);
  const refreshAnalysis = useCallback(async (id: string) => { try { setAnalysis(await api<Analysis>(`/v1/analyses/${id}`)); } catch (error) { setMessage(error instanceof Error ? error.message : "Could not read analysis status."); } }, []);
  useEffect(() => { const initial = window.setTimeout(() => void refreshHealth(), 0); const timer = window.setInterval(() => void refreshHealth(), 5000); return () => { window.clearTimeout(initial); window.clearInterval(timer); }; }, [refreshHealth]);
  useEffect(() => { if (!analysis || !["ANALYSIS_STATE_RUNNING", "ANALYSIS_STATE_QUEUED"].includes(analysis.state)) return; const timer = window.setInterval(() => void refreshAnalysis(analysis.analysis_id), 1500); return () => window.clearInterval(timer); }, [analysis, refreshAnalysis]);
  useEffect(() => { if (!report || report.state !== "GENERATING") return; const timer = window.setInterval(async () => { try { setReport(await api<Report>(`/v1/reports/${report.report_id}`)); } catch { /* the displayed report state remains useful */ } }, 1200); return () => window.clearInterval(timer); }, [report]);

  async function uploadPCAP() {
    if (!file) return;
    setBusy(true); setMessage("Uploading and validating PCAP…"); setAnalysis(null); setReport(null);
    try { const form = new FormData(); form.set("pcap", file); const source = await api<Upload>("/v1/pcap", { method: "POST", body: form }); setUpload(source); setMessage(`Validated ${source.filename}. Start analysis when ready.`); } catch (error) { setMessage(error instanceof Error ? error.message : "PCAP upload failed."); } finally { setBusy(false); }
  }
  async function start() {
    if (!upload) return;
    setBusy(true); setMessage("Starting passive PCAP analysis…");
    try { const created = await api<{ analysis_id: string }>("/v1/analyses", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ source_id: upload.source_id, enable_ml: false }) }); await refreshAnalysis(created.analysis_id); setMessage("Analysis is running. Results update automatically."); } catch (error) { setMessage(error instanceof Error ? error.message : "Analysis could not start."); } finally { setBusy(false); }
  }
  async function createReport() {
    if (!analysis) return;
    setBusy(true); setMessage("Generating executive PDF report…");
    try { setReport(await api<Report>(`/v1/analyses/${analysis.analysis_id}/report`, { method: "POST" })); } catch (error) { setMessage(error instanceof Error ? error.message : "Report generation failed."); } finally { setBusy(false); }
  }
  const complete = analysis?.state === "ANALYSIS_STATE_COMPLETED";
  const summary = analysis?.summary;
  return <main className="monitor-shell">
    <header className="monitor-header"><div><p className="eyebrow">SIH 26160 · Team Alchemist</p><h1>IPsec PCAP Analyzer</h1><p className="subtitle">Upload a capture, run passive analysis, and inspect the real Fusion and security results.</p></div><span className={`status-pill ${health?.live ? "good" : "bad"}`}>Core {health?.live ? health.status : "offline"}</span></header>
    <section className="panel workflow-panel"><div className="section-heading"><div><h2>1. Upload classic PCAP</h2><p>Packets are processed locally by the Go Core; ESP is never decrypted.</p></div></div><div className="upload-row"><label className="file-picker"><input type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" onChange={(event: ChangeEvent<HTMLInputElement>) => setFile(event.target.files?.[0] ?? null)} />{file ? file.name : "Choose PCAP file"}</label><button className="refresh-button" disabled={!file || busy} onClick={() => void uploadPCAP()}>{busy ? "Working…" : "Upload & validate"}</button></div>{upload && <div className="metric-strip"><Metric label="Packets" value={value(upload.packets)} /><Metric label="Size" value={bytes(upload.bytes)} /><Metric label="IKE" value={value(upload.ike_packets)} /><Metric label="ESP" value={value(upload.esp_packets)} /></div>}</section>
    <section className="panel workflow-panel"><div className="section-heading"><div><h2>2. Run analysis</h2><p>Passive evidence, Fusion conclusions, security/risk, and report rendering run in the existing Go pipeline.</p></div><button className="refresh-button" disabled={!upload || busy || Boolean(analysis)} onClick={() => void start()}>Start analysis</button></div>{analysis ? <><div className="analysis-state"><span className={`status-pill ${complete ? "good" : analysis.state.includes("FAILED") ? "bad" : "warn"}`}>{analysis.state.replace("ANALYSIS_STATE_", "")}</span><strong>{analysis.stage.replaceAll("_", " ")}</strong><span>{analysis.failure_reason || message}</span></div><div className="progress-track"><div style={{ width: `${analysis.progress?.percent ?? (complete ? 100 : 12)}%` }} /></div><div className="metric-strip"><Metric label="Packets" value={value(analysis.progress?.packets_processed)} /><Metric label="Flows" value={value(analysis.progress?.flows_processed)} /><Metric label="Evidence" value={value(analysis.progress?.evidence_count)} /><Metric label="Findings" value={value(analysis.progress?.findings_generated)} /></div></> : <p className="empty-state">Upload a valid PCAP to enable analysis.</p>}</section>
    {summary && <section className="results-grid"><article className="panel result-card"><h2>Protocol & IPsec</h2><Result label="IPsec detected" value={summary.ipsec_detected ? "Yes" : "No"} /><Result label="Protocols" value={summary.protocols?.join(", ") || "None observed"} /><Result label="IKE version" value={summary.protocol?.ike_version || "Unknown"} /><Result label="Data protocol" value={summary.protocol?.data_protocol || "Unknown"} /><Result label="VPN mode" value={summary.protocol?.vpn_mode || "Unknown"} /></article><article className="panel result-card"><h2>Fusion & security</h2><Result label="Evidence" value={value(summary.evidence_count)} /><Result label="Flows / SAs" value={`${value(summary.flow_count)} / ${value(summary.sa_count)}`} /><Result label="Risk score" value={summary.security?.state === 1 ? `${summary.security.score}/100` : "Not available"} /><Result label="Risk level" value={summary.security?.risk_level || "Unknown"} /></article></section>}
    <section className="panel workflow-panel"><div className="section-heading"><div><h2>3. Executive report</h2><p>Generate a downloadable PDF from the completed analysis.</p></div>{complete && !report && <button className="refresh-button" disabled={busy} onClick={() => void createReport()}>Generate PDF</button>}</div>{report ? <div className="analysis-state"><span className={`status-pill ${report.state === "READY" ? "good" : report.state === "FAILED" ? "bad" : "warn"}`}>{report.state}</span>{report.state === "READY" ? <a className="download-link" href={`/api/core${report.download_url}`}>Download report</a> : <span>{report.failure_reason || "Rendering report…"}</span>}</div> : <p className="empty-state">A PDF report becomes available after analysis completes.</p>}</section>
    <p className="notice">{message}</p>
  </main>;
}

function Metric({ label, value: content }: { label: string; value: string }) { return <div><span>{label}</span><strong>{content}</strong></div>; }
function Result({ label, value: content }: { label: string; value: string }) { return <p className="result-line"><span>{label}</span><strong>{content}</strong></p>; }
