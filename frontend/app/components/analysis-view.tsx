"use client";
/* The Core insight payload intentionally supports independently unavailable sections. */
/* eslint-disable @typescript-eslint/no-explicit-any, react-hooks/set-state-in-effect */

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

type View = "overview" | "protocol" | "intelligence" | "security" | "evidence" | "reports";
type Insight = Record<string, any>;

const api = async <T,>(url: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(`/api/core${url}`, { ...init, cache: "no-store" });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error ?? "Request failed");
  return payload as T;
};

const get = (value: any, ...keys: string[]): any => keys.reduce<any>((found, key) => found ?? value?.[key], undefined);
const list = (value: any) => Array.isArray(value) ? value : [];
const number = (value: any) => Number(value ?? 0).toLocaleString();
const status = (value: any) => String(value ?? "UNKNOWN").replaceAll("_", " ");
const title = (value: string) => value.replaceAll("_", " ").replace(/\b\w/g, letter => letter.toUpperCase());

export function AnalysisView({ analysisId, view }: { analysisId: string; view: View }) {
  const [insight, setInsight] = useState<Insight | null>(null);
  const [error, setError] = useState("");
  const [report, setReport] = useState<any>(null);
  const refresh = useCallback(async () => {
    try { setInsight(await api<Insight>(`/v1/analyses/${analysisId}/insights`)); setError(""); }
    catch (err) { setError(err instanceof Error ? err.message : "Unable to load analysis."); }
  }, [analysisId]);
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 3000); return () => window.clearInterval(timer); }, [refresh]);
  useEffect(() => { if (!report || report.state !== "GENERATING") return; const timer = window.setInterval(async () => { try { setReport(await api(`/v1/reports/${report.report_id}`)); } catch {} }, 1200); return () => window.clearInterval(timer); }, [report]);
  const makeReport = async () => { try { setReport(await api(`/v1/analyses/${analysisId}/report`, { method: "POST" })); } catch (err) { setError(err instanceof Error ? err.message : "Report generation failed."); } };

  if (!insight) return <main className="view-main"><PageHeading eyebrow="Analysis workspace" title="Opening the evidence ledger" description="Retrieving the current protocol, risk, and intelligence views." /><div className="loading-grid"><span /><span /><span /></div>{error && <ErrorBox message={error} />}</main>;

  const analysis = insight.analysis ?? {};
  const summary = insight.summary ?? {};
  const progress = insight.progress ?? {};
  const protocol = insight.protocol ?? {};
  const security = insight.security ?? {};
  const assessment = security.assessment ?? {};
  const fusion = insight.fusion ?? {};
  const ml = insight.ml ?? {};
  const page = { overview: <Overview summary={summary} progress={progress} protocol={protocol} assessment={assessment} fusion={fusion} ml={ml} />, protocol: <Protocol protocol={protocol} />, intelligence: <Intelligence ml={ml} fusion={fusion} />, security: <Security security={security} />, evidence: <Evidence protocol={protocol} fusion={fusion} />, reports: <Reports report={report} onGenerate={makeReport} /> }[view];

  return <main className="view-main">
    <div className="analysis-topline"><Link href="/workspace">← New analysis</Link><span>Analysis {analysisId.slice(0, 8)}</span><button className="quiet-button" onClick={() => void refresh()}>Refresh</button></div>
    <PageHeading eyebrow={status(analysis.stage)} title={view === "overview" ? "Analysis ledger" : title(view)} description={analysis.failure_reason || "Evidence is retained with its source, confidence, and availability state."} />
    <div className="analysis-status"><span className={`status-dot ${String(analysis.state).includes("COMPLETED") ? "good" : String(analysis.state).includes("FAILED") ? "bad" : "warn"}`} /><strong>{status(analysis.state)}</strong><span>{number(progress.packets_processed)} packets observed</span><span>{number(progress.evidence_count)} evidence items</span><span>{number(progress.findings_generated)} findings</span></div>
    {error && <ErrorBox message={error} />}
    {page}
  </main>;
}

function Overview({ summary, progress, protocol, assessment, fusion, ml }: any) {
  const findings = list(assessment.findings);
  return <>
    <section className="metric-grid">
      <Metric label="Security posture" value={assessment.score !== undefined ? `${assessment.score}/100` : "—"} note={get(summary, "security")?.risk_level ?? "Awaiting assessment"} tone={assessment.score >= 80 ? "good" : "warn"} />
      <Metric label="Protocol" value={get(protocol, "summary")?.data_protocol ?? get(summary, "protocol")?.data_protocol ?? "—"} note={get(protocol, "summary")?.ike_version ?? "No IKE evidence"} />
      <Metric label="Traffic inference" value={list(ml.predictions).length ? "Ready" : "—"} note={get(summary, "ml_result") ?? "ML not requested or unavailable"} />
      <Metric label="Fusion confidence" value={get(fusion, "summary")?.conclusion_count ?? "0"} note={`${get(fusion, "summary")?.unresolved_conflicts ?? 0} unresolved conflicts`} />
    </section>
    <section className="two-column">
      <article className="surface-panel feature-panel"><div className="panel-kicker">What we observed</div><h2>IPsec is {get(protocol, "summary")?.ipsec_detected ? "present" : "not confirmed"}</h2><p>Protocol facts stay separate from inference. Missing gateway or encrypted-IKE data is intentionally shown as unavailable.</p><div className="key-lines"><Line label="IKE version" value={get(protocol, "summary")?.ike_version ?? "Unknown"} /><Line label="VPN mode" value={get(protocol, "summary")?.vpn_mode ?? "Unknown"} /><Line label="NAT traversal" value={get(protocol, "nat_traversal")?.observed ? "Observed" : "Not observed"} /></div><Link className="inline-link" href={`./${"protocol"}`}>Inspect protocol evidence →</Link></article>
      <article className="surface-panel feature-panel finding-preview"><div className="panel-kicker">Priority queue</div><h2>{findings.length ? `${findings.length} actionable finding${findings.length === 1 ? "" : "s"}` : "No completed findings yet"}</h2>{findings.slice(0, 3).map((finding: any) => <div className="finding-line" key={finding.RuleID ?? finding.rule_id}><span className={`severity ${String(finding.Severity ?? finding.severity).toLowerCase()}`}>{finding.Severity ?? finding.severity}</span><div><strong>{finding.Title ?? finding.title}</strong><small>{finding.Recommendation ?? finding.recommendation}</small></div></div>)}<Link className="inline-link" href={`./${"security"}`}>Open remediation view →</Link></article>
    </section>
    <section className="surface-panel timeline-panel"><div className="panel-header"><div><div className="panel-kicker">Processing trace</div><h2>Analysis progress</h2></div><span>{number(progress.flows_processed)} flows processed</span></div><div className="stage-track">{["Protocol", "Features", "ML", "Fusion", "Security"].map((stage, index) => <div key={stage} className={index < 4 || String(progress.stage).includes("COMPLETED") ? "done" : ""}><b>{index + 1}</b><span>{stage}</span></div>)}</div></section>
  </>;
}

function Protocol({ protocol }: any) {
  const crypto = list(protocol.crypto_properties); const sas = list(protocol.security_associations); const ike = list(protocol.ike_exchanges);
  return <>
    <section className="metric-grid"><Metric label="IKE" value={protocol.summary?.ike_version ?? "Unknown"} note={`confidence ${Math.round(Number(protocol.summary?.confidence ?? 0) * 100)}%`} /><Metric label="Data plane" value={protocol.summary?.data_protocol ?? "Unknown"} note={protocol.summary?.vpn_mode ?? "Mode unavailable"} /><Metric label="Security associations" value={String(sas.length)} note="Observed or gateway verified" /><Metric label="NAT-T packets" value={number(protocol.nat_traversal?.nat_t_packets)} note={protocol.nat_traversal?.observed ? "Observed" : "Not observed"} /></section>
    <section className="two-column"><DataPanel title="Cryptographic properties" caption="Only clear-text IKE or verified gateway/kernel values are shown." rows={crypto.map((row: any) => [row.name, row.value, row.source])} empty="No crypto properties are available for this capture." /><DataPanel title="Security associations" caption="SPI values remain protocol evidence; they are not ML inputs." rows={sas.map((row: any) => [row.security_association_id, row.protocol || "—", row.spi_values?.join(", ") || "—"])} empty="No security associations were reconstructed." /></section>
    <section className="surface-panel table-panel"><div className="panel-header"><div><div className="panel-kicker">Negotiation record</div><h2>IKE exchanges</h2></div><span>{ike.length} records</span></div><Table headings={["Exchange", "IKE", "Initiator SPI", "Responder SPI"]} rows={ike.map((row: any) => [row.exchange_id, row.ike_version || "—", row.initiator_spi || "—", row.responder_spi || "—"])} empty="No IKE exchange was available in this PCAP." /></section>
  </>;
}

function Intelligence({ ml, fusion }: any) {
  const predictions = list(ml.predictions); const explanations = ml.explanations ?? {}; const conclusions = list(fusion.conclusions);
  return <>
    <section className="two-column"><article className="surface-panel feature-panel"><div className="panel-kicker">ML worker</div><h2>{ml.worker?.available ? "Model connected" : "Model unavailable"}</h2><p>{ml.worker?.status_message ?? "The ML worker has not been queried."}</p><div className="key-lines"><Line label="Model version" value={ml.worker?.model_version ?? "—"} /><Line label="Round trip" value={ml.worker?.latency_ms ? `${Number(ml.worker.latency_ms).toFixed(1)} ms` : "—"} /><Line label="Predictions" value={String(predictions.length)} /></div></article><article className="surface-panel feature-panel"><div className="panel-kicker">Fusion engine</div><h2>{fusion.summary?.state ?? "Awaiting fusion"}</h2><p>Fusion preserves source provenance, records conflicts, and selects conclusions by policy rather than hiding disagreement.</p><div className="key-lines"><Line label="Evidence" value={number(fusion.summary?.evidence_count)} /><Line label="Conclusions" value={number(fusion.summary?.conclusion_count)} /><Line label="Conflicts" value={number(fusion.summary?.unresolved_conflicts)} /></div></article></section>
    <section className="surface-panel table-panel"><div className="panel-header"><div><div className="panel-kicker">Flow classification</div><h2>Metadata-only traffic inference</h2></div><span>{predictions.length} eligible flows</span></div><Table headings={["Flow", "Class", "Confidence", "Decision"]} rows={predictions.map((row: any) => [String(row.flow_id).slice(0, 13), row.traffic_class, `${Math.round(Number(row.confidence ?? 0) * 100)}%`, row.is_unknown ? "UNKNOWN / abstained" : "Classified"])} empty="No eligible ML feature window was available." /></section>
    <section className="two-column"><DataPanel title="Top feature explanations" caption="Returned only when explanations were requested and permitted by the worker." rows={Object.values(explanations).flatMap((item: any) => list(item.features).slice(0, 3).map((feature: any) => [feature.feature_name, Number(feature.attribution ?? 0).toFixed(3), `value ${Number(feature.value ?? 0).toFixed(2)}`]))} empty="No SHAP explanation was returned for this run." /><DataPanel title="Fused conclusions" caption="Winning sources and confidence remain inspectable." rows={conclusions.slice(0, 10).map((row: any) => [row.property_key, row.value, `${Math.round(Number(row.confidence ?? 0) * 100)}% · ${list(row.winning_sources).join(", ")}`])} empty="Fusion has not produced conclusions yet." /></section>
  </>;
}

function Security({ security }: any) {
  const assessment = security.assessment ?? {}; const breakdown = security.risk_breakdown ?? {}; const findings = list(assessment.findings); const recommendations = list(assessment.recommendations);
  const categories = ["cryptography", "authentication", "key_exchange", "pfs", "replay", "lifecycle", "metadata"];
  return <>
    <section className="security-hero surface-panel"><div><div className="panel-kicker">Deterministic assessment</div><h2>{assessment.score ?? "—"}<small>/100</small></h2><p>{security.risk_score?.risk_level ?? "Risk pending"} risk · grade {assessment.grade ?? "—"} · confidence {Math.round(Number(security.risk_score?.confidence ?? 0) * 100)}%</p></div><div className="metadata-card"><span>Metadata exposure</span><strong>{assessment.metadata_exposure ? "Observable" : "Unavailable"}</strong><small>Outer endpoints, timing, direction, and volume are never encrypted by ESP.</small></div></section>
    <section className="surface-panel breakdown-panel"><div className="panel-header"><div><div className="panel-kicker">Risk ledger</div><h2>Posture by category</h2></div><span>{assessment.unknown_evidence_count ?? 0} unknown evidence items</span></div>{categories.map(category => { const row = breakdown[category] ?? {}; const maximum = Number(row.maximum ?? 0); const score = Number(row.score ?? 0); const percent = maximum ? score / maximum * 100 : 0; return <div className="risk-row" key={category}><span>{title(category)}</span><div><i style={{ width: `${percent}%` }} /></div><strong>{score}/{maximum || "—"}</strong></div>; })}</section>
    <section className="two-column"><DataPanel title="Findings" caption="Every severity is generated from a fixed, auditable rule." rows={findings.map((row: any) => [row.RuleID ?? row.rule_id, row.Title ?? row.title, row.Severity ?? row.severity])} empty="No completed security assessment was available." /><DataPanel title="Recommended actions" caption="Prioritised from the findings above." rows={recommendations.map((row: any) => [row.Priority ?? row.priority, row.Text ?? row.text, list(row.RuleIDs ?? row.rule_ids).join(", ")])} empty="No remediation actions are available." /></section>
  </>;
}

function Evidence({ protocol, fusion }: any) {
  const evidence = list(protocol.evidence); const conclusions = list(fusion.conclusions);
  return <>
    <section className="metric-grid"><Metric label="Fusion state" value={fusion.summary?.state ?? "—"} note={`${fusion.summary?.unresolved_conflicts ?? 0} unresolved conflicts`} /><Metric label="Evidence records" value={number(fusion.summary?.evidence_count)} note="Observed, derived, inferred, verified, or unknown" /><Metric label="Winning conclusions" value={number(fusion.summary?.conclusion_count)} note="Policy-selected values" /><Metric label="Unavailable sources" value={list(fusion.summary?.unavailable_sources).length ? list(fusion.summary?.unavailable_sources).join(", ") : "None"} note="No fabricated evidence" /></section>
    <section className="surface-panel table-panel"><div className="panel-header"><div><div className="panel-kicker">Conclusion ledger</div><h2>What the engine decided</h2></div><span>Source-aware</span></div><Table headings={["Property", "Value", "Confidence", "Winning source"]} rows={conclusions.map((row: any) => [row.property_key, row.value, `${Math.round(Number(row.confidence ?? 0) * 100)}%`, list(row.winning_sources).join(", ") || "—"])} empty="No Fusion conclusions are available." /></section>
    <section className="surface-panel table-panel"><div className="panel-header"><div><div className="panel-kicker">Raw normalized evidence</div><h2>Evidence trail</h2></div><span>First 200 records</span></div><Table headings={["Property", "Value", "Source", "Status"]} rows={evidence.map((row: any) => [row.property_key, row.value, row.source, status(row.evidence_status)])} empty="No protocol evidence was available." /></section>
  </>;
}

function Reports({ report, onGenerate }: { report: any; onGenerate: () => void }) {
  return <section className="report-stage surface-panel"><div><div className="panel-kicker">Executive handoff</div><h2>A report built from the evidence ledger</h2><p>The PDF includes protocol observations, deterministic findings, risk score, Fusion conclusions, and the selected evidence chain. It does not expose decrypted ESP payload data.</p></div>{report?.state === "READY" ? <a className="primary-button" href={`/api/core${report.download_url}`}>Download executive PDF</a> : <button className="primary-button" onClick={onGenerate}>{report?.state === "GENERATING" ? "Rendering report…" : "Generate executive PDF"}</button>}<div className="report-options"><span>✓ Timeline</span><span>✓ Threat matrix</span><span>✓ Evidence chain</span><span>· 24h retention</span></div></section>;
}

function PageHeading({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) { return <header className="page-heading"><p>{eyebrow}</p><h1>{title}</h1><span>{description}</span></header>; }
function Metric({ label, value, note, tone }: { label: string; value: string; note: string; tone?: string }) { return <article className={`metric-card ${tone ?? ""}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></article>; }
function Line({ label, value }: { label: string; value: any }) { return <p><span>{label}</span><b>{String(value)}</b></p>; }
function DataPanel({ title, caption, rows, empty }: { title: string; caption: string; rows: any[][]; empty: string }) { return <section className="surface-panel table-panel"><div className="panel-kicker">Evidence view</div><h2>{title}</h2><p className="panel-copy">{caption}</p><Table headings={["Property", "Value", "Source / context"]} rows={rows} empty={empty} /></section>; }
function Table({ headings, rows, empty }: { headings: string[]; rows: any[][]; empty: string }) { return rows.length ? <div className="data-table"><div className="data-row data-head">{headings.map(heading => <span key={heading}>{heading}</span>)}</div>{rows.map((row, index) => <div className="data-row" key={`${index}-${row[0]}`}>{headings.map((_, cell) => <span key={cell} title={String(row[cell] ?? "—")}>{String(row[cell] ?? "—")}</span>)}</div>)}</div> : <p className="empty-copy">{empty}</p>; }
function ErrorBox({ message }: { message: string }) { return <div className="error-box"><strong>Backend connection note</strong><span>{message}</span></div>; }
