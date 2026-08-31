"use client";

import { useCallback, useEffect, useState } from "react";

type StatusPayload = {
  checkedAt: string;
  latencyMs: number;
  live: boolean;
  ready: boolean;
  status: string;
  dependencies: Record<string, string>;
  error?: string;
};

const labels: Record<string, string> = {
  memory: "In-memory store",
  temp_storage: "Temporary storage",
  sensor: "Sensor capture",
  ml: "ML worker",
  fusion: "Fusion engine",
};

function tone(value: string | boolean) {
  const normalized = String(value).toLowerCase();
  return normalized === "ready" || normalized === "true" || normalized === "alive"
    ? "good"
    : normalized === "unavailable" || normalized === "false"
      ? "bad"
      : "warn";
}

export default function Home() {
  const [data, setData] = useState<StatusPayload | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch("/api/backend-status", { cache: "no-store" });
      setData(await response.json());
    } catch {
      setData({ checkedAt: new Date().toISOString(), latencyMs: 0, live: false, ready: false, status: "offline", dependencies: {}, error: "The dashboard could not reach its status proxy." });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const initial = window.setTimeout(() => void refresh(), 0);
    const interval = window.setInterval(() => void refresh(), 5000);
    return () => {
      window.clearTimeout(initial);
      window.clearInterval(interval);
    };
  }, [refresh]);

  const dependencies = Object.entries(data?.dependencies ?? {});
  return (
    <main className="monitor-shell">
      <header className="monitor-header">
        <div>
          <p className="eyebrow">SIH 26160 · Team Alchemist</p>
          <h1>IPsec Core Monitor</h1>
          <p className="subtitle">Live backend observability for the Go Core service.</p>
        </div>
        <button className="refresh-button" onClick={() => void refresh()} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh now"}
        </button>
      </header>

      <section className="hero-status panel" aria-live="polite">
        <div className={`status-orb ${tone(data?.live ?? false)}`} />
        <div>
          <span>Core process</span>
          <strong>{data?.live ? "Alive" : "Unavailable"}</strong>
          <p>{data?.error ?? "The process is accepting status requests."}</p>
        </div>
        <div className="hero-side">
          <span className={`status-pill ${tone(data?.ready ?? false)}`}>{data?.ready ? "Ready for analysis" : "Degraded"}</span>
          <small>{data ? `Updated ${new Date(data.checkedAt).toLocaleTimeString()} · ${data.latencyMs} ms` : "Checking backend…"}</small>
        </div>
      </section>

      <section className="summary-grid" aria-label="Backend summary">
        <article className="panel summary-card"><span>Process</span><strong className={data?.live ? "text-good" : "text-bad"}>{data?.live ? "Alive" : "Offline"}</strong></article>
        <article className="panel summary-card"><span>Readiness</span><strong className={data?.ready ? "text-good" : "text-warn"}>{data?.ready ? "Ready" : "Degraded"}</strong></article>
        <article className="panel summary-card"><span>Dependencies ready</span><strong>{dependencies.filter(([, value]) => value === "READY").length}/{dependencies.length || "–"}</strong></article>
        <article className="panel summary-card"><span>Status latency</span><strong>{data ? `${data.latencyMs} ms` : "–"}</strong></article>
      </section>

      <section className="panel dependency-panel">
        <div className="section-heading"><div><h2>Backend dependencies</h2><p>Values are reported directly by <code>GET /health</code>.</p></div><span className="auto-refresh">Auto-refreshes every 5 seconds</span></div>
        {dependencies.length > 0 ? <div className="dependency-list">
          {dependencies.map(([key, value]) => <article className="dependency-row" key={key}><div><strong>{labels[key] ?? key}</strong><span>{key}</span></div><span className={`status-pill ${tone(value)}`}>{value.toLowerCase()}</span></article>)}
        </div> : <div className="empty-state">No dependency state is available yet. Start the Go Core service and refresh this page.</div>}
      </section>

      <section className="panel check-panel">
        <h2>What this confirms</h2>
        <ul><li>The Go Core process is reachable.</li><li>Fusion, storage, sensor, and ML dependency readiness are visible.</li><li>A degraded state is reported honestly instead of being displayed as healthy.</li></ul>
      </section>
    </main>
  );
}
