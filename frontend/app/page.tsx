const trafficClasses = [
  { label: "Web", value: 10, color: "#58a6ff" },
  { label: "Video", value: 10, color: "#b392f0" },
  { label: "VoIP", value: 10, color: "#f778ba" },
  { label: "Email", value: 10, color: "#f2cc60" },
  { label: "File transfer", value: 10, color: "#3fb950" },
  { label: "Messaging", value: 10, color: "#39c5cf" },
  { label: "ICMP", value: 10, color: "#ff7b72" },
];

const corpusRoles = [
  { label: "Known traffic", value: 70, color: "#58a6ff" },
  { label: "Protocol validation", value: 5, color: "#b392f0" },
  { label: "OOD / UNKNOWN", value: 4, color: "#f2cc60" },
  { label: "Anomaly evaluation", value: 3, color: "#ff7b72" },
];

const profileCoverage = [
  { label: "IKEv1", value: 33, color: "#f778ba" },
  { label: "IKEv2", value: 49, color: "#58a6ff" },
  { label: "Tunnel mode", value: 66, color: "#3fb950" },
  { label: "Transport mode", value: 16, color: "#f2cc60" },
  { label: "IPv6", value: 15, color: "#b392f0" },
];

type ChartItem = { label: string; value: number; color: string };

function BarChart({ title, items, maximum }: { title: string; items: ChartItem[]; maximum: number }) {
  return (
    <figure className="panel chart-panel">
      <figcaption>{title}</figcaption>
      <div className="bar-list">
        {items.map((item) => (
          <div className="bar-row" key={item.label}>
            <span>{item.label}</span>
            <div className="bar-track" aria-label={`${item.label}: ${item.value}`}>
              <div className="bar-fill" style={{ width: `${(item.value / maximum) * 100}%`, background: item.color }} />
            </div>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>
    </figure>
  );
}

function Donut({ value, label, color }: { value: number; label: string; color: string }) {
  return (
    <figure className="panel donut-panel">
      <div className="donut" style={{ background: `conic-gradient(${color} ${value}%, #202b3b 0)` }} aria-label={`${label}: ${value}%`}>
        <div className="donut-center"><strong>{value}%</strong><span>{label}</span></div>
      </div>
    </figure>
  );
}

export default function Home() {
  return (
    <main className="dashboard">
      <header className="topbar">
        <div><p className="eyebrow">SIH 26160 · Team Alchemist</p><h1>IPsec VPN Analyzer</h1></div>
        <div className="status-chip">Dataset figures · model not trained</div>
      </header>
      <section className="metric-grid" aria-label="Corpus summary">
        <article className="panel metric"><span>Validated PCAPs</span><strong>82</strong></article>
        <article className="panel metric"><span>Traffic classes</span><strong>7</strong></article>
        <article className="panel metric"><span>Known captures</span><strong>70</strong></article>
        <article className="panel metric warning"><span>Calibrated models</span><strong>0</strong></article>
      </section>
      <section className="chart-grid">
        <BarChart title="Known captures per traffic class" items={trafficClasses} maximum={10} />
        <BarChart title="Capture corpus by role" items={corpusRoles} maximum={82} />
        <BarChart title="IPsec profile coverage" items={profileCoverage} maximum={82} />
        <div className="donut-grid">
          <Donut value={100} label="hashes verified" color="#3fb950" />
          <Donut value={0} label="model readiness" color="#ff7b72" />
          <Donut value={40} label="final corpus target" color="#f2cc60" />
        </div>
      </section>
      <footer>Figures are static repository-state indicators. Live capture, predictions, risk scores, and reports appear here only after the Core analysis API and trained ML model are available.</footer>
    </main>
  );
}
