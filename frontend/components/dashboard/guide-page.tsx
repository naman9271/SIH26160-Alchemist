import Link from "next/link";

const workflow = [
  ["01", "Choose an input mode", "Use Passive PCAP for an existing .pcap or .cap file, Passive Live for an authorized interface, or Deep Assessment when you are authorized to read gateway state."],
  ["02", "Collect evidence", "The sensor records IPsec metadata for IKE, NAT-T, ESP, and AH. It never decrypts ESP payloads."],
  ["03", "Analyse and classify", "Core derives sessions and flows, fuses evidence, runs deterministic security checks, and optionally asks the ML worker to classify encrypted-flow metadata."],
  ["04", "Review results", "Use Progress, Overview, VPN Sessions, Flows, Evidence, Security Findings, and Risk & Fixes to understand what was found and what remains unknown."],
  ["05", "Ask and export", "The Report Assistant can explain a saved result in plain language. Reports creates a deterministic PDF from the completed analysis."],
];

const features = [
  {
    title: "Passive Analysis (PCAP)",
    when: "Use it when you already have a classic .pcap or .cap capture.",
    input: "A capture file up to 4 GiB. PCAPNG must be converted first.",
    action: "The browser uploads the file to Core. The sensor reads packet headers and IPsec metadata; Fusion combines the available evidence; security rules score only facts that can be supported. Optional ML uses flow metadata, never decrypted content.",
    output: "Protocol observations, sessions, flows, evidence coverage, security findings, a risk score, and optional traffic classifications.",
    next: "Open the completed dashboard, check Evidence for missing sources, then review Findings and Risk & Fixes.",
  },
  {
    title: "Deep Analysis (Deep Assessment)",
    when: "Use it only on a gateway you are authorized to assess and when VICI/XFRM access is configured on the host.",
    input: "A capture-capable interface plus explicit authorization in the workspace.",
    action: "It performs the same passive live capture and also requests read-only StrongSwan VICI and Linux XFRM state. These gateway facts can verify configuration that packets alone cannot prove; no gateway settings are changed.",
    output: "Captured protocol evidence plus available gateway-verified facts. Unavailable VICI or XFRM sources remain clearly marked as unavailable.",
    next: "Compare verified gateway facts with passive observations in Evidence and address any deterministic findings.",
  },
  {
    title: "Live Capture",
    when: "Use it when you need to observe current IPsec activity instead of uploading a saved capture.",
    input: "An authorized, capture-capable network interface.",
    action: "Core captures a fixed IPsec metadata filter for IKE, NAT-T, ESP, and AH. The console shows counters while capture is active. Capture stops when you choose Stop & Analyse or at the five-minute/64 MiB limit.",
    output: "A saved capture source that automatically enters the same analysis pipeline used by uploaded PCAP files.",
    next: "Allow enough relevant traffic to occur, stop the capture, wait for analysis to finish, and open the results dashboard.",
  },
  {
    title: "Traffic Classifier",
    when: "Use it when the ML worker is ready and you want an estimated application category for encrypted flows.",
    input: "Sufficient IPsec flow windows built from timing, direction, packet sizes, and volume metadata.",
    action: "The ML worker classifies metadata-only flow windows. It does not inspect encrypted payloads and its output is inference, not protocol truth.",
    output: "A class, confidence, alternative probabilities, and model version for each prediction. UNKNOWN means confidence was too low to make a reliable choice.",
    next: "Treat classifications as supporting context and confirm important conclusions with protocol or gateway evidence.",
  },
  {
    title: "Progress Flow",
    when: "Use it while an analysis is queued or running, or to understand where a failure occurred.",
    input: "An active analysis ID created after an upload or stopped live capture.",
    action: "Core reports the current operational stage as the pipeline initializes, extracts evidence, performs optional inference, fuses sources, assesses security, and completes.",
    output: "Current state, current stage, and availability of optional VICI, XFRM, and ML sources.",
    next: "Wait for Completed before generating a report. If a stage fails, use System Health and the displayed failure reason before retrying.",
  },
  {
    title: "Overview",
    when: "Use it first after an analysis completes.",
    input: "A selected analysis.",
    action: "It combines the analysis summary, security posture, risk score, and Fusion coverage into one starting view.",
    output: "High-level status and record counts. The security score is higher-is-better, while confidence and unknown-evidence counts describe coverage.",
    next: "Open the detailed section behind any metric before treating it as a conclusion, especially when evidence is missing.",
  },
  {
    title: "AI Analysis (Report Assistant)",
    when: "Use it after a completed analysis has been saved in browser history and you want a plain-language explanation.",
    input: "A selected saved report snapshot and your question.",
    action: "The selected snapshot is sent through the server-side Groq integration. The assistant is instructed to stay within the report and distinguish missing evidence from a safe result.",
    output: "A conversational explanation of the selected report. It does not change the deterministic score or add evidence to the analysis.",
    next: "Verify important statements in Evidence or Findings, then generate the deterministic PDF if you need a shareable record.",
  },
  {
    title: "Generate Report",
    when: "Use it after the analysis state is Completed.",
    input: "The selected completed analysis and its available protocol, Fusion, security, risk, traffic, and ML results.",
    action: "Core transforms those records into a structured report model, creates a temporary PDF artifact, and makes it available for 24 hours. The report does not ask the AI assistant to invent narrative content.",
    output: "A professional PDF with a cover, contents, readable summaries, supported findings and recommendations, and a technical evidence appendix.",
    next: "Download the PDF while it is available and retain it according to your organization’s handling policy.",
  },
];

export function GuidePage() {
  return <section className="mt-7 space-y-8">
    <div className="border border-teal-200/25 bg-teal-200/[.035] p-6 sm:p-8">
      <p className="text-[10px] font-bold tracking-[.16em] text-teal-200">FIRST-TIME USER GUIDE</p>
      <h1 className="mt-4 max-w-3xl text-2xl font-bold leading-tight sm:text-4xl">FROM CAPTURE TO A REPORT YOU CAN ACT ON.</h1>
      <p className="mt-5 max-w-3xl text-sm leading-7 text-white/65">Alchemist analyses observable IPsec protocol and traffic metadata. It keeps direct observations, deterministic results, ML inference, and authorized gateway verification separate. ESP payloads remain encrypted throughout.</p>
      <Link href="/workspace" className="mt-6 inline-flex border border-teal-200 bg-teal-200 px-4 py-2.5 text-[10px] font-bold tracking-[.12em] text-slate-950 transition-colors hover:bg-transparent hover:text-teal-100 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-200">START AN ANALYSIS</Link>
    </div>

    <section aria-labelledby="workflow-guide-title">
      <div className="flex items-end justify-between gap-4"><div><p className="text-[10px] tracking-[.16em] text-sky-200">COMPLETE WORKFLOW</p><h2 id="workflow-guide-title" className="mt-3 text-2xl font-bold">How the application works</h2></div><span className="hidden text-[10px] text-white/35 sm:block">OBSERVE → DERIVE → INFER → VERIFY → ASSESS</span></div>
      <ol className="mt-5 grid gap-3 lg:grid-cols-5">{workflow.map(([number, title, copy]) => <li key={number} className="border border-white/15 bg-white/[.025] p-5"><span className="text-[10px] font-bold tracking-[.14em] text-teal-200">{number}</span><h3 className="mt-4 text-sm font-bold">{title}</h3><p className="mt-3 text-xs leading-6 text-white/55">{copy}</p></li>)}</ol>
    </section>

    <section aria-labelledby="feature-guide-title">
      <p className="text-[10px] tracking-[.16em] text-sky-200">FEATURE REFERENCE</p>
      <h2 id="feature-guide-title" className="mt-3 text-2xl font-bold">What to use, when, and why</h2>
      <div className="mt-5 grid gap-4">{features.map((feature, index) => <article key={feature.title} className="border border-white/15 bg-white/[.02] p-6 sm:p-7">
        <div className="flex gap-4"><span className="text-[10px] font-bold text-teal-200">{String(index + 1).padStart(2, "0")}</span><div className="min-w-0 flex-1"><h3 className="text-lg font-bold text-white">{feature.title}</h3><p className="mt-3 text-sm leading-7 text-white/65">{feature.when}</p>
          <dl className="mt-5 grid gap-4 text-xs leading-6 md:grid-cols-2">
            <div className="border-l border-sky-200/40 pl-4"><dt className="font-bold tracking-[.1em] text-sky-200">INPUT</dt><dd className="mt-1 text-white/55">{feature.input}</dd></div>
            <div className="border-l border-white/20 pl-4"><dt className="font-bold tracking-[.1em] text-white/75">WHAT HAPPENS</dt><dd className="mt-1 text-white/55">{feature.action}</dd></div>
            <div className="border-l border-teal-200/40 pl-4"><dt className="font-bold tracking-[.1em] text-teal-200">OUTPUT</dt><dd className="mt-1 text-white/55">{feature.output}</dd></div>
            <div className="border-l border-amber-200/40 pl-4"><dt className="font-bold tracking-[.1em] text-amber-200">NEXT STEP</dt><dd className="mt-1 text-white/55">{feature.next}</dd></div>
          </dl>
        </div></div>
      </article>)}</div>
    </section>

    <aside className="border border-amber-200/25 bg-amber-200/[.035] p-6 text-sm leading-7 text-white/65"><b className="text-amber-100">Important interpretation rule:</b> unavailable or unknown evidence is not proof that a tunnel is safe. A high security score describes the checks that could be evaluated; always read it together with confidence, unknown-evidence counts, and unavailable sources.</aside>
  </section>;
}
