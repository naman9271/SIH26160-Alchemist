import { SectionGrid } from "@/components/ui/section-grid";

const stages = [
  ["01", "OBSERVE", "Read IKE, ESP, AH, NAT-T, timing, and transport metadata visible in the capture."],
  ["02", "DERIVE", "Turn observations into deterministic protocol summaries, flow statistics, and source coverage."],
  ["03", "INFER", "Classify aggregate flow metadata only when the ML worker is ready; low confidence stays UNKNOWN."],
  ["04", "VERIFY", "Show gateway facts only after authorized Deep Assessment establishes their provenance."],
  ["05", "ASSESS", "Explain findings, remediation, threat context, and risk with deterministic rules."],
];

export function EvidenceStorySection() {
  return (
    <section id="method" className="relative isolate overflow-hidden border-y border-sky-200/15 px-5 py-20 font-mono lg:px-8 lg:py-28">
      <SectionGrid />
      <div className="relative z-10 mx-auto max-w-7xl">
        <p className="text-[10px] font-bold tracking-[.18em] text-sky-300">THE EVIDENCE STORY</p>
        <div className="mt-5 flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
          <h2 className="max-w-3xl text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">Every conclusion keeps its source, status, and limit.</h2>
          <p className="max-w-sm text-sm leading-7 text-white/60">Alchemist gives analysts a defensible account of what is observed, derived, inferred, unavailable, or still unknown.</p>
        </div>
        <div className="mt-14 grid border-l border-t border-sky-200/15 sm:grid-cols-2 lg:grid-cols-5">
          {stages.map(([number, title, copy]) => (
            <article key={title} className="min-h-64 border-b border-r border-sky-200/15 bg-black/40 p-5 backdrop-blur-[1px] lg:p-6">
              <span className="text-[10px] text-sky-200/60">{number}</span>
              <h3 className="mt-12 text-lg font-bold tracking-[.1em] text-sky-100">{title}</h3>
              <p className="mt-5 text-xs leading-6 text-white/60">{copy}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
