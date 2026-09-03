import { HeroAscii } from "@/components/ui/hero-ascii";
import { LandingFooter } from "@/components/ui/site-chrome";

const stages = [
  ["01", "OBSERVE", "Read IKE, ESP, AH, NAT-T, packet timing, and transport metadata that are visible without decrypting payloads."],
  ["02", "DERIVE", "Turn packet observations into deterministic protocol summaries, flow statistics, and source coverage."],
  ["03", "INFER", "Classify aggregate flow metadata only when ML is available; low confidence remains UNKNOWN."],
  ["04", "VERIFY", "Show gateway facts only after authorized Deep Assessment establishes their provenance."],
  ["05", "ASSESS", "Use deterministic rules to explain findings, remediation, threat context, and risk."],
];

export default function Home() {
  return (
    <main className="bg-black text-white">
      <HeroAscii />

      <section id="method" className="border-y border-white/15 px-5 py-20 font-mono lg:px-8 lg:py-28">
        <div className="mx-auto max-w-7xl">
          <p className="text-[10px] font-bold tracking-[.18em] text-white/50">THE EVIDENCE STORY</p>
          <div className="mt-5 flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between">
            <h2 className="max-w-3xl text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">Every conclusion keeps its source, status, and limit.</h2>
            <p className="max-w-sm text-sm leading-7 text-white/60">Alchemist is built for analysts who need a defensible account of what is known, inferred, unavailable, or still unknown.</p>
          </div>
          <div className="mt-14 grid border-l border-t border-white/15 sm:grid-cols-2 lg:grid-cols-5">
            {stages.map(([number, title, copy]) => (
              <article key={title} className="min-h-64 border-b border-r border-white/15 p-5 lg:p-6">
                <span className="text-[10px] text-white/45">{number}</span>
                <h3 className="mt-12 text-lg font-bold tracking-[.1em]">{title}</h3>
                <p className="mt-5 text-xs leading-6 text-white/60">{copy}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section id="evidence" className="relative overflow-hidden px-5 py-20 font-mono lg:px-8 lg:py-28">
        <div aria-hidden="true" className="absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(255,255,255,.08)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,.08)_1px,transparent_1px)] [background-size:42px_42px]" />
        <div className="relative mx-auto grid max-w-7xl gap-8 lg:grid-cols-[.8fr_1.2fr] lg:gap-16">
          <div>
            <p className="text-[10px] font-bold tracking-[.18em] text-white/50">WHAT THE INTERFACE PROTECTS</p>
            <h2 className="mt-5 text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">No black-box certainty.</h2>
          </div>
          <div className="grid gap-px bg-white/15 sm:grid-cols-2">
            <article className="bg-black p-7"><span className="text-[10px] text-sky-300">OBSERVED</span><p className="mt-4 text-sm leading-7 text-white/65">Packet and protocol facts remain tied to captured traffic.</p></article>
            <article className="bg-black p-7"><span className="text-[10px] text-teal-300">DERIVED</span><p className="mt-4 text-sm leading-7 text-white/65">Computed flow and protocol summaries stay distinct from direct observations.</p></article>
            <article className="bg-black p-7"><span className="text-[10px] text-amber-300">INFERRED</span><p className="mt-4 text-sm leading-7 text-white/65">ML traffic classification is context, never a protocol fact or security finding.</p></article>
            <article className="bg-black p-7"><span className="text-[10px] text-emerald-300">VERIFIED GATEWAY</span><p className="mt-4 text-sm leading-7 text-white/65">Authorized Deep Assessment is required before gateway configuration facts appear.</p></article>
          </div>
        </div>
      </section>

      <section id="scope" className="border-t border-white/15 px-5 py-20 font-mono lg:px-8 lg:py-28">
        <div className="mx-auto max-w-7xl rounded-sm border border-white/25 bg-white px-7 py-10 text-black sm:px-10 lg:flex lg:items-end lg:justify-between lg:px-14 lg:py-14">
          <div>
            <p className="text-[10px] font-bold tracking-[.18em] text-black/55">READY WHEN THE CAPTURE IS</p>
            <h2 className="mt-5 max-w-2xl text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">Bring a PCAP. Leave with an evidence-led story.</h2>
          </div>
          <a href="/workspace" className="mt-8 inline-flex border border-black px-6 py-3 text-xs font-bold tracking-[.12em] transition hover:bg-black hover:text-white lg:mt-0">OPEN WORKSPACE</a>
        </div>
      </section>

      <LandingFooter />
    </main>
  );
}
