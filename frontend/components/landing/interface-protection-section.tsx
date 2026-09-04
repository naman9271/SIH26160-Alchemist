import { SectionGrid } from "@/components/ui/section-grid";

const evidenceBoundaries = [
  ["OBSERVED", "Packet and protocol facts remain tied to captured traffic.", "text-sky-300"],
  ["DERIVED", "Computed flow and protocol summaries stay distinct from direct observations.", "text-teal-300"],
  ["INFERRED", "ML classification is context, never a protocol fact or security finding.", "text-amber-300"],
  ["VERIFIED GATEWAY", "Authorized Deep Assessment is required before gateway configuration facts appear.", "text-emerald-300"],
];

export function InterfaceProtectionSection() {
  return (
    <section id="evidence" className="relative isolate overflow-hidden px-5 py-20 font-mono lg:px-8 lg:py-28">
      <SectionGrid opacity={0.35} />
      <div className="relative z-10 mx-auto grid max-w-7xl gap-8 lg:grid-cols-[.8fr_1.2fr] lg:gap-16">
        <div>
          <p className="text-[10px] font-bold tracking-[.18em] text-sky-300">WHAT THE INTERFACE PROTECTS</p>
          <h2 className="mt-5 text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">No black-box certainty.</h2>
        </div>
        <div className="grid gap-px bg-sky-200/15 sm:grid-cols-2">
          {evidenceBoundaries.map(([label, copy, color]) => (
            <article key={label} className="bg-black/80 p-7 backdrop-blur-[1px]">
              <span className={`text-[10px] ${color}`}>{label}</span>
              <p className="mt-4 text-sm leading-7 text-white/65">{copy}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
