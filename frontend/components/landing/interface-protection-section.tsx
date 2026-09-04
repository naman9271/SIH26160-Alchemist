"use client";

import { motion } from "framer-motion";
import { SectionGrid } from "@/components/ui/section-grid";

const evidenceBoundaries = [
  ["OBSERVED", "Packet and protocol facts remain tied to captured traffic.", "text-sky-300", "from-sky-300/55"],
  ["DERIVED", "Computed flow and protocol summaries stay distinct from direct observations.", "text-teal-300", "from-teal-300/55"],
  ["INFERRED", "ML classification is context, never a protocol fact or security finding.", "text-amber-300", "from-amber-300/50"],
  ["VERIFIED GATEWAY", "Authorized Deep Assessment is required before gateway configuration facts appear.", "text-emerald-300", "from-emerald-300/50"],
];

export function InterfaceProtectionSection() {
  return (
    <section id="evidence" className="relative isolate overflow-hidden px-5 py-16 font-mono lg:px-8 lg:py-20">
      <SectionGrid opacity={0.35} />
      <div className="relative z-10 mx-auto grid max-w-7xl gap-8 lg:grid-cols-[.8fr_1.2fr] lg:gap-16">
        <motion.div
          initial={{ opacity: 0, x: -24 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true, amount: 0.45 }}
          transition={{ duration: 0.55, ease: "easeOut" }}
        >
          <p className="text-[10px] font-bold tracking-[.18em] text-sky-300">WHAT THE INTERFACE PROTECTS</p>
          <h2 className="mt-5 text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">No black-box certainty.</h2>
          <div className="mt-6 hidden h-px w-44 bg-gradient-to-r from-teal-200/70 to-transparent lg:block" />
        </motion.div>
        <div className="grid gap-px bg-sky-200/15 sm:grid-cols-2">
          {evidenceBoundaries.map(([label, copy, color, glow], index) => (
            <motion.article
              key={label}
              className="group relative overflow-hidden bg-black/80 p-7 backdrop-blur-[1px] transition-colors duration-500 hover:bg-slate-950/95"
              initial={{ opacity: 0, y: 28, filter: "blur(8px)" }}
              whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ duration: 0.5, ease: "easeOut", delay: index * 0.09 }}
              whileHover={{ y: -6 }}
            >
              <span className={`pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r ${glow} via-white/35 to-transparent opacity-0 transition-opacity duration-500 group-hover:opacity-100`} />
              <span className="evidence-stage-scan pointer-events-none absolute inset-x-0 top-0 h-14 opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
              <span className="pointer-events-none absolute right-5 top-5 h-8 w-8 border-r border-t border-white/10 transition-colors duration-500 group-hover:border-teal-100/45" />
              <span className="evidence-stage-node pointer-events-none absolute bottom-6 right-6 h-1.5 w-1.5 rounded-full bg-teal-100/70 opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
              <span className={`relative z-10 text-[10px] ${color}`}>{label}</span>
              <p className="relative z-10 mt-4 text-sm leading-7 text-white/65 transition-colors duration-500 group-hover:text-white/80">{copy}</p>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
