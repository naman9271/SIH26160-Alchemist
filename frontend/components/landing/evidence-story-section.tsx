"use client";

import { motion } from "framer-motion";
import { SectionGrid } from "@/components/ui/section-grid";

const stages = [
  ["01", "OBSERVE", "Read IKE, ESP, AH, NAT-T, timing, and transport metadata visible in the capture.", "from-sky-300/50"],
  ["02", "DERIVE", "Turn observations into deterministic protocol summaries, flow statistics, and source coverage.", "from-teal-300/50"],
  ["03", "INFER", "Classify aggregate flow metadata only when the ML worker is ready; low confidence stays UNKNOWN.", "from-amber-300/45"],
  ["04", "VERIFY", "Show gateway facts only after authorized Deep Assessment establishes their provenance.", "from-emerald-300/45"],
  ["05", "ASSESS", "Explain findings, remediation, threat context, and risk with deterministic rules.", "from-cyan-300/50"],
];

export function EvidenceStorySection() {
  return (
    <section id="method" className="relative isolate overflow-hidden border-y border-sky-200/15 px-5 py-16 font-mono lg:px-8 lg:py-20">
      <SectionGrid />
      <div className="relative z-10 mx-auto max-w-7xl">
        <motion.p
          className="text-[10px] font-bold tracking-[.18em] text-sky-300"
          initial={{ opacity: 0, y: 14 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.7 }}
          transition={{ duration: 0.45, ease: "easeOut" }}
        >
          THE EVIDENCE STORY
        </motion.p>
        <motion.div
          className="mt-5 flex flex-col gap-8 lg:flex-row lg:items-end lg:justify-between"
          initial={{ opacity: 0, y: 22 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.45 }}
          transition={{ duration: 0.55, ease: "easeOut", delay: 0.08 }}
        >
          <h2 className="max-w-3xl text-3xl font-bold leading-tight tracking-[.04em] sm:text-5xl">Every conclusion keeps its source, status, and limit.</h2>
          <p className="max-w-sm text-sm leading-7 text-white/60">Alchemist gives analysts a defensible account of what is observed, derived, inferred, unavailable, or still unknown.</p>
        </motion.div>
        <div className="mt-10 grid border-l border-t border-sky-200/15 sm:grid-cols-2 lg:grid-cols-5">
          {stages.map(([number, title, copy, glow], index) => (
            <motion.article
              key={title}
              className="group relative min-h-56 overflow-hidden border-b border-r border-sky-200/15 bg-black/45 p-5 backdrop-blur-[1px] transition-colors duration-500 hover:border-teal-200/40 hover:bg-slate-950/80 lg:p-6"
              initial={{ opacity: 0, y: 34, filter: "blur(8px)" }}
              whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
              viewport={{ once: true, amount: 0.35 }}
              transition={{ duration: 0.55, ease: "easeOut", delay: index * 0.08 }}
              whileHover={{ y: -8 }}
            >
              <span className={`pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r ${glow} via-white/50 to-transparent opacity-0 transition-opacity duration-500 group-hover:opacity-100`} />
              <span className="evidence-stage-scan pointer-events-none absolute inset-x-0 top-0 h-14 opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
              <span className="pointer-events-none absolute right-5 top-5 h-8 w-8 border-r border-t border-sky-100/15 transition-colors duration-500 group-hover:border-teal-100/45" />
              <span className="evidence-stage-node pointer-events-none absolute bottom-6 right-6 h-1.5 w-1.5 rounded-full bg-teal-100/70 opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
              <span className="relative z-10 text-[10px] text-sky-200/60 transition-colors duration-500 group-hover:text-teal-100">{number}</span>
              <h3 className="relative z-10 mt-12 text-lg font-bold tracking-[.1em] text-sky-100 transition-colors duration-500 group-hover:text-white">{title}</h3>
              <p className="relative z-10 mt-5 text-xs leading-6 text-white/60 transition-colors duration-500 group-hover:text-white/75">{copy}</p>
            </motion.article>
          ))}
        </div>
      </div>
    </section>
  );
}
