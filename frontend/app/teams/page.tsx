"use client";

import { motion } from "framer-motion";
import { LandingFooter } from "@/components/ui/site-chrome";
import { NoiseOverlay } from "@/components/ui/noise-overlay";
import { SectionGrid } from "@/components/ui/section-grid";

type TeamFocus = {
  area: string;
  role: string;
  description: string;
};

// Replace these focus areas with your team members' names and roles when ready.
export const teamFocus: TeamFocus[] = [
  {
    area: "CORE RUNTIME",
    role: "Go Services & Protocol Engine",
    description: "Builds the HTTP workflow, packet evidence processing, and transport boundaries that keep browser access safe and explicit.",
  },
  {
    area: "FUSION & ML",
    role: "Metadata Classification",
    description: "Connects aggregate flow classification to the evidence model without presenting inference as protocol truth.",
  },
  {
    area: "SECURITY & RISK",
    role: "Deterministic Assessment",
    description: "Translates security rules, remediation guidance, and risk context into explainable analyst-facing conclusions.",
  },
  {
    area: "EVIDENCE UX",
    role: "Frontend & Reporting",
    description: "Designs the evidence-led workflow, accessible status language, and reports used by analysts and SIH evaluators.",
  },
];

export default function TeamsPage() {
  return (
    <main className="min-h-svh bg-black text-white">
      <section className="relative isolate overflow-hidden px-5 py-16 font-mono lg:px-8 lg:py-20">
        <SectionGrid opacity={0.35} />
        <NoiseOverlay position="absolute" layer="over" opacity={0.2} />
        <div className="relative z-10 mx-auto max-w-7xl">
          <motion.p
            className="text-[10px] font-bold tracking-[.22em] text-sky-300"
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease: "easeOut" }}
          >
            SIH 2026 / TEAM
          </motion.p>
          <motion.div
            className="mt-5 grid gap-8 lg:grid-cols-[.9fr_1.1fr] lg:items-end"
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut", delay: 0.08 }}
          >
            <h1 className="max-w-3xl font-serif text-5xl font-normal leading-[.9] tracking-[-.06em] sm:text-7xl">THE PEOPLE BEHIND THE EVIDENCE.</h1>
            <p className="max-w-md text-sm leading-7 text-white/60">Alchemist brings protocol engineering, metadata-aware ML, deterministic security analysis, and clear evidence UX into one disciplined workflow.</p>
          </motion.div>

          <div className="mt-12 grid gap-px border border-sky-200/20 bg-sky-200/20 md:grid-cols-2">
            {teamFocus.map((focus, index) => (
              <motion.article
                key={focus.area}
                className="group relative min-h-56 overflow-hidden bg-slate-950/90 p-6 backdrop-blur-[1px] transition-colors duration-500 hover:bg-slate-950 lg:p-7"
                initial={{ opacity: 0, y: 32, filter: "blur(8px)" }}
                whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
                viewport={{ once: true, amount: 0.35 }}
                transition={{ duration: 0.55, ease: "easeOut", delay: index * 0.08 }}
                whileHover={{ y: -6 }}
              >
                <span className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-teal-300/55 via-white/35 to-transparent opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
                <span className="evidence-stage-scan pointer-events-none absolute inset-x-0 top-0 h-14 opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
                <span className="pointer-events-none absolute right-6 top-6 h-10 w-10 border-r border-t border-sky-100/15 transition-colors duration-500 group-hover:border-teal-100/45" />
                <span className="evidence-stage-node pointer-events-none absolute bottom-7 right-7 h-1.5 w-1.5 rounded-full bg-teal-100/70 opacity-0 transition-opacity duration-500 group-hover:opacity-100" />
                <span className="relative z-10 text-[10px] tracking-[.18em] text-sky-300">{String(index + 1).padStart(2, "0")} / {focus.area}</span>
                <h2 className="relative z-10 mt-10 font-serif text-3xl font-normal leading-none tracking-[-.04em] text-white transition-colors duration-500 group-hover:text-teal-50 sm:text-4xl">{focus.role}</h2>
                <p className="relative z-10 mt-5 max-w-sm text-sm leading-7 text-white/55 transition-colors duration-500 group-hover:text-white/70">{focus.description}</p>
              </motion.article>
            ))}
          </div>
        </div>
      </section>
      <LandingFooter />
    </main>
  );
}
