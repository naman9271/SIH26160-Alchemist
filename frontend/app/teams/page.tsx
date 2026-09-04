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
      <section className="relative isolate overflow-hidden px-5 py-24 font-mono lg:px-8 lg:py-32">
        <SectionGrid opacity={0.35} />
        <NoiseOverlay position="absolute" layer="over" opacity={0.2} />
        <div className="relative z-10 mx-auto max-w-7xl">
          <p className="text-[10px] font-bold tracking-[.22em] text-sky-300">SIH 2026 / TEAM</p>
          <div className="mt-6 grid gap-10 lg:grid-cols-[.9fr_1.1fr] lg:items-end">
            <h1 className="max-w-3xl font-serif text-5xl font-normal leading-[.9] tracking-[-.06em] sm:text-7xl">THE PEOPLE BEHIND THE EVIDENCE.</h1>
            <p className="max-w-md text-sm leading-7 text-white/60">Alchemist brings protocol engineering, metadata-aware ML, deterministic security analysis, and clear evidence UX into one disciplined workflow.</p>
          </div>

          <div className="mt-20 grid gap-px border border-sky-200/20 bg-sky-200/20 md:grid-cols-2">
            {teamFocus.map((focus, index) => (
              <article key={focus.area} className="relative min-h-72 bg-slate-950/90 p-7 backdrop-blur-[1px] lg:p-9">
                <span className="text-[10px] tracking-[.18em] text-sky-300">{String(index + 1).padStart(2, "0")} / {focus.area}</span>
                <h2 className="mt-14 font-serif text-3xl font-normal leading-none tracking-[-.04em] text-white sm:text-4xl">{focus.role}</h2>
                <p className="mt-6 max-w-sm text-sm leading-7 text-white/55">{focus.description}</p>
              </article>
            ))}
          </div>
        </div>
      </section>
      <LandingFooter />
    </main>
  );
}
