"use client";

import { useEffect, useRef, useState } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { SectionGrid } from "@/components/ui/section-grid";

type Feature = { title: string; label: string; description: string; span: string };

export const features: Feature[] = [
  { title: "Passive PCAP Analysis", label: "Capture Input", description: "Upload a classic PCAP and inspect IPsec metadata without decrypting ESP payloads.", span: "md:col-span-2 md:row-span-2" },
  { title: "Protocol Evidence", label: "Observed", description: "Read IKE, ESP, AH, NAT-T, timing, and transport facts directly from captured packets.", span: "" },
  { title: "Flow Classification", label: "Inferred", description: "Classify aggregate flow metadata when ML is ready, while preserving UNKNOWN at low confidence.", span: "md:row-span-2" },
  { title: "Deterministic Derivations", label: "Derived", description: "Convert observations into flow statistics, protocol summaries, and source coverage.", span: "" },
  { title: "Risk & Remediation", label: "Assessment", description: "Explain deterministic security findings, risk drivers, threat context, and recommended actions.", span: "md:col-span-2" },
  { title: "Gateway Boundaries", label: "Authorized", description: "Keep gateway facts unavailable until an authorized Deep Assessment establishes provenance.", span: "" },
  { title: "Executive Reports", label: "Export", description: "Generate a concise evidence-led PDF report after an analysis completes.", span: "" },
];

export function FeaturesSection() {
  const sectionRef = useRef<HTMLElement>(null);
  const headerRef = useRef<HTMLDivElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const section = sectionRef.current;
    const header = headerRef.current;
    const grid = gridRef.current;
    if (!section || !header || !grid || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    gsap.registerPlugin(ScrollTrigger);
    const context = gsap.context(() => {
      const cards = grid.querySelectorAll<HTMLElement>("article");
      gsap.from(header, { x: -60, duration: 1, ease: "power3.out", scrollTrigger: { trigger: header, start: "top 90%" } });
      gsap.from(cards, { y: 60, duration: 0.8, stagger: 0.1, ease: "power3.out", scrollTrigger: { trigger: grid, start: "top 90%" } });
    }, section);
    return () => context.revert();
  }, []);

  return (
    <section ref={sectionRef} id="features" className="relative isolate overflow-hidden py-16 md:py-24">
      <SectionGrid />
      <div className="site-container relative z-10">
        <div ref={headerRef} className="mb-12 flex items-end justify-between gap-8">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[.3em] text-primary">FEATURES</p>
            <h2 className="mt-4 font-mono text-3xl font-bold tracking-[.04em] md:text-5xl lg:text-6xl">WHAT YOU GET</h2>
          </div>
          <p className="hidden max-w-xs text-right font-mono text-xs leading-relaxed text-foreground/50 md:block">The capture-to-report workflow for protocol evidence, bounded inference, and deterministic security assessment.</p>
        </div>
        <div ref={gridRef} className="grid grid-cols-1 auto-rows-[156px] gap-3 sm:grid-cols-2 md:auto-rows-[170px] md:grid-cols-4 md:gap-5">
          {features.map((feature, index) => <FeatureCard key={feature.title} feature={feature} index={index} persistActive={index === 0} />)}
        </div>
      </div>
    </section>
  );
}

function FeatureCard({ feature, index, persistActive }: { feature: Feature; index: number; persistActive: boolean }) {
  const cardRef = useRef<HTMLElement>(null);
  const [hovered, setHovered] = useState(false);
  const [scrollActive, setScrollActive] = useState(false);

  useEffect(() => {
    const card = cardRef.current;
    if (!card || !persistActive) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.registerPlugin(ScrollTrigger);
    const trigger = ScrollTrigger.create({ trigger: card, start: "top 80%", onEnter: () => setScrollActive(true) });
    return () => trigger.kill();
  }, [persistActive]);

  const active = hovered || scrollActive;
  return (
    <article ref={cardRef} className={`group relative flex cursor-pointer flex-col justify-between overflow-hidden border border-border/40 p-4 transition-all duration-500 md:p-5 ${feature.span} ${active ? "border-primary/60" : ""}`} onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
      <div aria-hidden="true" className={`absolute inset-0 bg-primary/5 transition-opacity duration-500 ${active ? "opacity-100" : "opacity-0"}`} />
      <div className="relative z-10">
        <p className="font-mono text-[10px] uppercase tracking-widest text-foreground/40">{feature.label}</p>
        <h3 className={`mt-3 font-mono text-xl font-bold leading-tight tracking-[.02em] transition-colors duration-300 md:text-3xl ${active ? "text-primary" : "text-foreground"}`}>{feature.title}</h3>
      </div>
      <p className={`relative z-10 max-w-[280px] font-mono text-[11px] leading-5 text-foreground/50 transition-all duration-500 motion-reduce:translate-y-0 motion-reduce:opacity-100 ${active ? "translate-y-0 opacity-100" : "translate-y-2 opacity-0"}`}>{feature.description}</p>
      <span className={`absolute bottom-4 right-4 font-mono text-[10px] transition-colors duration-300 ${active ? "text-primary" : "text-foreground/20"}`}>{String(index + 1).padStart(2, "0")}</span>
      <div aria-hidden="true" className={`absolute right-0 top-0 h-12 w-12 transition-opacity duration-500 ${active ? "opacity-100" : "opacity-0"}`}>
        <div className="absolute right-0 top-0 h-px w-full bg-primary" />
        <div className="absolute right-0 top-0 h-full w-px bg-primary" />
      </div>
    </article>
  );
}
