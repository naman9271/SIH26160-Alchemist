"use client";

import { useLayoutEffect, useRef } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { HighlightText } from "@/components/highlight-text";
import { SectionGrid } from "@/components/ui/section-grid";

export type Principle = {
  number: string;
  title: string;
  highlight: string;
  description: string;
  align: "left" | "right";
};

export const principles: Principle[] = [
  {
    number: "01",
    title: "CAPTURE-LED ANALYSIS",
    highlight: "CAPTURE-LED",
    description:
      "Start from what the capture can support: IPsec packets, protocol headers, timing, transport metadata, and evidence source coverage.",
    align: "left",
  },
  {
    number: "02",
    title: "EVIDENCE BOUNDARIES",
    highlight: "EVIDENCE",
    description:
      "Observed facts, deterministic derivations, ML inference, and authorized gateway verification remain visibly separate at every step.",
    align: "right",
  },
  {
    number: "03",
    title: "CONFIDENCE, NOT CERTAINTY",
    highlight: "CERTAINTY",
    description:
      "Low-confidence classification remains UNKNOWN. A model result is context—not protocol truth, a security finding, or a gateway fact.",
    align: "left",
  },
  {
    number: "04",
    title: "ACTIONABLE ASSESSMENT",
    highlight: "ASSESSMENT",
    description:
      "Finish with deterministic findings, risk context, remediation guidance, and an executive report grounded in the available evidence.",
    align: "right",
  },
  {
    number: "05",
    title: "REPORT-READY EVIDENCE",
    highlight: "EVIDENCE",
    description:
      "Carry the same status, source, and confidence boundaries into an executive report that can be reviewed without overstating what the capture proves.",
    align: "left",
  },
];

export function PrinciplesSection({ items = principles }: { items?: Principle[] }) {
  const sectionRef = useRef<HTMLElement>(null);

  useLayoutEffect(() => {
    const section = sectionRef.current;
    if (!section || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    gsap.registerPlugin(ScrollTrigger);
    const context = gsap.context(() => {
      const header = section.querySelector<HTMLElement>("[data-principles-header]");
      const entries = gsap.utils.toArray<HTMLElement>("[data-principle]");

      if (header) {
        gsap.from(header, {
          x: -60,
          autoAlpha: 0,
          duration: 1,
          ease: "power3.out",
          scrollTrigger: { trigger: header, start: "top 85%" },
        });
      }

      entries.forEach((entry) => {
        const isRight = entry.dataset.align === "right";
        const backdrops = entry.querySelectorAll<HTMLElement>("[data-highlight-backdrop]");
        const foregrounds = entry.querySelectorAll<HTMLElement>("[data-highlight-foreground]");

        gsap.set(backdrops, { scaleX: 0, transformOrigin: "left center" });
        gsap.set(foregrounds, { color: "#ffffff" });

        const timeline = gsap.timeline({
          scrollTrigger: { trigger: entry, start: "top 85%", once: true },
        });

        timeline
          .from(entry, { x: isRight ? 80 : -80, autoAlpha: 0, duration: 1, ease: "power3.out" })
          .to(backdrops, { scaleX: 1, duration: 1.2, ease: "power3.out" }, 0)
          .to(foregrounds, { color: "#000000", duration: 0.45, ease: "power2.out" }, 0.6);

        gsap.to(backdrops, {
          yPercent: 6,
          ease: "none",
          scrollTrigger: {
            trigger: entry,
            start: "top bottom",
            end: "bottom top",
            scrub: true,
          },
        });
      });
    }, section);

    return () => context.revert();
  }, [items]);

  return (
    <section ref={sectionRef} id="approach" className="relative isolate overflow-x-clip bg-[var(--landing-canvas)] px-4 py-16 text-white md:px-8 md:py-24 lg:px-12">
      <SectionGrid />
      <div className="relative z-10 mx-auto max-w-[1440px]">
        <header data-principles-header className="mb-16">
          <p className="font-mono text-[10px] uppercase tracking-[.3em] text-primary">APPROACH</p>
          <h2 className="mt-5 uppercase [font-family:var(--serif)] text-3xl font-normal leading-[.92] tracking-[-.06em] md:text-5xl lg:text-6xl">
            HOW IT WORKS
          </h2>
        </header>

        <div className="space-y-16 md:space-y-24">
          {items.map((principle) => {
            const isRight = principle.align === "right";

            return (
              <article
                key={principle.number}
                data-principle
                data-align={principle.align}
                className={`max-w-[1280px] ${isRight ? "ml-auto text-right" : "text-left"}`}
              >
                <p className="font-mono text-[10px] uppercase tracking-[.24em] text-white/45">
                  {principle.number} / {principle.highlight}
                </p>
                <h3 className="mt-5 uppercase [font-family:var(--serif)] text-3xl font-normal leading-[.96] tracking-[-.05em] md:text-5xl lg:text-7xl">
                  <HighlightText title={principle.title} highlight={principle.highlight} />
                </h3>
                <p className={`mt-6 max-w-md font-mono text-sm leading-7 text-white/50 ${isRight ? "ml-auto" : ""}`}>
                  {principle.description}
                </p>
                <div aria-hidden="true" className={`mt-6 h-px w-24 bg-primary/35 lg:w-48 ${isRight ? "ml-auto" : ""}`} />
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}
