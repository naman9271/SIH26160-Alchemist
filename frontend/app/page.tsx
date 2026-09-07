import { EvidenceStorySection } from "@/components/landing/evidence-story-section";
import { InterfaceProtectionSection } from "@/components/landing/interface-protection-section";
import { ReadinessSection } from "@/components/landing/readiness-section";
import { FeaturesSection } from "@/components/features-section";
import { PrinciplesSection } from "@/components/principles-section";
import { LandingFooter } from "@/components/ui/site-chrome";
import { HeroAscii } from "@/components/ui/hero-ascii";
import { NoiseOverlay } from "@/components/ui/noise-overlay";

export default function Home() {
  return (
    <main className="bg-[var(--landing-canvas)] text-white">
      <HeroAscii />

      <div className="relative isolate overflow-hidden">
        <NoiseOverlay position="absolute" layer="behind" opacity={0.055} />
        <div className="relative z-10">
          <FeaturesSection />
          <EvidenceStorySection />
          <InterfaceProtectionSection />
          <PrinciplesSection />
          <ReadinessSection />
          <LandingFooter />
        </div>
      </div>
    </main>
  );
}
