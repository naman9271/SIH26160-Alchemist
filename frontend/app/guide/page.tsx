import { GuidePage } from "@/components/dashboard/guide-page";
import { LandingFooter } from "@/components/ui/site-chrome";

export default function Guide() {
  return <main className="min-h-svh bg-black font-mono text-white">
    <div className="mx-auto max-w-[1440px] px-5 py-12 sm:px-8 lg:py-16">
      <GuidePage />
    </div>
    <LandingFooter />
  </main>;
}
