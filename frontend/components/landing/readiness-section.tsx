import Link from "next/link";
import { SectionGrid } from "@/components/ui/section-grid";

export function ReadinessSection() {
  return (
    <section id="scope" className="relative isolate overflow-hidden border-t border-sky-200/15 px-5 py-20 font-mono lg:px-8 lg:py-28">
      <SectionGrid />
      <div className="relative z-10 mx-auto max-w-7xl border border-sky-200/30 bg-slate-950/85 px-7 py-10 sm:px-10 lg:flex lg:items-end lg:justify-between lg:px-14 lg:py-14">
        <div>
          <p className="text-[10px] font-bold tracking-[.18em] text-sky-300">READY WHEN THE CAPTURE IS</p>
          <h2 className="mt-5 max-w-2xl text-3xl font-bold leading-tight tracking-[.04em] text-white sm:text-5xl">Bring a PCAP. Leave with an evidence-led story.</h2>
        </div>
        <Link href="/workspace" className="mt-8 inline-flex border border-sky-300 bg-sky-300 px-6 py-3 text-xs font-bold tracking-[.12em] text-slate-950 transition hover:bg-transparent hover:text-sky-200 lg:mt-0">OPEN WORKSPACE</Link>
      </div>
    </section>
  );
}
