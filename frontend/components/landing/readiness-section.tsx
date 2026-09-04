import Link from "next/link";
import { SectionGrid } from "@/components/ui/section-grid";

export function ReadinessSection() {
  return (
    <section id="scope" className="relative isolate overflow-hidden border-t border-sky-200/15 px-5 py-16 font-mono lg:px-8 lg:py-20">
      <SectionGrid />
      <div className="group relative z-10 mx-auto max-w-7xl overflow-hidden border border-sky-200/30 bg-slate-950/85 px-7 py-10 shadow-[0_0_80px_rgba(14,165,233,.08)] backdrop-blur-sm transition duration-500 hover:border-teal-200/50 hover:shadow-[0_0_110px_rgba(45,212,191,.13)] sm:px-10 lg:flex lg:items-end lg:justify-between lg:px-14 lg:py-14">
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_20%,rgba(94,234,212,.13),transparent_28%),radial-gradient(circle_at_92%_88%,rgba(56,189,248,.12),transparent_30%)]" />
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(125,211,252,.11)_1px,transparent_1px),linear-gradient(90deg,rgba(125,211,252,.08)_1px,transparent_1px)] [background-size:38px_38px] opacity-25" />
        <div aria-hidden="true" className="readiness-scan pointer-events-none absolute inset-x-0 top-0 h-20 opacity-45" />
        <span aria-hidden="true" className="absolute left-0 top-0 h-10 w-10 border-l border-t border-teal-100/55" />
        <span aria-hidden="true" className="absolute bottom-0 right-0 h-10 w-10 border-b border-r border-teal-100/55" />

        <div className="relative z-10">
          <p className="flex items-center gap-3 text-[10px] font-bold tracking-[.18em] text-sky-300">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-teal-200 shadow-[0_0_14px_rgba(153,246,228,.8)]" />
            READY WHEN THE CAPTURE IS
          </p>
          <h2 className="mt-5 max-w-2xl text-3xl font-bold leading-tight tracking-[.04em] text-white sm:text-5xl">Bring a PCAP. Leave with an evidence-led story.</h2>
          <div className="mt-7 flex flex-wrap gap-2 text-[9px] font-bold tracking-[.14em] text-white/45">
            <span className="border border-white/15 bg-black/35 px-2.5 py-1">PCAP</span>
            <span className="border border-white/15 bg-black/35 px-2.5 py-1">NO ESP DECRYPTION</span>
            <span className="border border-teal-100/25 bg-teal-100/[.06] px-2.5 py-1 text-teal-100/70">EVIDENCE READY</span>
          </div>
        </div>
        <Link href="/workspace" className="relative z-10 mt-9 inline-flex overflow-hidden border border-teal-100/75 bg-teal-100/10 px-7 py-3.5 text-xs font-bold tracking-[.14em] text-teal-50 shadow-[0_0_34px_rgba(94,234,212,.15)] transition-all duration-300 hover:bg-teal-100 hover:text-slate-950 hover:shadow-[0_0_46px_rgba(94,234,212,.32)] lg:mt-0">
          <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/30 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
          <span className="relative">OPEN WORKSPACE</span>
        </Link>
      </div>
    </section>
  );
}
