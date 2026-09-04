"use client";

import Link from "next/link";
import { LandingNavigation } from "@/components/ui/site-chrome";

export function HeroAscii() {
  return (
    <section className="relative min-h-svh overflow-hidden bg-black font-mono text-white">
      <div aria-hidden="true" className="hero-ascii-grid absolute inset-0" />
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_22%_55%,transparent_0,rgba(0,0,0,.2)_36%,rgba(0,0,0,.76)_100%)]" />

      <LandingNavigation overlay />

      <div aria-hidden="true" className="absolute left-0 top-0 z-20 h-10 w-10 border-l-2 border-t-2 border-white/35 lg:h-14 lg:w-14" />
      <div aria-hidden="true" className="absolute right-0 top-0 z-20 h-10 w-10 border-r-2 border-t-2 border-white/35 lg:h-14 lg:w-14" />
      <div aria-hidden="true" className="absolute bottom-[5vh] left-0 z-20 h-10 w-10 border-b-2 border-l-2 border-white/35 lg:h-14 lg:w-14" />
      <div aria-hidden="true" className="absolute bottom-[5vh] right-0 z-20 h-10 w-10 border-b-2 border-r-2 border-white/35 lg:h-14 lg:w-14" />

      <section className="relative z-10 mx-auto flex min-h-svh max-w-7xl items-center px-6 pb-28 pt-24 lg:px-16">
        <div className="max-w-2xl">
          <div className="mb-4 flex items-center gap-2 text-[10px] tracking-[.16em] text-white/65">
            <span className="h-px w-8 bg-white" />
            <span>001</span>
            <span className="h-px flex-1 bg-white" />
          </div>
          <h1 className="border-l border-dashed border-white/45 pl-4 text-4xl font-bold leading-[.94] tracking-[.08em] sm:text-5xl lg:text-7xl">
            READ THE POSTURE.
            <span className="mt-3 block text-white/85">NOT THE PAYLOAD.</span>
          </h1>
          <div aria-hidden="true" className="my-5 hidden h-px w-64 bg-[radial-gradient(circle,white_1px,transparent_1.5px)] bg-[size:6px_1px] opacity-55 lg:block" />
          <p className="max-w-xl text-sm leading-7 text-white/75 lg:text-base">
            Evidence-led IPsec VPN analysis that separates verified protocol facts from inference—without decrypting ESP traffic.
          </p>
          <div className="mt-7 flex flex-col gap-3 sm:flex-row">
            <Link
              href="/workspace"
              className="border border-sky-300 bg-sky-300 px-6 py-3 text-center text-xs font-bold tracking-[.12em] text-slate-950 transition hover:bg-transparent hover:text-sky-200"
            >
              START ANALYSIS
            </Link>
            <Link
              href="/workspace#workflow"
              className="border border-sky-200/70 px-6 py-3 text-center text-xs font-bold tracking-[.12em] transition hover:border-sky-200 hover:bg-sky-200 hover:text-slate-950"
            >
              VIEW WORKFLOW
            </Link>
          </div>
          <div className="mt-8 flex items-center gap-2 text-[10px] tracking-[.12em] text-white/50">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-sky-300" />
            PASSIVE · EXPLAINABLE · ESP NEVER DECRYPTED
          </div>
        </div>
      </section>

      <footer className="absolute inset-x-0 bottom-[5vh] z-20 border-y border-white/20 bg-black/35 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-3 text-[9px] tracking-[.13em] text-white/55 lg:px-8">
          <span>SYSTEM.ACTIVE</span>
          <span className="hidden sm:inline">IPSEC VPN PROTOCOL ANALYZER</span>
          <span>FRAME: ∞</span>
        </div>
      </footer>
    </section>
  );
}
