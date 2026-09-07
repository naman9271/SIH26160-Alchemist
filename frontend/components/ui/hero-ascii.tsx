"use client";

import Link from "next/link";

const signalBars = [7, 15, 10, 22, 14, 28, 18, 9];

function GhostGraphic() {
  return (
    <svg viewBox="0 0 231 289" className="w-full max-w-sm text-slate-950" aria-label="Alchemist signal">
      <path d="M230.809 115.385V249.411C230.809 269.923 214.985 287.282 194.495 288.411C184.544 288.949 175.364 285.718 168.26 280C159.746 273.154 147.769 273.461 139.178 280.23C132.638 285.384 124.381 288.462 115.379 288.462C106.377 288.462 98.1451 285.384 91.6055 280.23C82.912 273.385 70.9353 273.385 62.2415 280.23C55.7532 285.334 47.598 288.411 38.7246 288.462C17.4132 288.615 0 270.667 0 249.359V115.385C0 51.6667 51.6756 0 115.404 0C179.134 0 230.809 51.6756 230.809 115.385Z" fill="#0f766e" />
      <path d="M230.809 115.385V249.411C230.809 269.923 214.985 287.282 194.495 288.411C184.544 288.949 175.364 285.718 168.26 280C159.746 273.154 147.769 273.461 139.178 280.23C132.638 285.384 124.381 288.462 115.379 288.462C106.377 288.462 98.1451 285.384 91.6055 280.23C82.912 273.385 70.9353 273.385 62.2415 280.23C55.7532 285.334 47.598 288.411 38.7246 288.462C17.4132 288.615 0 270.667 0 249.359V115.385C0 51.6667 51.6756 0 115.404 0C179.134 0 230.809 51.6756 230.809 115.385Z" fill="none" stroke="rgba(153,246,228,.75)" strokeWidth="1.5" />
      <ellipse cx="80" cy="120" rx="20" ry="30" fill="currentColor" />
      <ellipse cx="150" cy="120" rx="20" ry="30" fill="currentColor" />
    </svg>
  );
}

export function HeroAscii() {
  return (
    <section className="hero-ascii relative min-h-svh overflow-hidden bg-black font-mono text-white">
      <div aria-hidden="true" className="absolute left-0 top-0 z-20 h-8 w-8 border-l-2 border-t-2 border-white/30 lg:h-12 lg:w-12" />
      <div aria-hidden="true" className="absolute right-0 top-0 z-20 h-8 w-8 border-r-2 border-t-2 border-white/30 lg:h-12 lg:w-12" />
      <div aria-hidden="true" className="absolute bottom-[5vh] left-0 z-20 h-8 w-8 border-b-2 border-l-2 border-white/30 lg:h-12 lg:w-12" />
      <div aria-hidden="true" className="absolute bottom-[5vh] right-0 z-20 h-8 w-8 border-b-2 border-r-2 border-white/30 lg:h-12 lg:w-12" />

      <div className="relative z-10 flex min-h-svh items-start pt-[4vh] sm:pt-[5vh] lg:items-center lg:pt-0">
        <div className="mx-auto grid w-full max-w-7xl items-center gap-8 px-5 lg:grid-cols-[minmax(0,1fr)_minmax(17rem,.58fr)] lg:px-12">
          <div className="relative max-w-3xl">
            <div className="mb-5 flex items-center gap-3 text-[10px] font-bold tracking-[.2em] text-teal-100/70"><span className="h-px w-10 bg-teal-100/70" /><span>001 / IPSEC SENTINEL TWIN</span><span className="h-px flex-1 bg-white/20" /></div>
            <div className="relative">
              <div aria-hidden="true" className="hero-ascii-dither absolute -left-4 top-0 hidden h-full w-1 opacity-55 lg:block" />
              <h1 className="mb-5 text-3xl font-bold leading-[1.04] tracking-[.08em] text-white drop-shadow-[0_0_28px_rgba(255,255,255,.16)] sm:text-4xl lg:mb-6 lg:text-6xl">
                READ THE
                <span className="block text-teal-100">EVIDENCE</span>
                <span className="mt-2 block text-white/82 lg:mt-3">NOT THE PAYLOAD</span>
              </h1>
            </div>
            <div aria-hidden="true" className="mb-5 hidden gap-1 opacity-45 lg:flex">{Array.from({ length: 48 }, (_, index) => <span key={index} className="h-0.5 w-0.5 rounded-full bg-teal-100" />)}</div>
            <div className="relative border-l border-teal-100/35 pl-4"><p className="mb-5 max-w-2xl text-sm leading-7 text-gray-200/82 lg:text-base lg:leading-7">Turn passive IPsec VPN captures into explainable protocol facts and deterministic security findings—without decrypting ESP traffic.</p><span aria-hidden="true" className="absolute -right-4 top-1/2 hidden h-3 w-3 -translate-y-1/2 border border-teal-100/45 lg:block" /></div>
            <div className="mb-7 flex flex-wrap gap-2 text-[9px] font-bold tracking-[.13em] text-white/45">
              <span className="border border-white/15 bg-black/30 px-2.5 py-1">IKE</span>
              <span className="border border-white/15 bg-black/30 px-2.5 py-1">ESP</span>
              <span className="border border-white/15 bg-black/30 px-2.5 py-1">AH</span>
              <span className="border border-teal-100/25 bg-teal-100/[.06] px-2.5 py-1 text-teal-100/70">NO DECRYPTION</span>
            </div>
            <div className="flex flex-col gap-3 lg:flex-row lg:gap-4">
              <Link href="/workspace" className="group relative overflow-hidden border border-white/70 bg-white/10 px-6 py-3 text-center text-xs font-bold tracking-[.16em] text-white shadow-[0_0_28px_rgba(255,255,255,.12)] backdrop-blur-sm transition-all duration-300 hover:border-teal-200 hover:bg-teal-200/15 hover:text-teal-100 hover:shadow-[0_0_38px_rgba(94,234,212,.28)] lg:px-8 lg:py-3.5 lg:text-sm"><span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-teal-100/25 to-transparent transition-transform duration-700 group-hover:translate-x-full" /><span className="absolute -left-1 -top-1 hidden h-3 w-3 border-l border-t border-white/70 group-hover:border-teal-100 lg:block" /><span className="absolute -bottom-1 -right-1 hidden h-3 w-3 border-b border-r border-white/70 group-hover:border-teal-100 lg:block" /><span className="relative">START ANALYSIS</span></Link>
              <Link href="/dashboard" className="group relative overflow-hidden border border-white/70 bg-white/10 px-6 py-3 text-center text-xs font-bold tracking-[.16em] text-white shadow-[0_0_28px_rgba(255,255,255,.12)] backdrop-blur-sm transition-all duration-300 hover:border-teal-200 hover:bg-teal-200/15 hover:text-teal-100 hover:shadow-[0_0_38px_rgba(94,234,212,.28)] focus-visible:border-teal-200 focus-visible:bg-teal-200/15 focus-visible:text-teal-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-100/70 lg:px-8 lg:py-3.5 lg:text-sm"><span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-teal-100/25 to-transparent transition-transform duration-700 group-hover:translate-x-full group-focus-visible:translate-x-full" /><span className="absolute -left-1 -top-1 hidden h-3 w-3 border-l border-t border-white/70 group-hover:border-teal-100 group-focus-visible:border-teal-100 lg:block" /><span className="absolute -bottom-1 -right-1 hidden h-3 w-3 border-b border-r border-white/70 group-hover:border-teal-100 group-focus-visible:border-teal-100 lg:block" /><span className="relative">LEARN MORE</span></Link>
            </div>
            <div className="mt-6 hidden items-center gap-2 opacity-40 lg:flex"><span className="text-[9px]">∞</span><span className="h-px flex-1 bg-white" /><span className="text-[9px]">IPSEC SENTINEL</span></div>
          </div>
          <div className="hidden min-h-[26rem] place-items-center lg:grid" aria-hidden="true">
            <GhostGraphic />
          </div>
        </div>
      </div>

      <footer className="absolute inset-x-0 bottom-[5vh] z-20 border-y border-white/20 bg-black/40 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-2 text-[8px] text-white/50 lg:px-8 lg:py-3 lg:text-[9px]">
          <div className="flex items-center gap-3 lg:gap-6"><span className="hidden lg:inline">SYSTEM.ACTIVE</span><span className="lg:hidden">SYS.ACT</span><div className="hidden items-end gap-1 lg:flex">{signalBars.map((height, index) => <span key={index} className="w-1 bg-white/30" style={{ height }} />)}</div><span>V1.0.0</span></div>
          <div className="flex items-center gap-2 lg:gap-4"><span className="hidden lg:inline">◐ RENDERING</span><span className="flex gap-1"><i className="h-1 w-1 animate-pulse rounded-full bg-white/60" /><i className="h-1 w-1 animate-pulse rounded-full bg-white/40 [animation-delay:200ms]" /><i className="h-1 w-1 animate-pulse rounded-full bg-white/20 [animation-delay:400ms]" /></span><span className="hidden lg:inline">FRAME: ∞</span></div>
        </div>
      </footer>
    </section>
  );
}
