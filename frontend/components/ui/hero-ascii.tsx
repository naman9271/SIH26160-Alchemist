"use client";

import Link from "next/link";
import { useEffect } from "react";

declare global {
  interface Window {
    UnicornStudio?: { init: () => void; isInitialized?: boolean };
  }
}

const signalBars = [7, 15, 10, 22, 14, 28, 18, 9];

export function HeroAscii() {
  useEffect(() => {
    const existing = document.querySelector<HTMLScriptElement>('script[data-unicorn-studio="true"]');
    const initialize = () => {
      window.UnicornStudio?.init();
    };

    if (existing) {
      existing.addEventListener("load", initialize, { once: true });
      initialize();
      return () => existing.removeEventListener("load", initialize);
    }

    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/gh/hiunicornstudio/unicornstudio.js@v1.4.33/dist/unicornStudio.umd.js";
    script.async = true;
    script.dataset.unicornStudio = "true";
    script.addEventListener("load", initialize, { once: true });
    document.head.appendChild(script);
    return () => script.removeEventListener("load", initialize);
  }, []);

  return (
    <section className="hero-ascii relative min-h-svh overflow-hidden bg-black font-mono text-white">
      <div className="absolute inset-0 hidden lg:block" aria-hidden="true">
        <div data-us-project="whwOGlfJ5Rz2rHaEUgHl" className="h-full w-full min-h-svh" />
      </div>
      <div className="hero-ascii-stars absolute inset-0 lg:hidden" aria-hidden="true" />

      <div aria-hidden="true" className="absolute left-0 top-0 z-20 h-8 w-8 border-l-2 border-t-2 border-white/30 lg:h-12 lg:w-12" />
      <div aria-hidden="true" className="absolute right-0 top-0 z-20 h-8 w-8 border-r-2 border-t-2 border-white/30 lg:h-12 lg:w-12" />
      <div aria-hidden="true" className="absolute bottom-[5vh] left-0 z-20 h-8 w-8 border-b-2 border-l-2 border-white/30 lg:h-12 lg:w-12" />
      <div aria-hidden="true" className="absolute bottom-[5vh] right-0 z-20 h-8 w-8 border-b-2 border-r-2 border-white/30 lg:h-12 lg:w-12" />

      <div className="relative z-10 flex min-h-svh items-start pt-[6vh] sm:pt-[7vh] lg:pt-[7vh]">
        <div className="mx-auto w-full max-w-7xl px-5 lg:ml-[2%] lg:px-12">
          <div className="relative max-w-3xl">
            <div className="mb-5 flex items-center gap-3 text-[10px] font-bold tracking-[.2em] text-teal-100/70"><span className="h-px w-10 bg-teal-100/70" /><span>001 / IPSEC SENTINEL TWIN</span><span className="h-px flex-1 bg-white/20" /></div>
            <div className="relative">
              <div aria-hidden="true" className="hero-ascii-dither absolute -left-4 top-0 hidden h-full w-1 opacity-55 lg:block" />
              <h1 className="mb-5 text-4xl font-bold leading-[1.04] tracking-[.1em] text-white drop-shadow-[0_0_28px_rgba(255,255,255,.16)] sm:text-5xl lg:mb-6 lg:text-7xl">
                READ THE
                <span className="block text-teal-100">EVIDENCE</span>
                <span className="mt-2 block text-white/82 lg:mt-3">NOT THE PAYLOAD</span>
              </h1>
            </div>
            <div aria-hidden="true" className="mb-5 hidden gap-1 opacity-45 lg:flex">{Array.from({ length: 48 }, (_, index) => <span key={index} className="h-0.5 w-0.5 rounded-full bg-teal-100" />)}</div>
            <div className="relative border-l border-teal-100/35 pl-4"><p className="mb-5 max-w-2xl text-sm leading-7 text-gray-200/82 lg:text-lg lg:leading-8">Turn passive IPsec VPN captures into explainable protocol facts and deterministic security findings—without decrypting ESP traffic.</p><span aria-hidden="true" className="absolute -right-4 top-1/2 hidden h-3 w-3 -translate-y-1/2 border border-teal-100/45 lg:block" /></div>
            <div className="mb-7 flex flex-wrap gap-2 text-[9px] font-bold tracking-[.13em] text-white/45">
              <span className="border border-white/15 bg-black/30 px-2.5 py-1">IKE</span>
              <span className="border border-white/15 bg-black/30 px-2.5 py-1">ESP</span>
              <span className="border border-white/15 bg-black/30 px-2.5 py-1">AH</span>
              <span className="border border-teal-100/25 bg-teal-100/[.06] px-2.5 py-1 text-teal-100/70">NO DECRYPTION</span>
            </div>
            <div className="flex flex-col gap-3 lg:flex-row lg:gap-4">
              <Link href="/workspace" className="group relative overflow-hidden border border-white/70 bg-white/10 px-6 py-3 text-center text-xs font-bold tracking-[.16em] text-white shadow-[0_0_28px_rgba(255,255,255,.12)] backdrop-blur-sm transition-all duration-300 hover:border-teal-200 hover:bg-teal-200/15 hover:text-teal-100 hover:shadow-[0_0_38px_rgba(94,234,212,.28)] lg:px-8 lg:py-3.5 lg:text-sm"><span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-teal-100/25 to-transparent transition-transform duration-700 group-hover:translate-x-full" /><span className="absolute -left-1 -top-1 hidden h-3 w-3 border-l border-t border-white/70 group-hover:border-teal-100 lg:block" /><span className="absolute -bottom-1 -right-1 hidden h-3 w-3 border-b border-r border-white/70 group-hover:border-teal-100 lg:block" /><span className="relative">START ANALYSIS</span></Link>
              <Link href="/#features" className="border border-white px-5 py-2 text-center text-xs transition-all duration-200 hover:bg-white hover:text-black lg:px-6 lg:py-2.5 lg:text-sm">LEARN MORE</Link>
            </div>
            <div className="mt-6 hidden items-center gap-2 opacity-40 lg:flex"><span className="text-[9px]">∞</span><span className="h-px flex-1 bg-white" /><span className="text-[9px]">ALCHEMIST</span></div>
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
