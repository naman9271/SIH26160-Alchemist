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
    if (window.UnicornStudio?.isInitialized) return;

    const existing = document.querySelector<HTMLScriptElement>('script[data-unicorn-studio="true"]');
    const initialize = () => {
      if (!window.UnicornStudio?.isInitialized) {
        window.UnicornStudio?.init();
        if (window.UnicornStudio) window.UnicornStudio.isInitialized = true;
      }
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

      <div className="relative z-10 flex min-h-svh items-center pt-16" style={{ marginTop: "5vh" }}>
        <div className="mx-auto w-full max-w-7xl px-6 lg:ml-[10%] lg:px-16">
          <div className="relative max-w-lg">
            <div className="mb-3 flex items-center gap-2 opacity-60"><span className="h-px w-8 bg-white" /><span className="text-[10px] tracking-wider">001</span><span className="h-px flex-1 bg-white" /></div>
            <div className="relative">
              <div aria-hidden="true" className="hero-ascii-dither absolute -left-3 top-0 hidden h-full w-1 opacity-40 lg:block" />
              <h1 className="mb-3 text-2xl font-bold leading-tight tracking-[.1em] lg:mb-4 lg:text-5xl">READ THE EVIDENCE<span className="mt-1 block opacity-90 lg:mt-2">NOT THE PAYLOAD</span></h1>
            </div>
            <div aria-hidden="true" className="mb-3 hidden gap-1 opacity-40 lg:flex">{Array.from({ length: 40 }, (_, index) => <span key={index} className="h-0.5 w-0.5 rounded-full bg-white" />)}</div>
            <div className="relative"><p className="mb-5 text-xs leading-relaxed text-gray-300/80 lg:mb-6 lg:text-base">Turn passive IPsec VPN captures into explainable protocol facts and deterministic security findings—without decrypting ESP traffic.</p><span aria-hidden="true" className="absolute -right-4 top-1/2 hidden h-3 w-3 -translate-y-1/2 border border-white/30 lg:block" /></div>
            <div className="flex flex-col gap-3 lg:flex-row lg:gap-4">
              <Link href="/workspace" className="group relative border border-white px-5 py-2 text-center text-xs transition-all duration-200 hover:bg-white hover:text-black lg:px-6 lg:py-2.5 lg:text-sm"><span className="absolute -left-1 -top-1 hidden h-2 w-2 border-l border-t border-white opacity-0 transition-opacity group-hover:opacity-100 lg:block" />START ANALYSIS</Link>
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
