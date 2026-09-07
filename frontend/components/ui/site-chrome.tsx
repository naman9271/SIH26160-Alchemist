"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { FooterBackgroundGradient, TextHoverEffect } from "@/components/ui/hover-footer";

export function LandingNavigation({ overlay = false }: { overlay?: boolean }) {
  const [isOpen, setIsOpen] = useState(false);
  const [isCompact, setIsCompact] = useState(false);
  const navLinkClass = "border border-transparent px-2.5 py-1.5 text-[10px] font-bold tracking-[.13em] text-teal-100/70 transition-all duration-300 hover:border-teal-200/35 hover:bg-teal-200/[.055] hover:text-teal-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-200/70";
  const mobileNavLinkClass = "block border border-transparent px-3 py-2.5 text-[10px] font-bold tracking-[.13em] text-teal-100/70 transition-colors hover:border-teal-200/30 hover:bg-teal-200/[.055] hover:text-teal-50";

  useEffect(() => {
    const updateCompactState = () => setIsCompact(window.scrollY > 24);
    updateCompactState();
    window.addEventListener("scroll", updateCompactState, { passive: true });
    return () => window.removeEventListener("scroll", updateCompactState);
  }, []);

  return (
    <header className={`${overlay ? "absolute" : "sticky"} inset-x-0 top-0 z-30 font-mono text-white transition-[padding] duration-300 ${isCompact ? "px-3 pt-2 sm:px-5" : ""}`}>
      <div className={`mx-auto flex items-center justify-between gap-4 border-b border-teal-200/20 bg-black/90 px-4 backdrop-blur-sm transition-all duration-300 sm:px-6 lg:px-8 ${isCompact ? "h-11 max-w-6xl border border-teal-200/25 shadow-[0_10px_28px_rgba(0,0,0,.4)]" : "h-13 max-w-none"}`}>
        <Link href="/" aria-label="Alchemist home" className="shrink-0 border border-transparent px-1.5 py-1 text-white/80 transition-all duration-300 hover:border-teal-200/40 hover:bg-teal-200/[.06] hover:text-teal-100"><span className="text-base font-bold italic tracking-widest [transform:skewX(-12deg)] sm:text-lg">ALCHEMIST</span></Link>
        <nav className="hidden items-center gap-2 xl:flex" aria-label="Primary navigation">
          <Link className={navLinkClass} href="/#features">CAPABILITIES</Link>
          <Link className={navLinkClass} href="/dashboard">DASHBOARD</Link>
          <Link className={navLinkClass} href="/dashboard/evidence">EVIDENCE</Link>
          <Link className={navLinkClass} href="/dashboard/findings">FINDINGS</Link>
          <Link className={navLinkClass} href="/dashboard/reports">REPORTS</Link>
        </nav>
        <div className="flex items-center gap-2">
          <Link href="/workspace" className="border border-teal-200/55 bg-teal-200/[.07] px-3 py-1.5 text-[10px] font-bold tracking-[.13em] text-teal-50 transition-all duration-300 hover:bg-teal-200/15 hover:shadow-[0_0_22px_rgba(94,234,212,.18)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-teal-200">OPEN WORKSPACE</Link>
          <button type="button" onClick={() => setIsOpen((open) => !open)} aria-expanded={isOpen} aria-controls="mobile-navigation" className="grid h-8 w-8 place-items-center border border-teal-200/25 text-teal-100/75 transition-colors hover:bg-teal-200/[.07] hover:text-teal-50 xl:hidden"><span className="sr-only">Toggle navigation</span><span aria-hidden="true" className="text-base leading-none">{isOpen ? "×" : "☰"}</span></button>
        </div>
      </div>
      {isOpen && <nav id="mobile-navigation" className={`mx-auto border border-t-0 border-teal-200/20 bg-black/95 px-4 py-3 shadow-xl backdrop-blur-sm xl:hidden ${isCompact ? "max-w-6xl" : "max-w-none"}`} aria-label="Mobile navigation"><div className="mx-auto grid max-w-7xl gap-1"><Link onClick={() => setIsOpen(false)} className={mobileNavLinkClass} href="/#features">CAPABILITIES</Link><Link onClick={() => setIsOpen(false)} className={mobileNavLinkClass} href="/dashboard">DASHBOARD</Link><Link onClick={() => setIsOpen(false)} className={mobileNavLinkClass} href="/dashboard/evidence">EVIDENCE</Link><Link onClick={() => setIsOpen(false)} className={mobileNavLinkClass} href="/dashboard/findings">FINDINGS</Link><Link onClick={() => setIsOpen(false)} className={mobileNavLinkClass} href="/dashboard/reports">REPORTS</Link></div></nav>}
    </header>
  );
}

export function LandingFooter() {
  const footerButtons = [
    ["CAPABILITIES", "/#features"],
    ["APPROACH", "/#approach"],
    ["DASHBOARD", "/dashboard"],
    ["EVIDENCE", "/dashboard/evidence"],
    ["FINDINGS", "/dashboard/findings"],
    ["REPORTS", "/dashboard/reports"],
    ["API STATUS", "/dashboard/health"],
  ] as const;

  return (
    <footer className="relative isolate overflow-hidden border-t border-teal-200/20 bg-black px-5 py-8 font-mono text-[10px] tracking-[.12em] text-white/55 lg:px-8 lg:py-12">
      <FooterBackgroundGradient />
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 z-0 bg-[linear-gradient(rgba(94,234,212,.12)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.12)_1px,transparent_1px)] [background-size:42px_42px] opacity-55" />
      <div className="relative z-10 mx-auto grid max-w-7xl gap-5 lg:grid-cols-[minmax(0,0.85fr)_minmax(34rem,1.15fr)] lg:items-start">
        <div className="max-w-md">
          <Link href="/" className="inline-flex border border-teal-200/25 bg-teal-200/[.035] px-3 py-1.5 text-white transition-all duration-300 hover:border-teal-100/60 hover:text-teal-100 hover:shadow-[0_0_28px_rgba(94,234,212,.16)]"><span className="text-xl font-bold italic tracking-widest [transform:skewX(-12deg)] lg:text-2xl">ALCHEMIST</span></Link>
          <p className="mt-2 leading-5 text-white/52">Evidence-led IPsec analysis for passive captures and authorized Deep Assessment.</p>
        </div>
        <nav className="grid w-full grid-cols-1 gap-2 border border-teal-200/10 bg-black/25 p-2 sm:grid-cols-3" aria-label="Footer navigation">
          {footerButtons.map(([label, href]) => (
            <Link
              key={label}
              href={href}
              className="flex min-h-9 items-center border border-teal-200/20 bg-black/35 px-3 py-1.5 text-[9px] font-bold tracking-[.13em] text-teal-100/70 transition-all duration-300 hover:border-teal-100/55 hover:bg-teal-100/[.08] hover:text-teal-50 hover:shadow-[0_0_22px_rgba(94,234,212,.14)]"
            >
              {label}
            </Link>
          ))}
          <Link
            href="/workspace"
            className="flex min-h-9 items-center border border-teal-200/20 bg-black/35 px-3 py-1.5 text-[9px] font-bold tracking-[.13em] text-teal-100/70 transition-all duration-300 hover:border-teal-100/55 hover:bg-teal-100/[.08] hover:text-teal-50 hover:shadow-[0_0_22px_rgba(94,234,212,.14)]"
          >
            OPEN WORKSPACE
          </Link>
        </nav>
        <div className="pointer-events-auto hidden h-56 border-y border-teal-200/10 lg:col-span-2 lg:block">
          <TextHoverEffect text="ALCHEMIST" className="h-full w-full" />
        </div>
        <div className="border-t border-sky-200/15 pt-3 lg:col-span-2 sm:flex sm:justify-between">
          <span>EVIDENCE WORKSPACE</span>
          <span>PASSIVE · EXPLAINABLE · NO ESP DECRYPTION</span>
        </div>
      </div>
    </footer>
  );
}
