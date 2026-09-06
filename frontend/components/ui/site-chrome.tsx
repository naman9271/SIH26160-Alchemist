import Link from "next/link";
import { FooterBackgroundGradient, TextHoverEffect } from "@/components/ui/hover-footer";

export function LandingNavigation({ overlay = false }: { overlay?: boolean }) {
  const navLinkClass = "rounded-sm border border-transparent px-2.5 py-2 text-[10px] font-bold tracking-[.15em] text-white/68 transition-all duration-300 hover:border-teal-200/35 hover:bg-teal-200/[.055] hover:text-teal-100 hover:shadow-[0_0_24px_rgba(94,234,212,.16)]";

  return (
    <header className={`${overlay ? "absolute" : "relative"} inset-x-0 top-0 z-30 border-b border-white/20 bg-black/75 font-mono text-white backdrop-blur-sm`}>
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-5 px-4 py-3.5 lg:px-8 lg:py-4">
        <Link href="/" className="shrink-0 rounded-sm border border-transparent px-2.5 py-2 text-[10px] font-bold tracking-[.16em] text-white/78 transition-all duration-300 hover:border-teal-200/40 hover:bg-teal-200/[.06] hover:text-teal-100 hover:shadow-[0_0_24px_rgba(94,234,212,.18)]">HOME</Link>
        <nav className="hidden items-center gap-2 xl:flex" aria-label="Primary navigation">
          <Link className={navLinkClass} href="/#features">CAPABILITIES</Link>
          <Link className={navLinkClass} href="/dashboard">DASHBOARD</Link>
          <Link className={navLinkClass} href="/dashboard/evidence">EVIDENCE</Link>
          <Link className={navLinkClass} href="/dashboard/findings">FINDINGS</Link>
          <Link className={navLinkClass} href="/dashboard/reports">REPORTS</Link>
        </nav>
        <Link href="/workspace" className="group relative shrink-0 overflow-hidden border border-teal-100/65 bg-teal-100/[.045] px-4 py-2.5 text-[10px] font-bold tracking-[.14em] text-teal-50 shadow-[0_0_22px_rgba(94,234,212,.12)] transition-all duration-300 hover:border-teal-100 hover:bg-teal-100 hover:text-slate-950 hover:shadow-[0_0_34px_rgba(94,234,212,.28)]"><span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/35 to-transparent transition-transform duration-700 group-hover:translate-x-full" /><span className="relative">OPEN WORKSPACE</span></Link>
      </div>
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
    <footer className="relative isolate overflow-hidden border-t border-teal-200/20 bg-black px-5 py-5 font-mono text-[10px] tracking-[.12em] text-white/55 lg:px-8 lg:py-6">
      <FooterBackgroundGradient />
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 z-0 bg-[linear-gradient(rgba(94,234,212,.12)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.12)_1px,transparent_1px)] [background-size:42px_42px] opacity-55" />
      <div className="relative z-10 mx-auto grid max-w-7xl gap-5 lg:grid-cols-[minmax(0,0.85fr)_minmax(34rem,1.15fr)] lg:items-start">
        <div className="max-w-md">
          <Link href="/" className="inline-flex border border-teal-200/25 bg-teal-200/[.035] px-3 py-1.5 text-sm font-bold tracking-[.2em] text-white transition-all duration-300 hover:border-teal-100/60 hover:text-teal-100 hover:shadow-[0_0_28px_rgba(94,234,212,.16)]">IPSEC SENTINEL</Link>
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
            className="group relative flex min-h-9 items-center overflow-hidden border border-teal-100/60 bg-teal-100/[.08] px-3 py-1.5 text-[9px] font-bold tracking-[.13em] text-teal-50 transition-all duration-300 hover:bg-teal-100 hover:text-slate-950 hover:shadow-[0_0_28px_rgba(94,234,212,.24)]"
          >
            <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/35 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
            <span className="relative">OPEN WORKSPACE</span>
          </Link>
        </nav>
        <div className="pointer-events-auto hidden h-24 border-y border-teal-200/10 lg:col-span-2 lg:block">
          <TextHoverEffect text="SENTINEL" className="h-full w-full" />
        </div>
        <div className="border-t border-sky-200/15 pt-3 lg:col-span-2 sm:flex sm:justify-between">
          <span>EVIDENCE WORKSPACE</span>
          <span>PASSIVE · EXPLAINABLE · NO ESP DECRYPTION</span>
        </div>
      </div>
    </footer>
  );
}
