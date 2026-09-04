import Link from "next/link";

export function LandingNavigation({ overlay = false }: { overlay?: boolean }) {
  return (
    <header className={`${overlay ? "absolute" : "relative"} inset-x-0 top-0 z-30 border-b border-white/20 bg-black/75 font-mono text-white backdrop-blur-sm`}>
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8">
        <Link href="/" className="flex items-center gap-3 text-sm font-bold tracking-[.22em]">
          <span className="grid h-7 w-7 place-items-center bg-teal-300 text-base text-slate-950">Δ</span>
          ALCHEMIST
        </Link>
        <nav className="hidden items-center gap-6 text-[10px] font-bold tracking-[.14em] text-white/65 md:flex" aria-label="Landing navigation">
          <Link className="transition hover:text-teal-200" href="/#features">CAPABILITIES</Link>
          <Link className="transition hover:text-teal-200" href="/#method">EVIDENCE</Link>
          <Link className="transition hover:text-teal-200" href="/#approach">APPROACH</Link>
          <Link className="transition hover:text-teal-200" href="/teams">TEAM</Link>
        </nav>
        <Link href="/workspace" className="border border-teal-200/60 px-3 py-2 text-[10px] font-bold tracking-[.12em] transition hover:bg-teal-200 hover:text-slate-950">
          OPEN WORKSPACE
        </Link>
      </div>
    </header>
  );
}

export function LandingFooter() {
  return (
    <footer className="relative isolate overflow-hidden border-t border-teal-200/20 bg-black px-5 py-8 font-mono text-[10px] tracking-[.12em] text-white/55 lg:px-8">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(94,234,212,.12)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.12)_1px,transparent_1px)] [background-size:42px_42px]" />
      <div className="relative z-10 mx-auto grid max-w-7xl gap-6 sm:grid-cols-[1fr_auto] sm:items-end">
        <div>
          <Link href="/" className="text-sm font-bold tracking-[.2em] text-white transition hover:text-teal-200">ALCHEMIST</Link>
          <p className="mt-2 max-w-md leading-5">Evidence-led IPsec analysis for passive captures and authorized Deep Assessment.</p>
        </div>
        <nav className="flex flex-wrap gap-x-5 gap-y-3 text-teal-200/80" aria-label="Footer navigation">
          <Link href="/#features" className="hover:text-teal-100">CAPABILITIES</Link>
          <Link href="/#approach" className="hover:text-teal-100">APPROACH</Link>
          <Link href="/teams" className="hover:text-teal-100">TEAM</Link>
          <Link href="/workspace" className="hover:text-teal-100">WORKSPACE</Link>
        </nav>
        <div className="border-t border-sky-200/15 pt-4 sm:col-span-2 sm:flex sm:justify-between">
          <span>SMART INDIA HACKATHON 2026</span>
          <span>PASSIVE · EXPLAINABLE · NO ESP DECRYPTION</span>
        </div>
      </div>
    </footer>
  );
}
