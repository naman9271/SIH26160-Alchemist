import Link from "next/link";

export function LandingNavigation({ overlay = false }: { overlay?: boolean }) {
  return (
    <header className={`${overlay ? "absolute" : "relative"} inset-x-0 top-0 z-30 border-b border-white/20 bg-black/75 font-mono text-white backdrop-blur-sm`}>
      <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 lg:px-8">
        <Link href="/" className="flex items-center gap-3 text-sm font-bold tracking-[.22em]">
          <span className="grid h-7 w-7 place-items-center bg-white text-base text-black">Δ</span>
          ALCHEMIST
        </Link>
        <nav className="hidden items-center gap-6 text-[10px] font-bold tracking-[.14em] text-white/65 md:flex" aria-label="Landing navigation">
          <Link className="transition hover:text-white" href="/#method">METHOD</Link>
          <Link className="transition hover:text-white" href="/#evidence">EVIDENCE</Link>
          <Link className="transition hover:text-white" href="/#scope">SCOPE</Link>
        </nav>
        <Link href="/workspace" className="border border-white/60 px-3 py-2 text-[10px] font-bold tracking-[.12em] transition hover:bg-white hover:text-black">
          OPEN WORKSPACE
        </Link>
      </div>
    </header>
  );
}

export function LandingFooter() {
  return (
    <footer className="border-t border-white/20 bg-black px-5 py-8 font-mono text-[10px] tracking-[.12em] text-white/55 lg:px-8">
      <div className="mx-auto flex max-w-7xl flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <span>ALCHEMIST · IPSEC EVIDENCE WORKSPACE</span>
        <span>SMART INDIA HACKATHON 2026</span>
        <span>PASSIVE · EXPLAINABLE · NO ESP DECRYPTION</span>
      </div>
    </footer>
  );
}
