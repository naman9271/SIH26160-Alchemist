import type { ReactNode } from "react";

type InfoHintProps = { label: string; children: ReactNode };

// CSS-only disclosure keeps guidance available on hover, keyboard focus, and
// touch focus without hiding analysis content behind a modal.
export function InfoHint({ label, children }: InfoHintProps) {
  return <span className="group/info relative inline-flex">
    <button type="button" aria-label={label} className="grid h-5 w-5 place-items-center rounded-full border border-teal-100/45 bg-black/60 text-[11px] font-bold leading-none text-teal-100 transition hover:border-teal-100 hover:bg-teal-200 hover:text-slate-950 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-100">?</button>
    <span role="tooltip" className="pointer-events-none absolute right-0 top-7 z-30 w-64 origin-top-right border border-teal-100/30 bg-[#071018] p-3 text-left text-[11px] font-normal leading-5 tracking-normal text-white/80 opacity-0 shadow-xl transition duration-150 group-hover/info:opacity-100 group-focus-within/info:opacity-100">{children}</span>
  </span>;
}
