"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ReactNode } from "react";

type AppShellProps = { children: ReactNode; analysisId?: string };

const nav = [
  ["Workspace", "/workspace"],
  ["Capabilities", "/capabilities"],
];

export function AppShell({ children, analysisId }: AppShellProps) {
  const pathname = usePathname();
  const analysisNav = analysisId ? [
    ["Overview", `/analysis/${analysisId}`],
    ["Protocol", `/analysis/${analysisId}/protocol`],
    ["Intelligence", `/analysis/${analysisId}/intelligence`],
    ["Security", `/analysis/${analysisId}/security`],
    ["Evidence", `/analysis/${analysisId}/evidence`],
    ["Reports", `/analysis/${analysisId}/reports`],
  ] : [];

  return <div className="app-frame">
    <aside className="side-rail">
      <Link href="/" className="brand-mark"><span>Δ</span><i>ALCHEMIST</i></Link>
      <div className="rail-label">Command centre</div>
      <nav className="rail-nav">
        {nav.map(([label, href]) => <Link key={href} href={href} className={pathname === href ? "active" : ""}>{label}</Link>)}
      </nav>
      {analysisNav.length > 0 && <>
        <div className="rail-label">Current analysis</div>
        <nav className="rail-nav analysis-nav">
          {analysisNav.map(([label, href]) => <Link key={href} href={href} className={pathname === href ? "active" : ""}>{label}</Link>)}
        </nav>
      </>}
      <div className="rail-footer"><span className="pulse" /> Passive analysis · v1</div>
    </aside>
    <div className="app-content">{children}</div>
  </div>;
}
