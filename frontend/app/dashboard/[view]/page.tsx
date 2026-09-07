import { Suspense } from "react";
import { DashboardShell } from "@/components/dashboard/dashboard-shell";

export default async function DashboardViewPage({ params }: { params: Promise<{ view: string }> }) {
  const { view } = await params;
  return (
    <Suspense fallback={<div className="min-h-svh bg-[var(--landing-canvas)]" />}>
      <DashboardShell view={view} />
    </Suspense>
  );
}
