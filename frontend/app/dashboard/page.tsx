import { Suspense } from "react";
import { DashboardShell } from "@/components/dashboard/dashboard-shell";

export default function DashboardPage() {
  return (
    <Suspense fallback={<div className="min-h-svh bg-black" />}>
      <DashboardShell />
    </Suspense>
  );
}
