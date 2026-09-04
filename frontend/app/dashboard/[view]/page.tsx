import { DashboardShell } from "@/components/dashboard/dashboard-shell";

export default async function DashboardViewPage({ params }: { params: Promise<{ view: string }> }) {
  const { view } = await params;
  return <DashboardShell view={view} />;
}
