import { AppShell } from "../../../components/app-shell";
import { AnalysisView } from "../../../components/analysis-view";
export default async function ReportsPage({ params }: PageProps<"/analysis/[id]/reports">) { const { id } = await params; return <AppShell analysisId={id}><AnalysisView analysisId={id} view="reports" /></AppShell>; }
