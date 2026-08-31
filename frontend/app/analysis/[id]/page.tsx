import { AppShell } from "../../components/app-shell";
import { AnalysisView } from "../../components/analysis-view";
export default async function AnalysisPage({ params }: PageProps<"/analysis/[id]">) { const { id } = await params; return <AppShell analysisId={id}><AnalysisView analysisId={id} view="overview" /></AppShell>; }
