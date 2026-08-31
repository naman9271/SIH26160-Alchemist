import { AppShell } from "../../../components/app-shell";
import { AnalysisView } from "../../../components/analysis-view";
export default async function SecurityPage({ params }: PageProps<"/analysis/[id]/security">) { const { id } = await params; return <AppShell analysisId={id}><AnalysisView analysisId={id} view="security" /></AppShell>; }
