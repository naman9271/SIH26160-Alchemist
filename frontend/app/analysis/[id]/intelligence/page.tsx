import { AppShell } from "../../../components/app-shell";
import { AnalysisView } from "../../../components/analysis-view";
export default async function IntelligencePage({ params }: PageProps<"/analysis/[id]/intelligence">) { const { id } = await params; return <AppShell analysisId={id}><AnalysisView analysisId={id} view="intelligence" /></AppShell>; }
