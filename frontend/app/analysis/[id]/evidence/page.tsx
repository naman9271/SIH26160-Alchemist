import { AppShell } from "../../../components/app-shell";
import { AnalysisView } from "../../../components/analysis-view";
export default async function EvidencePage({ params }: PageProps<"/analysis/[id]/evidence">) { const { id } = await params; return <AppShell analysisId={id}><AnalysisView analysisId={id} view="evidence" /></AppShell>; }
