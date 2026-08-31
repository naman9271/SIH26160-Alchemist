import { AppShell } from "../../../components/app-shell";
import { AnalysisView } from "../../../components/analysis-view";
export default async function ProtocolPage({ params }: PageProps<"/analysis/[id]/protocol">) { const { id } = await params; return <AppShell analysisId={id}><AnalysisView analysisId={id} view="protocol" /></AppShell>; }
