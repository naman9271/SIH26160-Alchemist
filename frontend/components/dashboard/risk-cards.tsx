import { securityScorePresentation } from "./security-score";
import { InfoHint } from "@/components/ui/info-hint";

type Finding = {
  Title?: string;
  Severity?: string;
  Description?: string;
  Recommendation?: string;
  RuleID?: string;
  ResourceType?: string;
  ResourceID?: string;
  EvidenceProperties?: string[];
};

export function RiskCards({ value }: { value: unknown }) {
  const assessment = (value ?? {}) as {
    findings?: Finding[];
    configuration_facts?: number;
  };
  const presentation = securityScorePresentation(assessment);

  if (presentation.assessedScore === undefined) {
    return <section className="my-6 border border-amber-200/30 bg-amber-200/[.035] p-5">
      <p className="text-sm font-semibold text-amber-100">Security score unavailable</p>
      <p className="mt-2 text-sm leading-6 text-white/60">No security control could be evaluated from this capture. Use an IPsec capture containing IKE negotiation or ESP/AH traffic; gateway-only controls require authorized Deep Assessment.</p>
      {presentation.coveragePercent !== undefined && <p className="mt-3 text-xs text-white/45">Evidence coverage: {presentation.coveragePercent}%.</p>}
    </section>;
  }

  return <section className="my-6 space-y-4">
    <div className="grid gap-3 sm:grid-cols-3">
      <article className={`relative border p-5 ${presentation.isProvisional ? "border-amber-200/35" : "border-teal-200/25"}`}>
        <span className="absolute right-4 top-4"><InfoHint label="About security posture">This is a deterministic posture score based only on evaluated controls. It is not a guarantee that unobserved settings are secure.</InfoHint></span>
        <p className="pr-7 text-xs text-white/50">{presentation.isProvisional ? "Security posture · provisional" : "Security posture"}</p>
        <p className={`mt-3 text-3xl ${presentation.isProvisional ? "text-amber-100" : "text-teal-100"}`}>{presentation.assessedScore}/100</p>
        {presentation.isProvisional && <p className="mt-3 text-xs text-amber-100">Not fully verified: {presentation.coveragePercent === 0 ? "no assessment evidence was available" : "some assessment evidence was unavailable"}.</p>}
      </article>
      <article className="relative border border-white/15 p-5">
        <span className="absolute right-4 top-4"><InfoHint label="About findings">Findings are deterministic rule outcomes backed by the evidence listed below each item. Missing evidence does not become a pass.</InfoHint></span>
        <p className="pr-7 text-xs text-white/50">Findings</p>
        <p className="mt-3 text-3xl">{assessment.findings?.length ?? 0}</p>
      </article>
      <article className="relative border border-white/15 p-5">
        <span className="absolute right-4 top-4"><InfoHint label="About evidence coverage">Coverage counts every scored control that available evidence could establish, including lifecycle and metadata checks. Gateway-only facts such as replay protection may remain not evaluated in passive captures.</InfoHint></span>
        <p className="pr-7 text-xs text-white/50">Assessment evidence coverage</p>
        <p className="mt-3 text-3xl">{presentation.coveragePercent === undefined ? "Unavailable" : `${presentation.coveragePercent}%`}</p>
        <p className="mt-3 text-xs text-white/50">{presentation.unknownEvidence ?? "Unknown"} of {presentation.configurationFacts ?? "the reported"} critical configuration facts not evaluated</p>
      </article>
    </div>
    <p className="text-xs leading-6 text-white/50">The score reflects deterministic findings; coverage shows how much of the assessment could be verified. A passive capture cannot prove every gateway setting.</p>
    {!assessment.findings?.length && <p className="text-sm text-white/60">No findings were raised from the available evidence; unavailable controls still require verification.</p>}
    {assessment.findings?.map((finding, index) => <article key={`${finding.ResourceType ?? "SA"}:${finding.ResourceID ?? "unknown"}:${finding.RuleID ?? index}`} className="relative border border-amber-200/25 p-5">
      <span className="absolute right-4 top-4"><InfoHint label={`About ${finding.Title ?? "this finding"}`}>This finding is based on the evidence properties shown at the bottom of the card. Follow the remediation after confirming the affected gateway configuration.</InfoHint></span>
      <p className="pr-7 text-xs text-amber-200">{finding.Severity} · {finding.RuleID}</p>
      <h3 className="mt-3 text-lg">{finding.Title}</h3>
      {finding.ResourceID && <p className="mt-2 text-xs text-white/50">Affected {finding.ResourceType ?? "SA"}: {finding.ResourceID}</p>}
      <p className="mt-3 text-sm leading-6 text-white/60">{finding.Description}</p>
      <div className="mt-4 border-l-2 border-teal-200 pl-4"><p className="text-xs text-teal-100">HOW TO FIX</p><p className="mt-2 text-sm leading-6">{finding.Recommendation ?? "No recommendation supplied."}</p></div>
      <p className="mt-3 text-xs text-white/40">Evidence: {finding.EvidenceProperties?.join(", ") ?? "Not supplied"}</p>
    </article>)}
  </section>;
}
