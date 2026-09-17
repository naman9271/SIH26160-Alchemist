import { securityScorePresentation } from "./security-score";

type Finding = {Title?: string; Severity?: string; Description?: string; Recommendation?: string; RuleID?: string; EvidenceProperties?: string[]};
type Control = {rule_id: string; property: string; state: string; reason: string};

export function RiskCards({value}: {value: unknown}) {
  const assessment = (value ?? {}) as {findings?: Finding[]; controls?: Control[]};
  const presentation = securityScorePresentation(value);
  if (!value) return <p className="mt-5 text-white/50">Security assessment is not available yet.</p>;
  return <section className="my-6 space-y-4">
    <div className="grid gap-3 sm:grid-cols-3">
      <article className="border border-amber-200/35 p-5">
        <p className="text-xs text-white/50">Posture from evaluated controls</p>
        <p className="mt-3 text-3xl text-amber-100">{presentation.assessedScore === undefined ? "Not evaluated" : presentation.assessedScore + "/100"}</p>
        {presentation.isProvisional && <p className="mt-3 text-xs text-white/65">Provisional: configuration could not be fully verified.</p>}
      </article>
      <article className="border border-white/15 p-5"><p className="text-xs text-white/50">Findings</p><p className="mt-3 text-3xl">{assessment.findings?.length ?? 0}</p></article>
      <article className="border border-white/15 p-5"><p className="text-xs text-white/50">Evidence coverage</p><p className="mt-3 text-3xl">{presentation.coveragePercent === undefined ? "Unavailable" : presentation.coveragePercent + "%"}</p><p className="mt-3 text-xs text-white/50">{presentation.unknownEvidence ?? "Unknown"} unevaluated controls. Coverage is separate from ML confidence.</p></article>
    </div>
    <p className="text-xs leading-6 text-white/60">Passive captures expose protocol headers and metadata. Mode, ESP algorithms, PFS, lifetime and replay settings may require authorized gateway evidence. ESP payloads remain encrypted.</p>
    {assessment.controls && <div className="overflow-x-auto"><table className="w-full text-left text-xs"><caption className="mb-3 text-left text-sm">Control evidence coverage</caption><thead><tr><th className="p-2">Required evidence</th><th className="p-2">Outcome</th><th className="p-2">Reason</th></tr></thead><tbody>{assessment.controls.map(control => <tr key={control.rule_id} className="border-t border-white/10"><td className="p-2">{control.property}</td><td className="p-2">{control.state.replaceAll("_", " ")}</td><td className="p-2 text-white/60">{control.reason}</td></tr>)}</tbody></table></div>}
    {!assessment.findings?.length && <p className="text-sm text-white/60">No findings were raised from the available evidence. Unevaluated controls still require review.</p>}
    {assessment.findings?.map((finding,index) => <article key={finding.RuleID ?? index} className="border border-amber-200/25 p-5"><p className="text-xs text-amber-200">{finding.Severity} · {finding.RuleID}</p><h3 className="mt-3 text-lg">{finding.Title}</h3><p className="mt-3 text-sm leading-6 text-white/60">{finding.Description}</p><div className="mt-4 border-l-2 border-teal-200 pl-4"><p className="text-xs text-teal-100">HOW TO FIX</p><p className="mt-2 text-sm leading-6">{finding.Recommendation ?? "No recommendation supplied."}</p></div><p className="mt-3 text-xs text-white/40">Evidence: {finding.EvidenceProperties?.join(", ") ?? "Not supplied"}</p></article>)}
  </section>;
}
