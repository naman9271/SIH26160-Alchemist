export const SECURITY_CONFIGURATION_FACTS = 6;

export type SecurityScorePresentation = {
  assessedScore?: number;
  coveragePercent?: number;
  isProvisional: boolean;
  unknownEvidence?: number;
};

export function securityScorePresentation(value: unknown): SecurityScorePresentation {
  const assessment = (value ?? {}) as { score?: unknown; unknown_evidence_count?: unknown; coverage_percent?: unknown };
  const assessedScore = typeof assessment.score === "number" && Number.isFinite(assessment.score)
    ? assessment.score
    : undefined;
  const unknownEvidence = typeof assessment.unknown_evidence_count === "number" && Number.isFinite(assessment.unknown_evidence_count)
    ? Math.max(0, Math.floor(assessment.unknown_evidence_count))
    : undefined;
  const suppliedCoverage = typeof assessment.coverage_percent === "number" && Number.isFinite(assessment.coverage_percent)
    ? Math.max(0, Math.min(100, Math.round(assessment.coverage_percent)))
    : undefined;
  const coveragePercent = suppliedCoverage ?? (unknownEvidence === undefined
    ? undefined
    : Math.round((1 - Math.min(unknownEvidence, SECURITY_CONFIGURATION_FACTS) / SECURITY_CONFIGURATION_FACTS) * 100));

  return {
    assessedScore,
    coveragePercent,
    isProvisional: assessedScore !== undefined && (unknownEvidence === undefined || unknownEvidence > 0),
    unknownEvidence,
  };
}
