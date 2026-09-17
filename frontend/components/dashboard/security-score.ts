export const SECURITY_CONFIGURATION_FACTS = 8;

export type SecurityScorePresentation = {
  assessedScore?: number;
  coveragePercent?: number;
  isProvisional: boolean;
  unknownEvidence?: number;
};

export function securityScorePresentation(value: unknown): SecurityScorePresentation {
  const assessment = (value ?? {}) as { score?: unknown; unknown_evidence_count?: unknown; score_available?: boolean; coverage_percent?: number };
  const assessedScore = assessment.score_available !== false && typeof assessment.score === "number" && Number.isFinite(assessment.score)
    ? assessment.score
    : undefined;
  const unknownEvidence = typeof assessment.unknown_evidence_count === "number" && Number.isFinite(assessment.unknown_evidence_count)
    ? Math.max(0, Math.floor(assessment.unknown_evidence_count))
    : undefined;
  const coveragePercent = typeof assessment.coverage_percent === "number" && Number.isFinite(assessment.coverage_percent)
    ? Math.max(0, Math.min(100, assessment.coverage_percent))
    : unknownEvidence === undefined
    ? undefined
    : Math.round((1 - Math.min(unknownEvidence, SECURITY_CONFIGURATION_FACTS) / SECURITY_CONFIGURATION_FACTS) * 100);

  return {
    assessedScore,
    coveragePercent,
    isProvisional: coveragePercent !== 100,
    unknownEvidence,
  };
}
