export type SecurityScorePresentation = {
  assessedScore?: number;
  coveragePercent?: number;
  isProvisional: boolean;
  unknownEvidence?: number;
  configurationFacts?: number;
};

export type SecurityScoreUnavailableCopy = {
  detail: string;
  action: string;
};

export function securityScoreUnavailableCopy(summary: unknown): SecurityScoreUnavailableCopy {
  const value = (summary ?? {}) as {
    ipsec_detected?: unknown;
    protocol?: { data_protocol?: unknown; ike_version?: unknown };
  };
  const dataProtocol = typeof value.protocol?.data_protocol === "string"
    ? value.protocol.data_protocol.trim().toUpperCase()
    : "";
  const ikeVersion = typeof value.protocol?.ike_version === "string"
    ? value.protocol.ike_version.trim()
    : "";

  if (value.ipsec_detected === true && (dataProtocol === "ESP" || dataProtocol === "AH") && !ikeVersion) {
    return {
      detail: `${dataProtocol} traffic was detected, but this capture does not contain observable IKE negotiation. ${dataProtocol} headers identify the tunnel traffic, but do not disclose the negotiated cipher, key length, authentication, DH group, PFS, replay enforcement, or lifetime.`,
      action: "Capture from before tunnel establishment so the IKE exchange is included, or run an authorized Deep Assessment on the gateway.",
    };
  }
  if (value.ipsec_detected === false) {
    return {
      detail: "No IKE, ESP, or AH traffic was detected in this capture, so no IPsec security control could be evaluated.",
      action: "Upload a capture taken on the VPN path while the tunnel is negotiating or carrying traffic.",
    };
  }
  return {
    detail: "The available evidence did not establish any security control strongly enough to calculate a score.",
    action: "Include the IKE negotiation in the capture, or run an authorized Deep Assessment for gateway-only configuration and runtime evidence.",
  };
}

export function securityScorePresentation(value: unknown): SecurityScorePresentation {
  const assessment = (value ?? {}) as {
    observed_security_score?: unknown;
    score_available?: unknown;
    evidence_coverage_percent?: unknown;
    provisional?: unknown;
    configuration_facts?: unknown;
    score?: unknown;
    coverage_percent?: unknown;
    unknown_evidence_count?: unknown;
  };
  const currentScore = typeof assessment.observed_security_score === "number" && Number.isFinite(assessment.observed_security_score)
    ? assessment.observed_security_score
    : undefined;
  const legacyScore = typeof assessment.score === "number" && Number.isFinite(assessment.score) ? assessment.score : undefined;
  const assessedScore = assessment.score_available === false ? undefined : currentScore ?? legacyScore;
  const unknownEvidence = typeof assessment.unknown_evidence_count === "number" && Number.isFinite(assessment.unknown_evidence_count)
    ? Math.max(0, Math.floor(assessment.unknown_evidence_count))
    : undefined;
  const configurationFacts = typeof assessment.configuration_facts === "number" && Number.isFinite(assessment.configuration_facts)
    ? Math.max(0, Math.floor(assessment.configuration_facts))
    : undefined;
  const currentCoverage = typeof assessment.evidence_coverage_percent === "number" && Number.isFinite(assessment.evidence_coverage_percent)
    ? assessment.evidence_coverage_percent
    : undefined;
  const legacyCoverage = typeof assessment.coverage_percent === "number" && Number.isFinite(assessment.coverage_percent)
    ? assessment.coverage_percent
    : undefined;
  const suppliedCoverage = currentCoverage ?? legacyCoverage;
  const coverageFromUnknown = unknownEvidence === undefined || !configurationFacts
    ? undefined
    : Math.round((1 - Math.min(unknownEvidence, configurationFacts) / configurationFacts) * 100);
  const coveragePercent = suppliedCoverage === undefined
    ? coverageFromUnknown
    : Math.max(0, Math.min(100, Math.round(suppliedCoverage)));

  return {
    assessedScore,
    coveragePercent,
    isProvisional: assessment.provisional === true || (assessedScore !== undefined && (coveragePercent === undefined || coveragePercent < 100)),
    unknownEvidence,
    configurationFacts,
  };
}
