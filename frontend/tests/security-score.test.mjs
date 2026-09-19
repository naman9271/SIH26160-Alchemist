import assert from "node:assert/strict";
import test from "node:test";
import { securityScorePresentation } from "../components/dashboard/security-score.ts";

test("a score with missing configuration evidence is provisional", () => {
  assert.deepEqual(
    securityScorePresentation({ observed_security_score: 97, score_available: true, unknown_evidence_count: 6, configuration_facts: 6, provisional: true }),
    { assessedScore: 97, coveragePercent: 0, isProvisional: true, unknownEvidence: 6, configurationFacts: 6 },
  );
});

test("a fully evidenced score is definitive", () => {
  assert.deepEqual(
    securityScorePresentation({ observed_security_score: 82, score_available: true, unknown_evidence_count: 0, configuration_facts: 6, evidence_coverage_percent: 100 }),
    { assessedScore: 82, coveragePercent: 100, isProvisional: false, unknownEvidence: 0, configurationFacts: 6 },
  );
});

test("missing coverage metadata never presents a definitive score", () => {
  const result = securityScorePresentation({ observed_security_score: 90, score_available: true });
  assert.equal(result.isProvisional, true);
  assert.equal(result.coveragePercent, undefined);
});

test("backend coverage is used when supplied", () => {
  assert.deepEqual(
    securityScorePresentation({ observed_security_score: 100, score_available: true, unknown_evidence_count: 6, configuration_facts: 6, evidence_coverage_percent: 0 }),
    { assessedScore: 100, coveragePercent: 0, isProvisional: true, unknownEvidence: 6, configurationFacts: 6 },
  );
});

test("backend provisional status is authoritative", () => {
  assert.deepEqual(
    securityScorePresentation({ observed_security_score: 85, score_available: true, unknown_evidence_count: 0, configuration_facts: 6, evidence_coverage_percent: 87, provisional: true }),
    { assessedScore: 85, coveragePercent: 87, isProvisional: true, unknownEvidence: 0, configurationFacts: 6 },
  );
});

test("an unavailable score never renders protobuf zero as a real result", () => {
  assert.deepEqual(
    securityScorePresentation({ observed_security_score: 0, score_available: false, evidence_coverage_percent: 0, provisional: true }),
    { assessedScore: undefined, coveragePercent: 0, isProvisional: true, unknownEvidence: undefined, configurationFacts: undefined },
  );
});

test("legacy snapshots remain readable", () => {
  assert.deepEqual(
    securityScorePresentation({ score: 75, coverage_percent: 50, unknown_evidence_count: 3, configuration_facts: 6 }),
    { assessedScore: 75, coveragePercent: 50, isProvisional: true, unknownEvidence: 3, configurationFacts: 6 },
  );
});
