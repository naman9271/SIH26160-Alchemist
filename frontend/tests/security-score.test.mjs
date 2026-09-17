import assert from "node:assert/strict";
import test from "node:test";
import { securityScorePresentation } from "../components/dashboard/security-score.ts";

test("a score with missing configuration evidence is provisional", () => {
  assert.deepEqual(
    securityScorePresentation({ score: 97, unknown_evidence_count: 6 }),
    { assessedScore: 97, coveragePercent: 0, isProvisional: true, unknownEvidence: 6 },
  );
});

test("a fully evidenced score is definitive", () => {
  assert.deepEqual(
    securityScorePresentation({ score: 82, unknown_evidence_count: 0 }),
    { assessedScore: 82, coveragePercent: 100, isProvisional: false, unknownEvidence: 0 },
  );
});

test("missing coverage metadata never presents a definitive score", () => {
  const result = securityScorePresentation({ score: 90 });
  assert.equal(result.isProvisional, true);
  assert.equal(result.coveragePercent, undefined);
});

test("backend coverage is used when supplied", () => {
  assert.deepEqual(
    securityScorePresentation({ score: 100, unknown_evidence_count: 6, coverage_percent: 0 }),
    { assessedScore: 100, coveragePercent: 0, isProvisional: true, unknownEvidence: 6 },
  );
});
