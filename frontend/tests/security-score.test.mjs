import assert from "node:assert/strict";
import test from "node:test";
import { securityScorePresentation } from "../components/dashboard/security-score.ts";

test("a score with missing configuration evidence is provisional", () => {
  assert.deepEqual(
    securityScorePresentation({ score: 97, unknown_evidence_count: 8 }),
    { assessedScore: 97, coveragePercent: 0, isProvisional: true, unknownEvidence: 8 },
  );
});

test("no evaluated controls do not display a numeric security score", () => {
  const result = securityScorePresentation({score: 0, score_available: false, coverage_percent: 0, unknown_evidence_count: 8});
  assert.equal(result.assessedScore, undefined);
  assert.equal(result.coveragePercent, 0);
  assert.equal(result.isProvisional, true);
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
