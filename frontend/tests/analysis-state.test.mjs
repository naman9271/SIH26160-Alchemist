import assert from "node:assert/strict";
import test from "node:test";
import { analysisPhase } from "../app/workspace/analysis-state.ts";

for (const prefix of ["ANALYSIS_STATE_", ""]) {
  for (const [state, expected] of Object.entries({
    QUEUED: "running", RUNNING: "running", COMPLETED: "complete",
    FAILED: "failed", CANCELLED: "failed",
  })) {
    test(`${prefix}${state} maps to ${expected}`, () => {
      assert.equal(analysisPhase(`${prefix}${state}`), expected);
    });
  }
}

test("Core lifecycle continues polling until completion", () => {
  assert.deepEqual(
    ["QUEUED", "RUNNING", "COMPLETED"].map(state => analysisPhase(`ANALYSIS_STATE_${state}`)),
    ["running", "running", "complete"],
  );
});

test("unknown states fail explicitly instead of leaving the UI busy forever", () => {
  assert.throws(() => analysisPhase("ANALYSIS_STATE_UNSPECIFIED"), /Unsupported analysis state/);
});
