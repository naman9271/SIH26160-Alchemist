import assert from "node:assert/strict";
import test from "node:test";
import { analysisServiceState } from "../components/dashboard/service-state.ts";

test("a failed optional request does not hide a healthy analysis service", () => {
  assert.equal(analysisServiceState({ health: true, system: false, analysis: false }), "READY");
});

test("a successful Core response proves the service is reachable when readiness fails", () => {
  assert.equal(analysisServiceState({ health: false, system: false, analysis: true }), "DEGRADED");
  assert.equal(analysisServiceState({ health: false, system: true }), "DEGRADED");
});

test("the service is unavailable only when every requested Core endpoint fails", () => {
  assert.equal(analysisServiceState({ health: false, system: false, analysis: false }), "UNAVAILABLE");
});
