export type AnalysisServiceState = "READY" | "DEGRADED" | "UNAVAILABLE";

type ServiceChecks = {
  health: boolean;
  system: boolean;
  analysis?: boolean;
};

export function analysisServiceState(checks: ServiceChecks): AnalysisServiceState {
  if (checks.health) return "READY";
  if (checks.system || checks.analysis) return "DEGRADED";
  return "UNAVAILABLE";
}
