// Core serializes protobuf enum names, including the ANALYSIS_STATE_ prefix.
export function analysisPhase(state: string): "running" | "complete" | "failed" {
  switch (state.replace(/^ANALYSIS_STATE_/, "")) {
    case "QUEUED":
    case "RUNNING":
      return "running";
    case "COMPLETED":
      return "complete";
    case "FAILED":
    case "CANCELLED":
      return "failed";
    default:
      throw new Error(`Unsupported analysis state: ${state}`);
  }
}
