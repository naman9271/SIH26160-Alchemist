export type JsonRecord = Record<string, unknown>;

const MAX_DEPTH = 6;
const MAX_ARRAY_ITEMS = 30;
const MAX_STRING_LENGTH = 3_000;

function record(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : undefined;
}

function pick(source: unknown, keys: string[]) {
  const value = record(source);
  if (!value) return undefined;
  return Object.fromEntries(keys.flatMap(key => value[key] === undefined ? [] : [[key, value[key]]]));
}

function bounded(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return value.length > MAX_STRING_LENGTH ? `${value.slice(0, MAX_STRING_LENGTH)}\n[Text shortened for chat.]` : value;
  if (value === null || typeof value !== "object") return value;
  if (depth >= MAX_DEPTH) return "[Nested detail omitted for chat.]";
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ARRAY_ITEMS).map(item => bounded(item, depth + 1));
    return value.length > MAX_ARRAY_ITEMS ? [...items, `[${value.length - MAX_ARRAY_ITEMS} additional records omitted for chat.]`] : items;
  }
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, bounded(item, depth + 1)]));
}

/**
 * Keeps decision-making data while omitting high-volume packet, flow, timeline,
 * and raw-evidence records. It is safe to run on both browser input and API input.
 */
export function compactReportForChat(report: unknown): JsonRecord | undefined {
  const source = record(report);
  if (!source) return undefined;
  const protocol = record(source.protocol);
  const fusion = record(source.fusion);
  const security = record(source.security);
  const assessment = record(security?.assessment);
  const ml = record(source.ml);

  return bounded({
    analysis: pick(source.analysis, ["analysis_id", "state", "stage", "mode", "created_at", "completed_at"]),
    summary: source.summary,
    progress: pick(source.progress, ["state", "stage", "message", "failure_reason"]),
    protocol: protocol && {
      summary: protocol.summary,
      sessions: protocol.sessions,
      crypto_properties: protocol.crypto_properties,
      nat_traversal: protocol.nat_traversal,
    },
    fusion: fusion && {
      status: fusion.status,
      summary: fusion.summary,
      conclusions: fusion.conclusions,
    },
    security: security && {
      assessment: assessment && pick(assessment, ["state", "observed_security_score", "score_available", "evidence_coverage_percent", "security_bounds", "provisional", "grade", "findings", "recommendations", "threat_entries", "threat_matrix", "rules_evaluated", "rules_unknown", "unknown_evidence_count", "configuration_facts", "metadata_exposure"]),
      risk_score: security.risk_score,
      risk_breakdown: security.risk_breakdown,
      critical_overrides: security.critical_overrides,
    },
    ml: ml && {
      worker: ml.worker,
      predictions: ml.predictions,
    },
  }) as JsonRecord;
}
