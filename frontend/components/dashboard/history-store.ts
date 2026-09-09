export type Snapshot = { id: string; time: string; data: Record<string, unknown> };
const key = "ipsec-prism.analysis-history.v1";
export function readHistory(): Snapshot[] {
  try { const value = JSON.parse(localStorage.getItem(key) ?? "[]"); return Array.isArray(value) ? value.filter(v => typeof v?.id === "string" && v.data && typeof v.time === "string") : []; } catch { return []; }
}
export function saveSnapshot(id: string, data: Record<string, unknown>) {
  const previous = readHistory();
  const created = (data.analysis as {created_at?: string} | undefined)?.created_at;
  const entry = { id, time: previous.find(v => v.id === id)?.time ?? (created && !Number.isNaN(Date.parse(created)) ? new Date(created).toISOString() : new Date().toISOString()), data };
  localStorage.setItem(key, JSON.stringify([entry, ...previous.filter(v => v.id !== id)].sort((a,b) => b.time.localeCompare(a.time)).slice(0, 20)));
  window.dispatchEvent(new Event("analysis-history"));
}
