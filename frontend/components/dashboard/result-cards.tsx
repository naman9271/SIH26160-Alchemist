export function label(value: string) { return value.replace(/([a-z])([A-Z])/g, "$1 $2").replaceAll("_", " "); }
export function ResultCards({ value }: { value: unknown }) {
  if (value == null) return <span className="text-white/40">Not available</span>;
  if (typeof value !== "object") return <span className="break-words text-sm text-teal-100">{typeof value === "boolean" ? value ? "Yes" : "No" : String(value)}</span>;
  if (Array.isArray(value)) return value.length ? <div className="grid gap-3">{value.map((item, i) => <div key={i} className="rounded border border-white/10 bg-white/[.02] p-3"><ResultCards value={item}/></div>)}</div> : <p className="text-sm text-white/40">No records reported.</p>;
  return <dl className="grid gap-3 sm:grid-cols-2">{Object.entries(value).map(([key, item]) => <div key={key} className={typeof item === "object" && item !== null ? "min-w-0 sm:col-span-2" : "min-w-0 border-b border-white/10 pb-3"}><dt className="mb-2 text-xs capitalize text-white/50">{label(key)}</dt><dd><ResultCards value={item}/></dd></div>)}</dl>;
}
