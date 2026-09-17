import { InfoHint } from "@/components/ui/info-hint";

type Prediction = { prediction_id?: string; flow_id?: string; traffic_class?: string; confidence?: number; is_unknown?: boolean; class_probabilities?: Record<string, number>; model_version?: string };

function percentage(value: number) { return Math.max(0, Math.min(100, value * 100)); }

export function ClassificationCards({ value }: { value: unknown }) {
  const predictions = Array.isArray(value) ? value as Prediction[] : [];
  if (!predictions.length) return <p className="mt-5 border border-white/15 p-4 text-sm text-white/60">No classification windows were produced. Capture IPsec traffic for long enough to build flow windows; ordinary web browsing may produce no IPsec packets.</p>;

  return <div className={`mt-5 grid gap-4 ${predictions.length > 1 ? "xl:grid-cols-2" : "grid-cols-1"}`}>{predictions.map((prediction, index) => {
    const confidence = typeof prediction.confidence === "number" ? percentage(prediction.confidence) : undefined;
    const probabilities = Object.entries(prediction.class_probabilities ?? {});
    return <article key={prediction.prediction_id ?? index} className="relative min-w-0 overflow-hidden border border-teal-200/20 bg-teal-200/[.025] p-4 sm:p-5">
      <span className="absolute right-4 top-4"><InfoHint label="About this traffic inference">This is a metadata-only probabilistic classification of an encrypted flow, not proof of an application or payload. Confidence is model certainty, not measured accuracy.</InfoHint></span>
      <header className="min-w-0 border-b border-white/10 pb-4 pr-8"><p className="truncate text-[10px] font-bold tracking-[.12em] text-amber-200">INFERRED · {prediction.model_version ?? "MODEL VERSION UNAVAILABLE"}</p><h2 className="mt-2 truncate text-xl font-semibold text-white">{prediction.is_unknown ? "UNKNOWN" : prediction.traffic_class?.replace("TRAFFIC_CLASS_", "") ?? "Unavailable"}</h2><p className="mt-2 truncate text-xs text-white/40" title={prediction.flow_id}>Flow {prediction.flow_id ?? "unavailable"}</p></header>
      <div className="mt-4 rounded border border-white/10 bg-black/20 px-3 py-2.5"><div className="flex items-baseline justify-between gap-3"><span className="text-[10px] font-bold tracking-[.1em] text-white/50">MODEL CONFIDENCE</span><span className="shrink-0 text-sm font-semibold text-teal-100">{confidence === undefined ? "Unavailable" : `${confidence.toFixed(1)}%`}</span></div>{confidence !== undefined && <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full bg-teal-300 transition-[width] duration-300" style={{ width: `${confidence}%` }} /></div>}</div>
      {probabilities.length > 0 && <section className="mt-5"><div className="mb-3 flex items-center justify-between gap-3"><h3 className="text-[10px] font-bold tracking-[.12em] text-white/55">CLASS PROBABILITIES</h3><span className="text-[10px] text-white/35">{probabilities.length} CLASSES</span></div><div className="space-y-3">{probabilities.map(([name, probability]) => { const probabilityPercent = percentage(probability); return <div key={name} className="grid grid-cols-[minmax(0,1fr)_3.5rem] items-center gap-x-3 gap-y-1.5"><span className="truncate text-xs text-white/70" title={name}>{name.replace("TRAFFIC_CLASS_", "")}</span><span className="text-right text-xs tabular-nums text-white/60">{probabilityPercent.toFixed(1)}%</span><div className="col-span-2 h-2 overflow-hidden rounded-full bg-white/10"><div className="h-full rounded-full bg-teal-300" style={{ width: `${probabilityPercent}%` }} /></div></div>; })}</div></section>}
    </article>;
  })}</div>;
}
