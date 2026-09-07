"use client";
import { useEffect, useState } from "react";
import { readHistory, Snapshot } from "./history-store";
export function ReportChat() {
  const [items, setItems] = useState<Snapshot[]>([]);
  const [selected, setSelected] = useState("");
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<Array<{role: "user" | "assistant"; content: string}>>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => { const timer = setTimeout(() => { const all = readHistory(); setItems(all); setSelected(all[0]?.id ?? ""); }, 0); return () => clearTimeout(timer); }, []);
  async function send() {
    if (!question.trim() || busy) return;
    const next = [...messages, {role: "user" as const, content: question}];
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/report-chat", {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({report: items.find(v => v.id === selected)?.data, messages: next.slice(-20)})});
      const body = await response.json(); if (!response.ok) throw new Error(body.error);
      setMessages([...next, {role: "assistant", content: body.answer}]); setQuestion("");
    } catch (e) { setError(e instanceof Error ? e.message : "Chat failed"); } finally { setBusy(false); }
  }
  return <section className="mt-8 space-y-5"><p className="text-sm text-white/60">Ask follow-up questions about a saved analysis. Sending a question shares the selected snapshot with Groq. The newest saved report is selected by default.</p><select aria-label="Report for assistant" disabled={busy} className="w-full border border-white/20 bg-black p-3" value={selected} onChange={e => {setSelected(e.target.value); setMessages([]);}}><option value="">Select report</option>{items.map(v => <option key={v.id} value={v.id}>{new Date(v.time).toLocaleString()} · {v.id.slice(0,8)}</option>)}</select><div aria-live="polite" className="space-y-4">{messages.map((m,i) => <article key={i} className="whitespace-pre-wrap border border-white/15 p-4"><p className="mb-3 text-xs uppercase text-teal-200">{m.role}</p>{m.content}</article>)}</div><form onSubmit={e => {e.preventDefault(); void send();}} className="space-y-3"><textarea aria-label="Question" maxLength={4000} value={question} onChange={e => setQuestion(e.target.value)} placeholder="Which findings should I fix first, and why?" className="min-h-28 w-full border border-teal-200/25 bg-black p-4"/><button disabled={busy || !selected || !question.trim()} className="border border-teal-200 px-5 py-3 text-teal-100 disabled:opacity-40">{busy ? "Reading report…" : "Ask assistant"}</button></form>{error && <p role="alert" className="text-red-200">{error}</p>}</section>;
}
