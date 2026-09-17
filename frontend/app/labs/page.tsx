"use client";

import { useEffect, useRef, useState } from "react";
import { coreURL } from "@/lib/core-url";
import { parseCSV } from "./csv";

type Status = { state: string; ready: boolean; message: string; logs: string[] };
type Settings = { name: string; profiles: number[]; labels: string[]; repetitions: number; evaluation_labels:string[]; include_protocol:boolean; evaluation_duration:number };
type Run = { id: string; name: string; state: string; created_at: string; settings: Settings; logs: string[] };
type Dataset = { id: string; run_id: string; path: string; kind: string; records: number };
const profiles = [
  [1,"P01 · IKEv2 / IPv4 / tunnel","AES-128-CBC · SHA256 · DH14 · native ESP · PFS off"],
  [2,"P02 · IKEv2 / IPv4 / tunnel","AES-256-GCM · DH19 · forced UDP/4500 · PFS off"],
  [3,"P03 · IKEv1 / IPv4 / tunnel","AES-256-CBC · SHA256 · DH14 · native ESP · PFS on"],
  [4,"P04 · IKEv1 / IPv4 / transport","AES-128-CBC · SHA256 · DH15 · forced UDP/4500 · PFS on"],
  [5,"P05 · IKEv2 / IPv6 / tunnel","AES-256-CBC · SHA384 · DH20 · native ESP · PFS off"],
] as const;
const labels = ["web","video","voip","email","file_transfer","messaging","icmp"];
const evaluations=["dns","ssh","gaming_udp","database","remote_desktop","icmp_flood","udp_flood","beacon_burst"];
const buttonClass = "border border-teal-200/40 px-4 py-2 text-xs font-semibold text-teal-100 transition hover:bg-teal-200/10 focus-visible:outline-2 focus-visible:outline-teal-200 disabled:cursor-not-allowed disabled:opacity-40";
async function request<T>(path: string, options?: RequestInit): Promise<T> {
 const response = await fetch(coreURL(path), { ...options, cache: "no-store" });
 const body = await response.text();
 let value: T & {error?: string};
 try { value = JSON.parse(body); } catch { throw new Error(response.status === 404 ? "This backend does not have the Labs API. Rebuild the backend to load the current version." : "The lab service returned an unexpected response."); }
 if (!response.ok) throw new Error(value.error ?? "The lab request failed.");
 return value;
}
const artifactURL = (id: string, path: string) => coreURL(`/api/v1/labs/runs/${id}/artifact?path=${encodeURIComponent(path)}`);
export default function LabsPage() {
 const [status,setStatus] = useState<Status>();
 const [runs,setRuns] = useState<Run[]>([]);
 const [datasets,setDatasets] = useState<Dataset[]>([]);
 const [settings,setSettings] = useState<Settings>({name:"IPsec capture experiment",profiles:[1],labels:["icmp"],repetitions:1,evaluation_labels:[],include_protocol:false,evaluation_duration:20});
 const [busy,setBusy] = useState(false);
 const [error,setError] = useState("");
 const [connectionError,setConnectionError] = useState("");
 const [selected,setSelected] = useState<string>();
 const [logTarget,setLogTarget] = useState<string>();
 const [csv,setCSV] = useState<string[][]>([]);
 const [csvError,setCSVError] = useState("");
 const [follow,setFollow] = useState(true);
 const dialog = useRef<HTMLDialogElement>(null);
 const logEnd = useRef<HTMLDivElement>(null);
 useEffect(() => {
  let active = true;
  const controller = new AbortController();
  async function poll() {
   try {
    const [runtime,history,tree] = await Promise.all([
     request<Status>("/api/v1/labs/status",{signal:controller.signal}),
     request<{runs:Run[]}>("/api/v1/labs/runs",{signal:controller.signal}),
     request<{datasets:Dataset[]}>("/api/v1/labs/datasets",{signal:controller.signal}),
    ]);
    if (active) { setStatus(runtime);setRuns(history.runs);setDatasets(tree.datasets);setConnectionError(""); }
   } catch(cause) { if(active)setConnectionError(cause instanceof Error?cause.message:"Labs connection failed"); }
   if(active)timer=window.setTimeout(poll,1500);
  }
  let timer=window.setTimeout(poll,0);
  return () => {active=false;controller.abort();window.clearTimeout(timer);};
 },[]);
 const selectedRun = runs.find(run => run.id === selected) ?? runs[0];
 const runFiles = datasets.filter(file => file.run_id === selectedRun?.id);
 const metadata = runFiles.find(file => file.path === "metadata.csv");
 const selectedID = selectedRun?.id;
 const metadataPath = metadata?.path;
 const metadataCount = metadata?.records;
 useEffect(() => {
  let active=true;
  async function load() {
   setCSV([]);setCSVError("");
   if(!selectedID || !metadataPath) return;
   try {const response=await fetch(artifactURL(selectedID,metadataPath));if(!response.ok)throw new Error("Capture metadata could not be loaded.");const parsed=parseCSV(await response.text());if(active)setCSV(parsed);}
   catch(cause){if(active)setCSVError(cause instanceof Error?cause.message:"Metadata unavailable");}
  }
  const timer=window.setTimeout(load,0);
  return()=>{active=false;window.clearTimeout(timer);};
 },[selectedID,metadataPath,metadataCount]);
 const logLines = logTarget === "runtime" ? status?.logs ?? [] : runs.find(run => run.id === logTarget)?.logs ?? [];
 useEffect(() => {if(logTarget && !dialog.current?.open)dialog.current?.showModal();},[logTarget]);
 useEffect(() => {if(follow)logEnd.current?.scrollIntoView({block:"end"});},[logLines.length,follow]);
 async function activate() {
  setBusy(true);setError("");setLogTarget("runtime");
  try {setStatus(await request<Status>("/api/v1/labs/activate",{method:"POST"}));}
  catch(cause){setError(cause instanceof Error?cause.message:"Activation failed");}
  finally{setBusy(false);}
 }
 async function generate() {
  setBusy(true);setError("");
  try {const run=await request<Run>("/api/v1/labs/runs",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(settings)});setRuns(current=>[run,...current]);setSelected(run.id);setLogTarget(run.id);}
  catch(cause){setError(cause instanceof Error?cause.message:"Dataset generation failed");}
  finally{setBusy(false);}
 }
 async function download(url: string,name: string) {
  try {const response=await fetch(url);if(!response.ok)throw new Error("This artifact is not available for download yet.");const blob=await response.blob();const objectURL=URL.createObjectURL(blob);const anchor=document.createElement("a");anchor.href=objectURL;anchor.download=name;anchor.click();setTimeout(()=>URL.revokeObjectURL(objectURL),1000);}
  catch(cause){setError(cause instanceof Error?cause.message:"Download failed");}
 }
 const total=settings.profiles.length*((settings.labels.length+settings.evaluation_labels.length)*settings.repetitions+(settings.include_protocol?1:0));
 const capturing=runs.some(run=>run.state==="RUNNING");
 const activityTarget=status?.state==="STARTING" || status?.state==="FAILED" || logTarget==="runtime" ? "runtime" : selectedRun?.id ?? "runtime";
 const activityLines=activityTarget==="runtime" ? status?.logs ?? [] : selectedRun?.logs ?? [];
 return <main className="min-h-svh bg-[#080d15] px-4 pb-12 pt-10 text-slate-100 sm:px-8">
  <div className="mx-auto max-w-7xl">
   <p className="font-mono text-xs tracking-[.2em] text-teal-200/60">LABORATORY / PCAP DATASETS</p>
   <h1 className="mt-3 text-3xl font-semibold sm:text-4xl">IPsec capture laboratory</h1>
   <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">Run real encrypted traffic through isolated StrongSwan gateways. Select protocol profiles and traffic classes, inspect process logs, and export captures with their provenance.</p>
   {(error || connectionError) && <div role="alert" className="mt-5 border border-red-300/30 bg-red-300/5 p-4 text-sm text-red-100">{error || connectionError}</div>}
   <section className="mt-7 flex flex-wrap items-center justify-between gap-4 rounded-lg border border-white/10 bg-white/[.025] p-5">
    <div><div className="flex items-center gap-3"><h2 className="text-sm font-semibold">Lab runtime</h2><span className={`rounded-full px-3 py-1 text-[10px] font-semibold ${status?.ready?"bg-teal-200/10 text-teal-200":"bg-amber-200/10 text-amber-100"}`}>{status?.state ?? "CONNECTING"}</span></div><p className="mt-2 text-xs text-slate-400">{status?.message ?? "Connecting to the capture service…"}</p></div>
    <div className="flex gap-2"><button className={buttonClass} onClick={()=>setLogTarget("runtime")}>Runtime logs ↗</button><button className={buttonClass} onClick={()=>void activate()} disabled={!status || busy || status.ready || status.state==="STARTING"}>{status?.state==="STARTING"?"Starting…":status?.ready?"Runtime active":"Activate lab"}</button></div>
   </section>
   <div className="mt-5 grid gap-5 lg:grid-cols-[minmax(0,1fr)_21rem]">
    <div className="space-y-5">
     <section className="rounded-lg border border-white/10 bg-white/[.025] p-5 sm:p-6">
      <h2 className="text-lg font-semibold">Capture configuration</h2><p className="mt-1 text-xs text-slate-400">Each profile × traffic class × repetition produces an independent PCAP.</p>
      <div className="mt-5 grid gap-5 sm:grid-cols-2"><label className="text-xs text-slate-300">Experiment name <Help text="Saved alongside configuration, process logs and every captured artifact."/><input className="lab-input mt-2" maxLength={120} value={settings.name} onChange={e=>setSettings({...settings,name:e.target.value})}/></label><label className="text-xs text-slate-300">Repetitions per combination <Help text="Choose 1–5 independent captures. The generator uses fresh parameters and seeds for each capture."/><input type="number" min={1} max={5} className="lab-input mt-2" value={settings.repetitions} onChange={e=>setSettings({...settings,repetitions:Number(e.target.value)})}/></label></div>
      <fieldset className="mt-5"><legend className="text-xs font-semibold text-slate-300">Protocol profiles <Help text="Profiles preserve the reference lab's suites and topology combinations. Forced UDP encapsulation is recorded separately from actual NAT; actual NAT is not present."/></legend><div className="mt-3 space-y-2">{profiles.map(([id,title,detail])=><label key={id} className="flex cursor-pointer items-start gap-3 rounded border border-white/10 p-3 transition hover:border-teal-200/40"><input className="mt-1 accent-teal-200" type="checkbox" checked={settings.profiles.includes(id)} onChange={e=>setSettings({...settings,profiles:e.target.checked?[...settings.profiles,id]:settings.profiles.filter(p=>p!==id)})}/><span><span className="block text-xs">{title}</span><span className="mt-1 block text-[11px] text-slate-500">{detail}</span></span></label>)}</div></fieldset>
      <fieldset className="mt-5"><legend className="text-xs font-semibold text-slate-300">Traffic classes <Help text="Real HTTP/HLS downloads, RTP audio, SMTP messages, bulk transfer, WebSocket chat and ICMP echo. Messaging uses synthetic local traffic."/></legend><div className="mt-3 flex flex-wrap gap-2">{labels.map(label=><label key={label} className="flex cursor-pointer gap-2 rounded border border-white/10 px-3 py-2 text-xs"><input type="checkbox" className="accent-teal-200" checked={settings.labels.includes(label)} onChange={e=>setSettings({...settings,labels:e.target.checked?[...settings.labels,label]:settings.labels.filter(l=>l!==label)})}/>{label.replaceAll("_"," ")}</label>)}</div></fieldset>
      <details className="mt-5 rounded border border-white/10 p-4"><summary className="cursor-pointer text-xs font-semibold text-slate-300">Evaluation and protocol coverage</summary><p className="mt-3 text-[11px] leading-5 text-slate-500">OOD and anomaly samples retain separate evaluation roles and are excluded from known-class training. Flood scenarios stay inside the isolated gateway network.</p><div className="mt-3 flex flex-wrap gap-2">{evaluations.map(label=><label key={label} className="flex gap-2 rounded border border-white/10 px-3 py-2 text-xs"><input type="checkbox" checked={settings.evaluation_labels.includes(label)} onChange={e=>setSettings({...settings,evaluation_labels:e.target.checked?[...settings.evaluation_labels,label]:settings.evaluation_labels.filter(value=>value!==label)})}/>{label.replaceAll("_"," ")}</label>)}</div><label className="mt-4 flex items-center gap-2 text-xs"><input type="checkbox" checked={settings.include_protocol} onChange={e=>setSettings({...settings,include_protocol:e.target.checked})}/>Include negotiation-first IKE/ESP validation per profile</label><label className="mt-4 block text-xs text-slate-400">Evaluation duration (5–120 seconds)<input className="lab-input mt-2 max-w-40" type="number" min={5} max={120} value={settings.evaluation_duration} onChange={e=>setSettings({...settings,evaluation_duration:Number(e.target.value)})}/></label></details>
      <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-white/10 pt-5"><p className="text-xs text-slate-400"><b className="text-teal-100">{total}</b> PCAP captures planned · real-time traffic can take several minutes</p><button className={buttonClass} onClick={()=>void generate()} disabled={!status?.ready || capturing || busy || total===0 || settings.labels.length===0 || !settings.name.trim() || settings.repetitions<1 || settings.repetitions>5}>{capturing?"Capture in progress…":"Generate dataset →"}</button></div>
     </section>
     <section className="rounded-lg border border-white/10 p-5"><div className="flex items-center justify-between"><h2 className="text-sm font-semibold">Process activity</h2><button className={buttonClass} onClick={()=>setLogTarget(activityTarget)}>Expand logs ↗</button></div><pre className="mt-4 max-h-44 overflow-auto whitespace-pre-wrap break-all font-mono text-xs leading-6 text-slate-400">{activityLines.slice(-6).join("\n") || "Activate the lab to see command output here."}</pre></section>
     {selectedRun && <section className="rounded-lg border border-white/10 p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-sm font-semibold">Capture metadata</h2><p className="mt-1 text-xs text-slate-500">{selectedRun.name} · {csv.length>0?csv.length-1:0} recorded captures</p></div><button className={buttonClass} disabled={selectedRun.state!=="COMPLETED"} onClick={()=>void download(coreURL(`/api/v1/labs/runs/${selectedRun.id}/download`),`ipsec-dataset-${selectedRun.id}.zip`)}>Download dataset ZIP ↓</button></div>{csvError && <p className="mt-3 text-sm text-red-200">{csvError}</p>}{csv.length>0?<div className="mt-4 max-h-96 overflow-auto"><table className="w-full whitespace-nowrap text-left text-xs"><thead className="sticky top-0 bg-slate-900 text-teal-100"><tr>{csv[0].map((field,i)=><th key={i} className="p-3 font-medium">{field}</th>)}</tr></thead><tbody>{csv.slice(1).map((row,i)=><tr key={i} className="border-t border-white/5">{row.map((value,j)=><td key={j} className="max-w-80 truncate p-3 text-slate-400" title={value}>{value}</td>)}</tr>)}</tbody></table></div>:<p className="mt-4 text-xs text-slate-500">Verified metadata appears after capture and integrity checks finish.</p>}</section>}
    </div>
    <aside className="space-y-5"><section className="rounded-lg border border-white/10 p-5"><h2 className="text-sm font-semibold">Dataset explorer</h2><p className="mt-2 text-xs text-slate-500">Expand folders. Select a file to download it.</p><div className="mt-4 font-mono text-xs">{runFiles.length?<FileTree files={runFiles} onFile={file=>void download(artifactURL(file.run_id,file.path),file.path.split("/").pop()!)}/>:<p className="text-slate-500">No artifacts for this experiment yet.</p>}</div></section><section className="rounded-lg border border-white/10 p-5"><h2 className="text-sm font-semibold">Experiment history</h2><div className="mt-4 space-y-2">{runs.length?runs.map(run=><button key={run.id} onClick={()=>setSelected(run.id)} className={`block w-full rounded border p-3 text-left ${selectedRun?.id===run.id?"border-teal-200/40 bg-teal-200/5":"border-white/10 hover:bg-white/5"}`}><span className="block text-xs font-semibold">{run.name}</span><span className="mt-1 block text-[10px] text-teal-100/70">{run.state}</span><span className="mt-1 block text-[10px] text-slate-500">{new Date(run.created_at).toLocaleString()}</span></button>):<p className="text-xs text-slate-500">Your experiments will appear here.</p>}</div></section></aside>
   </div>
  </div>
  <dialog ref={dialog} onClose={()=>setLogTarget(undefined)} className="m-auto w-[min(95vw,72rem)] rounded-xl border border-teal-200/20 bg-[#0b1220] p-0 text-slate-100 shadow-2xl backdrop:bg-black/75"><div className="flex items-center justify-between border-b border-white/10 p-5"><div><h2 className="font-semibold">{logTarget==="runtime"?"Runtime activation":"Capture process"} logs</h2><p className="mt-1 text-xs text-slate-500">Live stdout and stderr from the backend runner</p></div><button className={buttonClass} onClick={()=>dialog.current?.close()}>Close ×</button></div><div className="flex items-center justify-between px-5 pt-4 text-xs text-slate-400"><span>{logLines.length} log entries</span><label className="flex gap-2"><input type="checkbox" checked={follow} onChange={e=>setFollow(e.target.checked)}/>Follow output</label></div><pre className="h-[60vh] overflow-auto whitespace-pre-wrap break-all p-5 font-mono text-xs leading-6 text-teal-100/80">{logLines.join("\n") || "Waiting for process output…"}<div ref={logEnd}/></pre></dialog>
 </main>;
}
function Help({text}:{text:string}) {return <span className="group relative ml-1 inline-block align-middle"><button type="button" aria-label={text} className="inline-grid h-4 w-4 place-items-center rounded-full border border-teal-200/40 text-[10px] text-teal-100">?</button><span role="tooltip" className="pointer-events-none absolute bottom-full left-0 z-30 mb-2 w-64 rounded border border-teal-200/30 bg-slate-950 p-3 text-[11px] font-normal leading-5 text-slate-200 opacity-0 shadow-xl group-hover:opacity-100 group-focus-within:opacity-100">{text}</span></span>}
function FileTree({files,prefix="",onFile}:{files:Dataset[];prefix?:string;onFile:(file:Dataset)=>void}) {
 const groups=new Map<string,Dataset[]>();
 files.forEach(file=>{const part=file.path.slice(prefix.length).split("/")[0];groups.set(part,[...(groups.get(part)??[]),file]);});
 return <ul className="space-y-1">{[...groups.entries()].map(([name,children])=>{const path=prefix+name;const folder=children.some(file=>file.path!==path);return <li key={path}>{folder?<details open={prefix===""}><summary className="cursor-pointer rounded px-2 py-1 text-teal-100 hover:bg-white/5">▣ {name}</summary><div className="ml-3 border-l border-white/10 pl-2"><FileTree files={children} prefix={path+"/"} onFile={onFile}/></div></details>:<button onClick={()=>onFile(children[0])} title={children[0].kind} className="w-full truncate rounded px-2 py-1 text-left text-slate-400 hover:bg-teal-200/5 hover:text-teal-100">↳ {name}</button>}</li>})}</ul>
}
