// Runs two short, explicitly authorized local captures and verifies both PDFs.
const base = process.env.CORE_HTTP_URL || 'http://127.0.0.1:8080';
const iface = process.argv[2];
if (!iface) throw new Error('Usage: node scripts/ubuntu-workflow-smoke.mjs <authorized-interface>');
async function request(path, body) {
 const response = await fetch(base + path, body ? {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)} : undefined);
 const data = await response.json();
 if (!response.ok) throw new Error(JSON.stringify(data));
 return data;
}
async function until(path, done) {
 for(let i=0;i<60;i++) { const value=await request(path); if (String(value.state).includes('FAILED')) throw new Error(JSON.stringify(value)); if(done(value)) return value; await new Promise(r=>setTimeout(r,500)); }
 throw new Error('Timed out: '+path);
}
const ids=[];
for (const mode of ['live','deep']) {
 const capture=await request('/api/v1/live-captures',{interface_name:iface,mode,consent:true,authorized:true,enable_vici:mode==='deep',enable_xfrm:mode==='deep',save_pcap:false});
 console.log(mode, 'capture started', capture.capture_id, 'gateway', Object.keys(capture.gateway || {}));
 let result;
 try { await new Promise(r=>setTimeout(r,2500)); }
 finally { result=await request('/api/v1/live-captures/'+capture.source_id+'/stop',{}); }
 const analysis=await until('/api/v1/analyses/'+result.analysis_id, v=>v.state==='ANALYSIS_STATE_COMPLETED');
 ids.push(analysis.analysis_id);
 const insight=await request('/api/v1/analyses/'+analysis.analysis_id+'/insights');
 console.log(mode,'analysis completed',analysis.analysis_id,'sections',Object.keys(insight),'score',insight.security?.assessment?.score);
}
for(const id of ids) {
 const report=await request('/api/v1/analyses/'+id+'/report',{});
 const ready=await until('/api/v1/reports/'+report.report_id,v=>v.state==='READY');
 const response=await fetch(base+ready.download_url);
 const bytes=new Uint8Array(await response.arrayBuffer());
 if (!response.ok || new TextDecoder().decode(bytes.slice(0,5))!=='%PDF-') throw new Error('Invalid PDF');
 console.log('PDF verified',id,bytes.length,'bytes');
}
