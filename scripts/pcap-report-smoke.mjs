import { readFile } from 'node:fs/promises';
const base='http://127.0.0.1:8080';
const data=await readFile(new URL('../ipsec_esp/ipsec_esp_capture_1/capture.pcap',import.meta.url));
const form=new FormData(); form.set('pcap',new Blob([data]),'capture.pcap');
async function check(response) {const result=await response.json(); if(!response.ok) throw new Error(JSON.stringify(result));return result;}
const source=await check(await fetch(base+'/api/v1/pcap',{method:'POST',body:form}));
const analysis=await check(await fetch(base+'/api/v1/analyses',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({source_id:source.source_id,enable_ml:true})}));
for(let i=0;i<90;i++) {
 const status=await check(await fetch(base+'/api/v1/analyses/'+analysis.analysis_id));
 if(status.state==='ANALYSIS_STATE_FAILED') throw new Error(status.failure_reason);
 if(status.state==='ANALYSIS_STATE_COMPLETED') {
  const insights=await check(await fetch(base+'/api/v1/analyses/'+analysis.analysis_id+'/insights'));
  console.log(JSON.stringify({analysis:analysis.analysis_id,packets:source.packets,flows:insights.flows?.items?.length,predictions:insights.ml?.predictions?.length,classes:insights.ml?.predictions?.map(p=>p.traffic_class),findings:insights.security?.assessment?.findings?.length}));
  if (!insights.ml?.predictions?.length) throw new Error('No ML predictions from the supplied IPsec fixture');
  process.exit(0);
 }
 await new Promise(r=>setTimeout(r,500));
}
throw new Error('Analysis timed out');
