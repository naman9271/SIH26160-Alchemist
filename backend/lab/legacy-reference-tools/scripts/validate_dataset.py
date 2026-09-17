#!/usr/bin/env python3
"""Strict, read-only validation for the final IPsec PCAP dataset."""
import csv, json, re, sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent)); from pcap_info import inspect

ROOT=Path(__file__).resolve().parents[2]; META=ROOT/'metadata.csv'
LABELS={'web','video','voip','email','file_transfer','messaging','icmp'}
ROLES={'train_known','ood_eval','anomaly_eval','protocol_validation','archived_provenance'}
REQUIRED={'sample_id','pcap_path','original_label','canonical_label','dataset_role','profile_id','run_id','capture_started_at_utc','capture_ended_at_utc','configured_capture_duration_s','observed_packet_span_s','packet_count','pcap_file_size_bytes','captured_frame_bytes','capture_interface','link_type','generator_parameters','sha256','strongswan_version','kernel_version','tcpdump_version','is_anomaly','anomaly_type','actual_nat_present','udp_encapsulation_forced'}
errors=[]
def bad(s, rule, expected, observed): errors.append(f'{s}: {rule}; expected {expected}; observed {observed}')
def yn(v): return v in {'yes','no'}
def positive(v):
    try: return int(v)>0
    except ValueError: return False
def number(v):
    try: return float(v)
    except ValueError: return None

try:
    with META.open(newline='') as f: rows=list(csv.DictReader(f)); headers=set(rows[0]) if rows else set()
except FileNotFoundError: rows=[]; headers=set(); errors.append('metadata.csv: missing')
if not rows: errors.append('metadata.csv: no rows')
for h in REQUIRED-headers: errors.append(f'metadata.csv: required column missing: {h}')
seen_id=set(); seen_hash={}; listed=set(); known=Counter(); ood=Counter(); anomaly=Counter(); protocols=[]
for r in rows:
    sid=r.get('sample_id','<missing>'); path_text=r.get('pcap_path') or r.get('pcap_file',''); listed.add(path_text)
    if not sid: bad('<row>','sample ID','non-empty','empty')
    elif sid in seen_id: bad(sid,'duplicate sample ID','unique',sid)
    seen_id.add(sid)
    missing=[k for k in REQUIRED if not r.get(k)]
    if missing: bad(sid,'required metadata','all populated',','.join(sorted(missing)))
    path=ROOT/path_text
    if not path.is_file() or path.stat().st_size==0: bad(sid,'PCAP','existing non-empty file',path_text); continue
    try: info=inspect(path)
    except Exception as e: bad(sid,'PCAP parse','valid classic PCAP',str(e)); continue
    for key, actual in [('sha256',info['sha256']),('packet_count',str(info['packet_count'])),('pcap_file_size_bytes',str(info['pcap_file_size_bytes'])),('captured_frame_bytes',str(info['captured_frame_bytes'])),('capture_started_at_utc',info['capture_started_at_utc']),('capture_ended_at_utc',info['capture_ended_at_utc'])]:
        if r.get(key)!=actual: bad(sid,key,actual,r.get(key,''))
    if info['sha256'] in seen_hash: bad(sid,'duplicate SHA-256','unique',f'{info["sha256"]} (also {seen_hash[info["sha256"]]})')
    seen_hash[info['sha256']]=sid
    if not positive(r.get('packet_count','')): bad(sid,'packet_count','positive integer',r.get('packet_count',''))
    span=number(r.get('observed_packet_span_s',''))
    if span is None or span < 0: bad(sid,'observed duration','non-negative number',r.get('observed_packet_span_s',''))
    try: json.loads(r.get('generator_parameters',''))
    except Exception as e: bad(sid,'generator_parameters','valid JSON',str(e))
    role,label=r.get('dataset_role'),r.get('canonical_label')
    if role not in ROLES: bad(sid,'dataset role',sorted(ROLES),role)
    if not re.fullmatch(r'P0[1-5]',r.get('profile_id','')): bad(sid,'profile ID','P01..P05',r.get('profile_id',''))
    if not yn(r.get('actual_nat_present','')) or not yn(r.get('udp_encapsulation_forced','')): bad(sid,'NAT flags','yes or no',f"{r.get('actual_nat_present')}/{r.get('udp_encapsulation_forced')}")
    profile=int(r.get('profile_id','P00')[-1]) if re.fullmatch(r'P0[1-5]',r.get('profile_id','')) else 0
    expected_outer = info['udp4500_packets'] if r.get('udp_encapsulation_forced')=='yes' else info['esp_packets']
    if expected_outer==0: bad(sid,'IPsec outer protocol','UDP/4500 when forced, otherwise ESP','none')
    if r.get('actual_nat_present')=='yes' and info['udp4500_packets']==0: bad(sid,'actual NAT semantics','UDP/4500 present','none')
    if r.get('actual_nat_present')=='yes' and r.get('udp_encapsulation_forced')=='yes': bad(sid,'actual NAT semantics','not forced encapsulation','forced UDP/4500')
    if role=='train_known':
        if label not in LABELS: bad(sid,'known canonical label',sorted(LABELS),label)
        if not re.fullmatch(r'R0[1-5]',r.get('run_id','')): bad(sid,'known run ID','R01..R05',r.get('run_id',''))
        known[(label,r.get('profile_id'),r.get('run_id'))]+=1
    elif label!='IGNORE': bad(sid,'non-training canonical label','IGNORE',label)
    if role=='ood_eval': ood[(r.get('original_label'),r.get('profile_id'))]+=1
    if role=='anomaly_eval':
        if r.get('is_anomaly')!='true': bad(sid,'anomaly flag','true',r.get('is_anomaly',''))
        anomaly[r.get('anomaly_type')]+=1
    if role=='protocol_validation':
        protocols.append(r)
        if r.get('run_id') in {'','N/A'}: bad(sid,'protocol run ID','populated identifier',r.get('run_id',''))
for p in ROOT.glob('pcaps/**/*.pcap'):
    if '/incomplete/' in p.relative_to(ROOT).as_posix(): continue
    if p.relative_to(ROOT).as_posix() not in listed: bad(p.name,'metadata','one metadata row','none')

for label in LABELS:
 for profile in range(1,6):
  for run in range(1,6):
   key=(label,f'P{profile:02d}',f'R{run:02d}')
   if known[key]!=1: bad('/'.join(key),'known matrix','exactly one capture',known[key])
OOD_TYPES={'dns','ssh','gaming_udp','database','remote_desktop'}
for t in OOD_TYPES:
 for p in range(1,6):
  if ood[(t,f'P{p:02d}')]!=1: bad(f'{t}/P{p:02d}','OOD matrix','exactly one capture',ood[(t,f'P{p:02d}')])
for t in {'icmp_flood','udp_flood','beacon_burst'}:
 if anomaly[t]!=10: bad(t,'anomaly count','10',anomaly[t])
for profile in range(1, 6):
 if sum(r.get('profile_id') == f'P{profile:02d}' for r in protocols) != 1:
  bad(f'protocol_validation/P{profile:02d}', 'protocol capture count', 'exactly one', sum(r.get('profile_id') == f'P{profile:02d}' for r in protocols))
facts=' '.join(r.get('protocol_facts','').lower() for r in protocols)
for required in ('ikev1','ikev2','native esp','udp/4500','ipv4','ipv6','psk authentication'):
 if required not in facts: bad('protocol_validation','protocol coverage',required,'absent')
if errors:
 print('Dataset validation failed:'); print('\n'.join('- '+e for e in errors)); sys.exit(1)
print('Dataset validation passed.')
