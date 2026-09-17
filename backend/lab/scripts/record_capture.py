#!/usr/bin/env python3
import argparse, csv, datetime as dt, json, platform, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent)); from pcap_info import inspect
FIELDS=['sample_id','pcap_path','pcap_file','traffic_class','mode','ike_version','ike_proposal','esp_proposal','cipher','integrity','dh_group','pfs','ip_version','nat_t','nat_t_forced','udp_encapsulation_forced','actual_nat_present','peer_auth','capture_duration_s','outer_left','outer_right','traffic_generator','sha256','original_label','canonical_label','dataset_role','profile_id','run_id','capture_timestamp_utc','capture_started_at_utc','capture_ended_at_utc','configured_capture_duration_s','observed_packet_span_s','packet_count','pcap_file_size_bytes','captured_frame_bytes','capture_interface','link_type','generator_parameters','strongswan_version','kernel_version','tcpdump_version','is_anomaly','anomaly_type','split','protocol_facts']
PROFILE={
 1:('tunnel','IKEv2','aes128-sha256-modp2048','aes128-sha256','AES-128-CBC','HMAC-SHA256','14-MODP2048','off','IPv4','off','no','172.31.0.2','172.31.0.3'),
 2:('tunnel','IKEv2','aes256gcm16-prfsha256-ecp256','aes256gcm16','AES-256-GCM-16','AEAD-GCM-128-bit-ICV','19-ECP256','off','IPv4','on','yes','172.31.0.2','172.31.0.3'),
 3:('tunnel','IKEv1','aes256-sha256-modp2048','aes256-sha256-modp2048','AES-256-CBC','HMAC-SHA256','14-MODP2048','on','IPv4','off','no','172.31.0.2','172.31.0.3'),
 4:('transport','IKEv1','aes128-sha256-modp3072','aes128-sha256-modp3072','AES-128-CBC','HMAC-SHA256','15-MODP3072','on','IPv4','on','yes','172.31.0.2','172.31.0.3'),
 5:('tunnel','IKEv2','aes256-sha384-ecp384','aes256-sha384','AES-256-CBC','HMAC-SHA384','20-ECP384','off','IPv6','off','no','fd00:31::2','fd00:31::3'),
}
def version(cmd):
 try: return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).splitlines()[0]
 except Exception: return 'unavailable'
p=argparse.ArgumentParser(); p.add_argument('pcap'); p.add_argument('--label',required=True); p.add_argument('--profile',type=int,required=True); p.add_argument('--run',default=''); p.add_argument('--role',default='train_known'); p.add_argument('--generator',required=True); p.add_argument('--params',default='{}'); p.add_argument('--anomaly',default=''); p.add_argument('--interface',default='gateway-eth0-outer'); p.add_argument('--actual-nat',action='store_true'); p.add_argument('--peer-auth',default='PSK'); p.add_argument('--protocol-facts',default=''); a=p.parse_args()
params=json.loads(a.params); info=inspect(a.pcap); mode,ike,ike_prop,esp_prop,cipher,integrity,dh,pfs,ip,natt,forced,left,right=PROFILE[a.profile]
if info['packet_count'] <= 0: raise SystemExit(f'capture contains no packets: {a.pcap}')
root=Path(__file__).resolve().parents[2]; meta=root/'metadata.csv'; rel=Path(a.pcap).resolve().relative_to(root).as_posix(); sid=Path(a.pcap).stem
canonical = a.label if a.role == 'train_known' or (a.role == 'anomaly_eval' and a.label in {'web','video','voip','email','file_transfer','messaging','icmp'}) else 'IGNORE'
split={'R01':'train','R02':'train','R03':'train','R04':'validation','R05':'locked_test'}.get(a.run,'')
row={x:'' for x in FIELDS}; row.update(sample_id=sid,pcap_path=rel,pcap_file=rel,traffic_class=a.label,mode=mode,ike_version=ike,ike_proposal=ike_prop,esp_proposal=esp_prop,cipher=cipher,integrity=integrity,dh_group=dh,pfs=pfs,ip_version=ip,nat_t=natt,nat_t_forced=forced,udp_encapsulation_forced=forced,actual_nat_present='yes' if a.actual_nat else 'no',peer_auth=a.peer_auth,capture_duration_s=str(params.get('duration_s','')),outer_left=left,outer_right=right,traffic_generator=a.generator,sha256=info['sha256'],original_label=a.label,canonical_label=canonical,dataset_role=a.role,profile_id=f'P{a.profile:02d}',run_id=a.run,capture_timestamp_utc=info['capture_started_at_utc'],capture_started_at_utc=info['capture_started_at_utc'],capture_ended_at_utc=info['capture_ended_at_utc'],configured_capture_duration_s=str(params.get('duration_s','')),observed_packet_span_s=str(info['observed_packet_span_s']),packet_count=str(info['packet_count']),pcap_file_size_bytes=str(info['pcap_file_size_bytes']),captured_frame_bytes=str(info['captured_frame_bytes']),capture_interface=a.interface,link_type=str(info['link_type']),generator_parameters=json.dumps(params,sort_keys=True),strongswan_version=version(['docker','exec','managed-ipsec-left','ipsec','--version']),kernel_version=platform.release(),tcpdump_version=version(['tcpdump','--version']),is_anomaly=str(bool(a.anomaly)).lower(),anomaly_type=a.anomaly or 'none',split=split,protocol_facts=a.protocol_facts)
rows=[]
if meta.exists():
 with meta.open(newline='') as f: rows=list(csv.DictReader(f))
if any(r.get('sample_id')==sid for r in rows): raise SystemExit(f'duplicate sample_id: {sid}')
with meta.open('w',newline='') as f:
 w=csv.DictWriter(f,FIELDS,lineterminator='\n'); w.writeheader(); w.writerows([{k:r.get(k,'') for k in FIELDS} for r in rows]); w.writerow(row)
