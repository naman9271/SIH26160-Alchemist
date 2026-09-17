#!/usr/bin/env python3
"""Migrate metadata in place using measurements from immutable PCAP files.

This intentionally does not create captures, guess timestamps, or alter PCAP bytes.
"""
import csv, json, re
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent))
from pcap_info import inspect
FIELDS=['sample_id','pcap_path','pcap_file','traffic_class','mode','ike_version','ike_proposal','esp_proposal','cipher','integrity','dh_group','pfs','ip_version','nat_t','nat_t_forced','udp_encapsulation_forced','actual_nat_present','peer_auth','capture_duration_s','outer_left','outer_right','traffic_generator','sha256','original_label','canonical_label','dataset_role','profile_id','run_id','capture_timestamp_utc','capture_started_at_utc','capture_ended_at_utc','configured_capture_duration_s','observed_packet_span_s','packet_count','pcap_file_size_bytes','captured_frame_bytes','capture_interface','link_type','generator_parameters','strongswan_version','kernel_version','tcpdump_version','is_anomaly','anomaly_type','split','protocol_facts']

ROOT = Path(__file__).resolve().parents[2]
META = ROOT / 'metadata.csv'
LABELS = {'web', 'video', 'voip', 'email', 'file_transfer', 'messaging', 'icmp'}
MAP = {'file': 'file_transfer', 'ping': 'icmp', 'interactive_ssh': 'ssh'}

def profile_from(value):
    m = re.search(r'_p(0?[1-5])(?:_|\.pcap)', value)
    return f'P{int(m.group(1)):02d}' if m else ''

def run_from(value, role):
    m = re.search(r'_(R0[1-5])(?:\.pcap)?$', value)
    if m: return m.group(1)
    # Non-known rows still require an explicit provenance run identifier.
    return 'R01'

def role_for(path, old):
    if 'anomaly/archive' in path.as_posix() or 'ood/archive' in path.as_posix(): return 'archived_provenance'
    if old in {'train_known', 'ood_eval', 'anomaly_eval', 'protocol_validation', 'archived_provenance'}: return old
    return {'ood':'ood_eval', 'anomaly':'anomaly_eval', 'protocol_validation':'protocol_validation'}.get(path.parts[1] if len(path.parts)>1 else '', 'train_known')

with META.open(newline='') as f:
    old_rows = list(csv.DictReader(f))
by_path = {r.get('pcap_path') or r.get('pcap_file'): r for r in old_rows}
out = []
for p in sorted(ROOT.glob('pcaps/**/*.pcap')):
    rel = p.relative_to(ROOT).as_posix()
    # Interrupted captures are retained for audit only and are not dataset rows.
    if '/incomplete/' in rel: continue
    old = by_path.get(rel, {})
    # Allow migration after organized legacy files were moved.
    if not old:
        old = next((r for r in old_rows if Path(r.get('pcap_path') or r.get('pcap_file','')).name == p.name), {})
    info = inspect(p)
    role = role_for(Path(rel), old.get('dataset_role',''))
    raw = old.get('original_label') or old.get('traffic_class') or p.name.split('_p')[0]
    label = MAP.get(raw, raw)
    if label not in LABELS and role == 'train_known':
        raise SystemExit(f'{rel}: cannot derive a canonical known label from {raw!r}')
    row = {k: old.get(k, '') for k in FIELDS}
    row.update(
        sample_id=old.get('sample_id') or p.stem,
        pcap_path=rel, pcap_file=rel, traffic_class=label,
        original_label=raw, canonical_label=label if role == 'train_known' else 'IGNORE',
        dataset_role=role, profile_id=old.get('profile_id') or profile_from(p.name),
        run_id=old.get('run_id') if old.get('run_id') not in {'', 'N/A'} else run_from(p.stem, role),
        sha256=info['sha256'], capture_timestamp_utc=info['capture_started_at_utc'],
        capture_started_at_utc=info['capture_started_at_utc'], capture_ended_at_utc=info['capture_ended_at_utc'],
        observed_packet_span_s=str(info['observed_packet_span_s']), packet_count=str(info['packet_count']),
        pcap_file_size_bytes=str(info['pcap_file_size_bytes']), captured_frame_bytes=str(info['captured_frame_bytes']),
        link_type=str(info['link_type']), udp_encapsulation_forced=old.get('udp_encapsulation_forced') or old.get('nat_t_forced'),
    )
    row['split'] = {'R01':'train','R02':'train','R03':'train','R04':'validation','R05':'locked_test'}.get(row['run_id'],'')
    if not row['generator_parameters']:
        row['generator_parameters'] = json.dumps({'legacy_capture': True}, sort_keys=True)
    try: json.loads(row['generator_parameters'])
    except json.JSONDecodeError: raise SystemExit(f'{rel}: generator_parameters is not JSON')
    if not row['actual_nat_present']: row['actual_nat_present'] = 'no'
    if not row['is_anomaly']: row['is_anomaly'] = 'true' if role == 'anomaly_eval' else 'false'
    if role == 'anomaly_eval' and row['anomaly_type'] in {'', 'none'}:
        row['anomaly_type'] = next((t for t in ('icmp_flood','udp_flood','beacon_burst') if p.name.startswith(t)), 'none')
    if not row['anomaly_type']: row['anomaly_type'] = 'none'
    if not row['capture_interface']: row['capture_interface'] = 'legacy-host-veth'
    out.append(row)

with META.open('w', newline='') as f:
    w = csv.DictWriter(f, FIELDS, lineterminator='\n'); w.writeheader(); w.writerows(out)
print(f'Migrated {len(out)} rows from measured PCAP contents; no PCAP was modified.')
