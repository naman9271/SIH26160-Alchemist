#!/usr/bin/env python3
"""Populate factual, PCAP-verified protocol coverage for existing sessions."""
import csv
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
META = ROOT / 'metadata.csv'
FACTS = {
    'P01': ('IKEv2; native ESP; IPv4; PSK authentication', 'esp'),
    'P02': ('IKEv2; UDP/4500; IPv4; forced encapsulation; PSK authentication', '4500'),
    'P03': ('IKEv1; native ESP; IPv4; PSK authentication', 'esp'),
    'P04': ('IKEv1; UDP/4500; IPv4; forced encapsulation; PSK authentication', '4500'),
    'P05': ('IKEv2; native ESP; IPv6; PSK authentication', 'esp'),
}

with META.open(newline='') as stream:
    reader = csv.DictReader(stream)
    fields = reader.fieldnames
    rows = list(reader)

updated = 0
for row in rows:
    if row.get('dataset_role') != 'protocol_validation':
        continue
    facts, marker = FACTS[row['profile_id']]
    path = ROOT / row['pcap_path']
    trace = subprocess.run(['tcpdump', '-nn', '-r', str(path)], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           check=True).stdout.lower()
    if 'isakmp' not in trace or marker not in trace:
        raise SystemExit(f'{path}: does not contain the expected IKE and {marker} traffic')
    row['protocol_facts'] = facts
    updated += 1

with META.open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
print(f'Refreshed protocol facts for {updated} PCAPs; no PCAP bytes were changed.')
