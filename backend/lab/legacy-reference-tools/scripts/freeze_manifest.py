#!/usr/bin/env python3
"""Freeze v1.0 only after strict validation has succeeded."""
import csv, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
subprocess.run([sys.executable, str(ROOT/'lab/scripts/validate_dataset.py')], check=True)
fields=['dataset_version','pcap_path','sha256','canonical_label','original_label','profile_id','run_id','dataset_role','split','packet_count','observed_packet_span_s','pcap_file_size_bytes','capture_started_at_utc','capture_ended_at_utc']
with (ROOT/'metadata.csv').open(newline='') as src, (ROOT/'dataset-manifest-v1.0.csv').open('w',newline='') as dst:
    writer=csv.DictWriter(dst,fields,lineterminator='\n'); writer.writeheader()
    for row in csv.DictReader(src): writer.writerow({'dataset_version':'1.0', **{k:row.get(k,'') for k in fields if k!='dataset_version'}})
print('Wrote dataset-manifest-v1.0.csv (dataset v1.0).')
