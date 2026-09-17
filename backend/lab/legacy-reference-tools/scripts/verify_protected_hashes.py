#!/usr/bin/env python3
"""Verify original-capture provenance after safe path-only moves."""
import hashlib, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
manifest=ROOT/'lab/original-20.sha256'
expected={line.split(maxsplit=1)[1].strip(): line.split()[0] for line in manifest.read_text().splitlines() if line.strip()}
by_name={p.name:p for p in ROOT.glob('pcaps/**/*.pcap')}
errors=[]
for old_path, digest in expected.items():
    path=by_name.get(Path(old_path).name)
    if not path: errors.append(f'{old_path}: missing')
    elif hashlib.sha256(path.read_bytes()).hexdigest()!=digest: errors.append(f'{old_path}: SHA-256 changed')
if errors:
    print('Protected-capture verification failed:', *errors, sep='\n- '); sys.exit(1)
print(f'Protected-capture verification passed ({len(expected)} original PCAPs).')
