#!/usr/bin/env python3
import hashlib, json, pathlib, sys, datetime
from profile import load
profile, out, run_id = load(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
pcap = out / "outer.pcap"
manifest = {"schema_version":"ipsec-lab-manifest.v1","run_id":run_id,"created_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"profile":profile,"capture":{"point":"left underlay outer IPsec only","bpf":"udp port 500 or udp port 4500 or esp or ah","file":"outer.pcap","sha256":digest(pcap),"bytes":pcap.stat().st_size},"gateway_state_sha256":digest(out / "gateway-state.txt"),"ground_truth_source":"swanctl --list-sas + profile"}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
