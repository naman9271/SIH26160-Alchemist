#!/bin/sh
set -eu
profile=${1:?profile path required}
data=$(python3 lab/scripts/profile.py "$profile")
id=$(printf '%s' "$data" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
duration=$(printf '%s' "$data" | python3 -c 'import json,sys; print(json.load(sys.stdin)["duration_seconds"])')
run_id="${id}-$(date -u +%Y%m%dT%H%M%SZ)"
out="lab/output/$run_id"; mkdir -p "$out"
lab/scripts/verify.sh "$profile"
docker compose -f lab/compose.yaml exec -T left tcpdump -i any -U -w /tmp/outer.pcap 'udp port 500 or udp port 4500 or esp or ah' >/dev/null 2>&1 & cap=$!
trap 'kill "$cap" 2>/dev/null || true' EXIT INT TERM
traffic=$(printf '%s' "$data" | python3 -c 'import json,sys; print(json.load(sys.stdin)["traffic"])')
case "$traffic" in web) docker compose -f lab/compose.yaml exec -T traffic-client wget -qO- http://traffic-server:8080/index.html >/dev/null;; video) docker compose -f lab/compose.yaml exec -T traffic-client iperf3 -c traffic-server -t "$duration" >/dev/null;; icmp) docker compose -f lab/compose.yaml exec -T traffic-client ping -c 4 traffic-server >/dev/null;; *) docker compose -f lab/compose.yaml exec -T traffic-client sh -c 'printf "labelled synthetic request\n" | nc traffic-server 2525' ;; esac
sleep 1; kill "$cap" 2>/dev/null || true; wait "$cap" 2>/dev/null || true
docker compose -f lab/compose.yaml cp left:/tmp/outer.pcap "$out/outer.pcap"
docker compose -f lab/compose.yaml exec -T left swanctl --list-sas > "$out/gateway-state.txt"
sha256sum "$profile" "$out/outer.pcap" "$out/gateway-state.txt" > "$out/SHA256SUMS"
python3 lab/scripts/manifest.py "$profile" "$out" "$run_id"
python3 - "$out" "$run_id" "$profile" "$traffic" "$duration" <<'PY'
import csv, json, pathlib, sys
out, run_id, profile, traffic, duration = sys.argv[1:]
manifest = json.loads((pathlib.Path(out) / "manifest.json").read_text())
capture = manifest["capture"]
fields = ["run_id", "profile", "traffic", "duration_seconds", "capture_file", "capture_sha256", "packet_count", "ground_truth_source"]
row = {"run_id": run_id, "profile": profile, "traffic": traffic, "duration_seconds": duration,
       "capture_file": capture["file"], "capture_sha256": capture["sha256"],
       "packet_count": "", "ground_truth_source": manifest["ground_truth_source"]}
with (pathlib.Path(out) / "generated-artifacts.csv").open("w", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader(); writer.writerow(row)
PY
echo "$out"
