#!/usr/bin/env bash
set -euo pipefail
LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="$LAB_ROOT"
case "${1:-}" in
 activate)
  echo 'Checking Docker daemon and Compose availability'
  docker info >/dev/null
  docker compose version
  docker compose -f "$ENGINE/compose.yaml" up -d --build
  echo 'Waiting for traffic fixtures and both gateways'
  for attempt in $(seq 1 180); do
   if docker exec managed-ipsec-right test -f /srv/data/.initialized && docker exec managed-ipsec-left test -x /usr/sbin/ipsec; then
    echo 'Gateways and HTTP/HLS/file fixtures are ready'; exit 0
   fi
   sleep 2
  done
  echo 'Timed out waiting for gateway fixtures' >&2; exit 1;;
 generate)
  OUT=${2:?output directory required}; PROFILES=${3:?}; LABELS=${4:?}; REPEATS=${5:?}
  EVALUATIONS=${6:-}; PROTOCOL=${7:-false}; EVAL_DURATION=${8:-20}
  mkdir -p "$OUT/lab"
  cp -R "$ENGINE/configs" "$ENGINE/generators" "$ENGINE/scripts" "$OUT/lab/"
  mkdir -p "$OUT/profiles" "$OUT/evidence"
  snapshot() {
   local profile=$1 sample=$2
   cp "$ENGINE/configs/p${profile}.conf" "$OUT/profiles/p${profile}.conf"
   docker exec managed-ipsec-left ipsec statusall > "$OUT/evidence/${sample}.txt"
  }
  IFS=, read -ra profile_list <<< "$PROFILES"
  IFS=, read -ra label_list <<< "$LABELS"
  IFS=, read -ra evaluation_list <<< "$EVALUATIONS"
  for profile in "${profile_list[@]}"; do
   for label in "${label_list[@]}"; do
    for repeat in $(seq 1 "$REPEATS"); do
     printf 'Capturing %s / P%02d / R%02d\n' "$label" "$profile" "$repeat"
     bash "$OUT/lab/scripts/capture_one.sh" "$label" "$profile" "$(printf 'R%02d' "$repeat")"
     snapshot "$profile" "${label}_p$(printf '%02d' "$profile")_$(printf 'R%02d' "$repeat")"
    done
   done
   for label in "${evaluation_list[@]}"; do
    for repeat in $(seq 1 "$REPEATS"); do
     run=$(printf 'R%02d' "$repeat")
     echo "Capturing evaluation $label / P$profile / $run"
     case "$label" in
      icmp_flood|udp_flood|beacon_burst) bash "$OUT/lab/scripts/capture_anomaly.sh" "$label" "$profile" "$run" "$EVAL_DURATION";;
      *) bash "$OUT/lab/scripts/capture_ood.sh" "$label" "$profile" "$run" "$EVAL_DURATION";;
     esac
     snapshot "$profile" "${label}_p$(printf '%02d' "$profile")_${run}"
    done
   done
   if [[ "$PROTOCOL" == true ]]; then
    echo "Capturing IKE negotiation and protocol validation for P$profile"
    bash "$OUT/lab/scripts/capture_protocol_validation.sh" "$profile"
    snapshot "$profile" "ike_session_p$(printf '%02d' "$profile")"
   fi
  done
  echo 'Checking captured metadata, packet counts and SHA-256 hashes'
  python3 - "$OUT" <<'PY'
import csv,hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(root/'lab/scripts'))
from pcap_info import inspect
rows=list(csv.DictReader((root/'metadata.csv').open()))
for row in rows:
    facts=inspect(root/row['pcap_path'])
    if facts['packet_count']<=0 or facts['sha256']!=row['sha256']: raise SystemExit('Capture integrity check failed')
    expected='udp4500_packets' if row['profile_id'] in ('P02','P04') else 'esp_packets'
    if facts[expected]<=0: raise SystemExit('Expected outer ESP/UDP4500 protection was not captured')
    print(f"Verified {row['sample_id']}: {facts['packet_count']} packets",flush=True)
artifacts=[]
for file in sorted(root.rglob('*')):
    if file.is_file() and 'lab' not in file.relative_to(root).parts:
        artifacts.append({'path':file.relative_to(root).as_posix(),'bytes':file.stat().st_size,'sha256':hashlib.sha256(file.read_bytes()).hexdigest()})
(root/'manifest.json').write_text(json.dumps({'schema_version':'managed-ipsec-lab.v2','samples':rows,'artifacts':artifacts},indent=2)+'\n')
manifest=root/'manifest.json'
artifacts.append({'path':'manifest.json','bytes':manifest.stat().st_size,'sha256':hashlib.sha256(manifest.read_bytes()).hexdigest()})
with (root/'artifacts.csv').open('w',newline='') as file:
    writer=csv.DictWriter(file,fieldnames=['path','bytes','sha256']);writer.writeheader();writer.writerows(artifacts)
PY
  # Reproduction scripts stay in the engine; archives contain produced artifacts.
  echo 'Dataset generation and integrity checks complete';;
 *) echo 'Expected activate or generate' >&2; exit 2;;
esac
