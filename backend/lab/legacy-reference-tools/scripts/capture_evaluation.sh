#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
capture(){
  local name=$1 label=$2 profile=$3 role=$4 anomaly=$5 cmd=$6
  local run="${name##*_}"
  mkdir -p "$ROOT/pcaps/$role"
  local out="$ROOT/pcaps/$role/${name}.pcap"
  [[ ! -e "$out" ]] || return 0
  "$ROOT/lab/scripts/apply_profile.sh" "$profile" >/dev/null
  local idx veth pid; idx=$(docker exec managed-ipsec-left cat /sys/class/net/eth0/iflink); veth=$(ip -o link show | awk -F': ' -v i="$idx" '$1==i {split($2,a,"@");print a[1]}'); [[ -n "$veth" ]] || exit 4
  tcpdump -U -i "$veth" -s 0 -w "$out" 'esp or udp port 4500' >/tmp/ipsec-eval-tcpdump.log 2>&1 & pid=$!
  trap 'kill "$pid" >/dev/null 2>&1 || true' RETURN; sleep 1; docker exec managed-ipsec-left sh -c "$cmd"; sleep 1; kill "$pid" >/dev/null 2>&1 || true; trap - RETURN
  if [[ -n "$anomaly" ]]; then
    python3 "$ROOT/lab/scripts/record_capture.py" "$out" --label "$label" --profile "$profile" --run "$run" --role "$([[ $role == ood ]] && echo ood_eval || echo anomaly_eval)" --generator "$label" --params '{"duration_s":45,"isolated_lab":true}' --anomaly "$anomaly"
  else
    python3 "$ROOT/lab/scripts/record_capture.py" "$out" --label "$label" --profile "$profile" --run "$run" --role ood_eval --generator "$label" --params '{"duration_s":20,"isolated_lab":true}'
  fi
}
# Complete the independent OOD matrix.  The source/destination are the tunnel
# selectors; P04 uses its transport-mode outer endpoints.
for p in 1 2 3 4 5; do
  [[ "$p" == 5 ]] && continue  # P05 needs IPv6-specific OOD generation below.
  src=10.10.0.1; dst=10.20.0.1; [[ "$p" == 4 ]] && { src=172.31.0.2; dst=172.31.0.3; }
  capture "dns_p$(printf '%02d' "$p")_R01" dns "$p" ood '' "for i in \$(seq 1 120); do printf 'dns-%s' \$i | nc -u -w 1 -s $src $dst 5353 || true; sleep .15; done"
  capture "ssh_p$(printf '%02d' "$p")_R01" ssh "$p" ood '' "for i in \$(seq 1 30); do printf 'ssh-command-%s\\n' \$i | nc -w 1 -s $src $dst 2222 || true; sleep .4; done"
  capture "gaming_udp_p$(printf '%02d' "$p")_R01" gaming_udp "$p" ood '' "for i in \$(seq 1 250); do head -c 160 /dev/urandom | nc -u -w 1 -s $src $dst 27015 || true; sleep .08; done"
  capture "database_p$(printf '%02d' "$p")_R01" database "$p" ood '' "for i in \$(seq 1 40); do printf 'SELECT %s;' \$i | nc -w 1 -s $src $dst 5432 || true; sleep .3; done"
  capture "remote_desktop_p$(printf '%02d' "$p")_R01" remote_desktop "$p" ood '' "for i in \$(seq 1 80); do head -c 900 /dev/urandom | nc -u -w 1 -s $src $dst 3389 || true; sleep .12; done"
done
for kind in dns ssh gaming_udp database remote_desktop; do
  port=5353; [[ "$kind" == ssh ]] && port=2222; [[ "$kind" == gaming_udp ]] && port=27015; [[ "$kind" == database ]] && port=5432; [[ "$kind" == remote_desktop ]] && port=3389
  capture "${kind}_p05_R01" "$kind" 5 ood '' "for i in \$(seq 1 80); do head -c 120 /dev/urandom | nc -6 -u -w 1 -s fd10::1 fd20::1 $port || true; sleep .15; done"
done
# Anomalies use the fail-fast runner so an empty PCAP is never retained.  Keep
# this batch at 30 samples (10 per type) while covering every profile twice.
for n in $(seq 1 10); do
  p=$(( (n - 1) % 5 + 1 ))
  run="R$(printf '%02d' "$(( (n - 1) / 5 + 1 ))")"
  for kind in icmp_flood udp_flood beacon_burst; do
    "$ROOT/lab/scripts/capture_anomaly.sh" "$kind" "$p" "$run" 30
  done
done
