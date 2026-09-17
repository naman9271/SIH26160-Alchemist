#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LABEL=${1:?}; PROFILE=${2:?}; RUN=${3:?}; DURATION=${4:-20}
case "$LABEL" in dns) port=5353;udp=1;;ssh)port=2222;udp=0;;gaming_udp)port=27015;udp=1;;database)port=5432;udp=0;;remote_desktop)port=3389;udp=1;;*)exit 2;;esac
[[ "$PROFILE" =~ ^[1-5]$ && "$RUN" =~ ^R0[1-5]$ && "$DURATION" =~ ^[0-9]+$ ]] || exit 2
src=10.10.0.1;dst=10.20.0.1; flags=""
[[ "$PROFILE" == 4 ]] && { src=172.31.0.2;dst=172.31.0.3; }
[[ "$PROFILE" == 5 ]] && { src=fd10::1;dst=fd20::1;flags="-6"; }
[[ "$udp" == 1 ]] && flags="$flags -u"
out="$ROOT/pcaps/ood/${LABEL}_p$(printf '%02d' "$PROFILE")_${RUN}.pcap"
mkdir -p "$(dirname "$out")";[[ ! -e "$out" ]] || exit 3
trap 'docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true' EXIT INT TERM
bash "$ROOT/lab/scripts/apply_profile.sh" "$PROFILE"
docker exec managed-ipsec-left rm -f /tmp/managed-ood.pcap
docker exec managed-ipsec-left tcpdump -Z root -U -i eth0 -s 0 -w /tmp/managed-ood.pcap 'esp or udp port 4500' & pid=$!
sleep 1
kill -0 "$pid" || { echo 'OOD capture could not start' >&2; exit 7; }
docker exec managed-ipsec-left sh -c "timeout $DURATION sh -c 'while :; do printf \"$LABEL-request\\n\" | nc $flags -w 1 -s $src $dst $port || true; sleep .15; done' || test \$? -eq 124"
sleep 1;docker exec managed-ipsec-left pkill -INT tcpdump || true;wait "$pid"
docker cp managed-ipsec-left:/tmp/managed-ood.pcap "$out.partial"
python3 "$ROOT/lab/scripts/pcap_info.py" "$out.partial" >/dev/null
mv "$out.partial" "$out"
python3 "$ROOT/lab/scripts/record_capture.py" "$out" --label "$LABEL" --profile "$PROFILE" --run "$RUN" --role ood_eval --generator "$LABEL" --params "{\"duration_s\":$DURATION,\"isolated_lab\":true}" --interface gateway-eth0-outer
echo "Captured $out"
