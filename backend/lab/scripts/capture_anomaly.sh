#!/usr/bin/env bash
# Capture one isolated anomaly sample.  A failed traffic or capture check never
# becomes a dataset file or metadata row.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TYPE="${1:?Usage: $0 TYPE PROFILE RUN [DURATION_SECONDS]}"
PROFILE="${2:?Usage: $0 TYPE PROFILE RUN [DURATION_SECONDS]}"
RUN="${3:?Usage: $0 TYPE PROFILE RUN [DURATION_SECONDS]}"
DURATION="${4:-30}"

case "$TYPE" in icmp_flood|udp_flood|beacon_burst) ;; *) echo 'TYPE must be icmp_flood, udp_flood, or beacon_burst' >&2; exit 2;; esac
case "$PROFILE" in 1|2|3|4|5) ;; *) echo 'PROFILE must be 1 through 5' >&2; exit 2;; esac
[[ "$RUN" =~ ^R0[1-5]$ ]] || { echo 'RUN must be R01 through R05' >&2; exit 2; }
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || { echo 'DURATION_SECONDS must be a positive integer' >&2; exit 2; }

if [[ "$PROFILE" == 5 ]]; then
  src='fd10::1'; dst='fd20::1'; ping_cmd='ping -6'; nc_flags='-6'; outer='esp'
elif [[ "$PROFILE" == 4 ]]; then
  src='172.31.0.2'; dst='172.31.0.3'; ping_cmd='ping'; nc_flags=''; outer='udp4500'
else
  src='10.10.0.1'; dst='10.20.0.1'; ping_cmd='ping'; nc_flags=''; outer='esp'
  [[ "$PROFILE" == 2 ]] && outer='udp4500'
fi

DEST="$ROOT/pcaps/anomaly/${TYPE}_p$(printf '%02d' "$PROFILE")_${RUN}.pcap"
TMP="${DEST}.partial"
mkdir -p "$(dirname "$DEST")"
[[ ! -e "$DEST" ]] || { echo "Refusing to overwrite existing sample: $DEST" >&2; exit 3; }
rm -f "$TMP"

cap_pid=''
cleanup() {
  docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true
  [[ -z "$cap_pid" ]] || kill "$cap_pid" >/dev/null 2>&1 || true
  rm -f "$TMP"
}
trap cleanup EXIT INT TERM

"$ROOT/lab/scripts/apply_profile.sh" "$PROFILE" >/dev/null
if ! docker exec managed-ipsec-left sh -c "$ping_cmd -c 2 -W 3 -I '$src' '$dst'" >/dev/null; then
  echo "Tunnel preflight failed for P$(printf '%02d' "$PROFILE")." >&2
  docker exec managed-ipsec-left ipsec statusall >&2 || true
  exit 5
fi


case "$TYPE" in
  icmp_flood)
    traffic="timeout --signal=INT $DURATION $ping_cmd -i 0.02 -s 512 -I '$src' '$dst' >/dev/null || test \$? -eq 124"
    ;;
  udp_flood)
    traffic="timeout --signal=INT $DURATION sh -c 'while :; do dd if=/dev/urandom bs=1200 count=1 status=none | nc $nc_flags -u -w 1 -s \"$src\" \"$dst\" 9999; sleep 0.05; done' || test \$? -eq 124"
    ;;
  beacon_burst)
    burst=$(( DURATION > 10 ? DURATION - 10 : 1 ))
    traffic="for i in \$(seq 1 20); do printf beacon | nc $nc_flags -u -w 1 -s '$src' '$dst' 9900; sleep 0.5; done; timeout --signal=INT $burst sh -c 'while :; do dd if=/dev/urandom bs=900 count=1 status=none | nc $nc_flags -u -w 1 -s \"$src\" \"$dst\" 9900; sleep 0.05; done' || test \$? -eq 124"
    ;;
esac

docker exec managed-ipsec-left rm -f /tmp/managed-anomaly.pcap
docker exec managed-ipsec-left tcpdump -Z root -U -i eth0 -s 0 -w /tmp/managed-anomaly.pcap "(ip or ip6) and (esp or udp port 4500)" &
cap_pid=$!
sleep 1
kill -0 "$cap_pid" || { echo 'Anomaly capture could not start' >&2; exit 7; }
docker exec managed-ipsec-left sh -c "$traffic"
sleep 1
docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true
wait "$cap_pid"
cap_pid=''
docker cp managed-ipsec-left:/tmp/managed-anomaly.pcap "$TMP"

python3 "$ROOT/lab/scripts/pcap_info.py" "$TMP" --require-outer "$outer" >/dev/null
mv "$TMP" "$DEST"
trap - EXIT INT TERM
python3 "$ROOT/lab/scripts/record_capture.py" "$DEST" --label unknown --profile "$PROFILE" --run "$RUN" --role anomaly_eval --generator "$TYPE" --params "{\"duration_s\":$DURATION,\"isolated_lab\":true}" --anomaly "$TYPE" --interface gateway-eth0-outer
echo "Captured $DEST"
