#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
mkdir -p "$ROOT/pcaps/protocol_validation"

capture_profile() {
  local p="$1"
  local out="$ROOT/pcaps/protocol_validation/ike_session_p$(printf '%02d' "$p").pcap"
  local tmp="${out}.partial" pid='' completed=false ping_cmd
  [[ ! -e "$out" ]] || return 0
  rm -f "$tmp"
  cleanup() {
    docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    [[ "$completed" == true ]] || rm -f "$tmp" "$out"
  }
  trap cleanup RETURN

  docker exec managed-ipsec-left ipsec stop >/dev/null 2>&1 || true
  docker exec managed-ipsec-right ipsec stop >/dev/null 2>&1 || true
  docker exec managed-ipsec-left rm -f /tmp/managed-protocol.pcap
  docker exec managed-ipsec-left tcpdump -Z root -U -i eth0 -s 0 -w /tmp/managed-protocol.pcap 'udp port 500 or udp port 4500 or esp' &
  pid=$!
  sleep 1
  kill -0 "$pid" || { echo 'Protocol capture could not start' >&2; return 7; }
  "$ROOT/lab/scripts/apply_profile.sh" "$p" >/dev/null
  case "$p" in
    5) ping_cmd='ping -6 -c 3 -I fd10::1 fd20::1' ;;
    7) ping_cmd='ping -6 -c 3 -I fd00:31::2 fd00:31::3' ;;
    4|6) ping_cmd='ping -c 3 -I 172.31.0.2 172.31.0.3' ;;
    *) ping_cmd='ping -c 3 -I 10.10.0.1 10.20.0.1' ;;
  esac
  docker exec managed-ipsec-left sh -c "$ping_cmd" >/dev/null
  if [[ "$p" == 8 ]]; then
    # P08 has a 30-second CHILD lifetime. Keep the capture open through the
    # first rekey and generate traffic on the replacement SA.
    sleep 35
    docker exec managed-ipsec-left sh -c "$ping_cmd" >/dev/null
  fi
  sleep 1
  docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true
  wait "$pid"
  pid=''
  docker cp managed-ipsec-left:/tmp/managed-protocol.pcap "$tmp"
  local expected_outer facts
  case "$p" in
    1) expected_outer=esp; facts='IKEv2; native ESP; IPv4; PSK authentication' ;;
    2) expected_outer=udp4500; facts='IKEv2; UDP/4500; IPv4; forced encapsulation; PSK authentication' ;;
    3) expected_outer=esp; facts='IKEv1; native ESP; IPv4; PSK authentication' ;;
    4) expected_outer=udp4500; facts='IKEv1; UDP/4500; IPv4; forced encapsulation; PSK authentication' ;;
    5) expected_outer=esp; facts='IKEv2; native ESP; IPv6; PSK authentication' ;;
    6) expected_outer=esp; facts='IKEv2; transport mode; native ESP; IPv4; PSK authentication; CHILD PFS configured' ;;
    7) expected_outer=esp; facts='IKEv2; transport mode; native ESP; IPv6; PSK authentication; CHILD PFS configured' ;;
    8) expected_outer=esp; facts='IKEv2; tunnel mode; native ESP; IPv4; PSK authentication; short CHILD lifetime and PFS rekey configured' ;;
  esac
  python3 "$ROOT/lab/scripts/pcap_info.py" "$tmp" --require-outer "$expected_outer" >/dev/null
  tcpdump -nn -r "$tmp" > "$tmp.trace" 2>/dev/null
  grep -qi isakmp "$tmp.trace" || {
    echo "Protocol capture P$(printf '%02d' "$p") has no IKE packets." >&2
    return 5
  }
  rm -f "$tmp.trace"
  mv "$tmp" "$out"
  local duration=8
  [[ "$p" == 8 ]] && duration=43
  python3 "$ROOT/lab/scripts/record_capture.py" "$out" --label protocol_session --profile "$p" --role protocol_validation --generator ike-negotiation-and-esp --params "{\"duration_s\":$duration,\"ike_before_traffic\":true,\"rekey_observed\":$([[ \"$p\" == 8 ]] && echo true || echo false)}" --protocol-facts "$facts" --interface gateway-eth0-outer
  completed=true
}

for p in "${@:-1}"; do
  capture_profile "$p"
done
