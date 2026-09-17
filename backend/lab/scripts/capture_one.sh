#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLASS="${1:?Usage: $0 CLASS PROFILE RUN}"; PROFILE="${2:?}"; RUN="${3:?Run must be R01-R05}"
case "$CLASS" in web|video|file_transfer|icmp|email|messaging|voip) ;; *) echo 'Invalid known class' >&2; exit 2;; esac
[[ "$PROFILE" =~ ^[1-5]$ && "$RUN" =~ ^R0[1-5]$ ]] || { echo 'profile 1-5 and run R01-R05 required' >&2; exit 2; }
DEST="$ROOT/pcaps/known/$CLASS/${CLASS}_p$(printf '%02d' "$PROFILE")_${RUN}.pcap"; TMP="${DEST}.partial"; mkdir -p "$(dirname "$DEST")"
[[ ! -e "$DEST" ]] || { echo "Refusing to overwrite $DEST" >&2; exit 3; }
rm -f "$TMP"  # An interrupted prior attempt is never a usable sample.
seed=$((10#$PROFILE * 100 + 10#${RUN#R} + $(date +%s) % 100000)); duration=45; generator=''; remote_start=''
case "$PROFILE" in
  5) src=fd10::1; dst=fd20::1; outer_filter='ip6'; base='http://[fd20::1]:8081'; ping_flag='-6' ;;
  4) src=172.31.0.2; dst=172.31.0.3; outer_filter='ip'; base='http://172.31.0.3:8080'; ping_flag='' ;;
  *) src=10.10.0.1; dst=10.20.0.1; outer_filter='ip'; base='http://10.20.0.1:8080'; ping_flag='' ;;
esac
case "$CLASS" in
 web) generator=multiple-http-object-requests; objects=$((4+seed%8)); duration=$((25+seed%20)); traffic="for i in \$(seq 1 $objects); do curl -fsS --connect-timeout 8 --max-time 60 --interface '$src' '$base/web/index.html' -o /dev/null; sleep 0.$((seed%7+1)); done";;
 video) generator=hls-segment-streaming; segments=$((8+seed%8)); rate="$((600+seed%700))K"; duration=$((35+seed%20)); traffic="curl -fsS --connect-timeout 8 --max-time 30 --interface '$src' '$base/hls/stream.m3u8' -o /dev/null; for i in \$(seq 0 $((segments-1))); do seg=\$(printf '%03d' \"\$i\"); curl -fsS --connect-timeout 8 --max-time 60 --interface '$src' --limit-rate $rate '$base/hls/seg'\$seg.ts -o /dev/null; sleep 1; done";;
 file_transfer) generator=bulk-http-file-download; size=$((8+(seed%4)*8)); duration=$((20+seed%20)); traffic="curl -fsS --connect-timeout 8 --max-time 180 --interface '$src' --limit-rate $((500+seed%1000))K '$base/files/file${size}M.bin' -o /dev/null";;
 icmp) generator=randomized-icmp-echo; count=$((30+seed%100)); duration=$((15+seed%20)); traffic="ping $ping_flag -I '$src' -c $count -i 0.15 -s $((32+seed%1200)) '$dst' >/dev/null";;
 email) generator=smtp-message-transfer; count=$((20+seed%31)); duration=45; remote_start="exec python3 /lab/generators/smtp_server.py --host '$dst' --port 2525"; traffic="python3 /lab/generators/smtp_send.py '$dst' --count $count --seed $seed";;
 messaging) generator=bidirectional-websocket-chat; count=$((100+seed%201)); duration=$((45+seed%46)); remote_start="exec python3 /lab/generators/chat.py server --host '$dst'"; traffic="python3 /lab/generators/chat.py client --host '$dst' --count $count --duration $duration --seed $seed";;
 voip) generator=rtp-audio-call; duration=$((30+seed%61)); rtp_src="rtp://$src:5006"; rtp_dst="rtp://$dst:5004"; [[ "$PROFILE" == 5 ]] && { rtp_src="rtp://[$src]:5006"; rtp_dst="rtp://[$dst]:5004"; }; remote_start="exec ffmpeg -hide_banner -loglevel error -re -f lavfi -i sine=frequency=700:sample_rate=8000 -t $duration -ac 1 -ar 8000 -c:a pcm_mulaw -f rtp $rtp_src"; traffic="ffmpeg -hide_banner -loglevel error -re -f lavfi -i sine=frequency=900:sample_rate=8000 -t $duration -ac 1 -ar 8000 -c:a pcm_mulaw -f rtp $rtp_dst";;
esac
completed=false
cleanup(){ docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true; [[ -n "${cap_pid:-}" ]] && kill "$cap_pid" >/dev/null 2>&1 || true; docker exec managed-ipsec-right pkill -f 'aiosmtpd|smtp_server.py|chat.py|ffmpeg.*rtp' >/dev/null 2>&1 || true; [[ "$completed" == true ]] || rm -f "$TMP" "$DEST"; }
trap cleanup EXIT INT TERM
"$ROOT/lab/scripts/apply_profile.sh" "$PROFILE" >/dev/null
if [[ "$PROFILE" == 5 ]]; then ping_check='ping -6 -c 2 -W 3 -I fd10::1 fd20::1'; elif [[ "$PROFILE" == 4 ]]; then ping_check='ping -c 2 -W 3 -I 172.31.0.2 172.31.0.3'; else ping_check='ping -c 2 -W 3 -I 10.10.0.1 10.20.0.1'; fi
if ! docker exec managed-ipsec-left sh -c "$ping_check" >/dev/null; then
  echo "Tunnel preflight failed for P$(printf '%02d' "$PROFILE")." >&2
  docker exec managed-ipsec-left ipsec statusall >&2 || true
  exit 5
fi
if [[ -n "$remote_start" ]]; then
  docker exec -d managed-ipsec-right sh -c "$remote_start" >/dev/null
  sleep 1
  case "$CLASS" in
    email)
      if ! docker exec managed-ipsec-right nc -z -w 2 "$dst" 2525; then
        echo "SMTP server did not start on $dst:2525" >&2
        exit 6
      fi
      ;;
    messaging)
      if ! docker exec managed-ipsec-right nc -z -w 2 "$dst" 8765; then
        echo "WebSocket server did not start on $dst:8765" >&2
        exit 6
      fi
      ;;
  esac
fi
docker exec managed-ipsec-left rm -f /tmp/managed-outer.pcap
docker exec managed-ipsec-left tcpdump -Z root -U -i eth0 -s 0 -w /tmp/managed-outer.pcap "$outer_filter and (esp or udp port 4500)" & cap_pid=$!; sleep 1
kill -0 "$cap_pid" || { echo 'Outer capture could not start' >&2; exit 7; }
docker exec managed-ipsec-left sh -c "$traffic"; sleep 1
docker exec managed-ipsec-left pkill -INT tcpdump >/dev/null 2>&1 || true; wait "$cap_pid"; cap_pid=''
docker cp managed-ipsec-left:/tmp/managed-outer.pcap "$TMP"
docker exec managed-ipsec-right pkill -f 'aiosmtpd|smtp_server.py|chat.py|ffmpeg.*rtp' >/dev/null 2>&1 || true
case "$CLASS" in
  web) params=$(printf '{"duration_s":%s,"object_count":%s,"seed":%s}' "$duration" "$objects" "$seed");;
  video) params=$(printf '{"duration_s":%s,"segment_count":%s,"rate":"%s","seed":%s}' "$duration" "$segments" "$rate" "$seed");;
  file_transfer) params=$(printf '{"duration_s":%s,"file_size_mib":%s,"rate_kib_s":%s,"seed":%s}' "$duration" "$size" "$((500+seed%1000))" "$seed");;
  icmp) params=$(printf '{"duration_s":%s,"packet_count":%s,"payload_bytes":%s,"seed":%s}' "$duration" "$count" "$((32+seed%1200))" "$seed");;
  email) params=$(printf '{"duration_s":%s,"message_count":%s,"seed":%s}' "$duration" "$count" "$seed");;
  messaging) params=$(printf '{"duration_s":%s,"message_count":%s,"seed":%s}' "$duration" "$count" "$seed");;
  voip) params=$(printf '{"duration_s":%s,"codec":"pcm_mulaw","sample_rate_hz":8000,"packetization":"rtp","seed":%s}' "$duration" "$seed");;
esac
mv "$TMP" "$DEST"
python3 "$ROOT/lab/scripts/record_capture.py" "$DEST" --label "$CLASS" --profile "$PROFILE" --run "$RUN" --generator "$generator" --params "$params" --interface gateway-eth0-outer
completed=true
echo "Captured $DEST"
