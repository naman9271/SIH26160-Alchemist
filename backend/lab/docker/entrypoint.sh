#!/usr/bin/env bash
set -euo pipefail
if [[ "${LAB_SIDE:-}" == left ]]; then
  ip addr add 10.10.0.1/32 dev lo 2>/dev/null || true; ip -6 addr add fd10::1/128 dev lo 2>/dev/null || true
elif [[ "${LAB_SIDE:-}" == right ]]; then
  ip addr add 10.20.0.1/32 dev lo 2>/dev/null || true; ip -6 addr add fd20::1/128 dev lo 2>/dev/null || true
  mkdir -p /srv/data/{web,files,hls}
  if [[ ! -f /srv/data/.initialized ]]; then
    printf '<html><body>controlled lab page</body></html>\n' >/srv/data/web/index.html
    yes 'body { font-family: sans-serif; }' | head -c 40000 >/srv/data/web/style.css || true
    yes 'console.log("lab")' | head -c 60000 >/srv/data/web/app.js || true
    head -c 120000 /dev/urandom >/srv/data/web/image1.bin; head -c 220000 /dev/urandom >/srv/data/web/image2.bin
    for n in 8 16 24 32 48; do dd if=/dev/urandom of=/srv/data/files/file${n}M.bin bs=1M count="$n" status=none; done
    ffmpeg -hide_banner -loglevel error -f lavfi -i testsrc2=size=640x360:rate=25 -f lavfi -i sine=frequency=1000:sample_rate=48000 -t 60 -c:v mpeg2video -b:v 900k -c:a mp2 -b:a 128k -f hls -hls_time 4 -hls_list_size 0 -hls_segment_filename '/srv/data/hls/seg%03d.ts' /srv/data/hls/stream.m3u8
    touch /srv/data/.initialized
  fi
  python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv/data >/var/log/http4.log 2>&1 &
  python3 -m http.server 8081 --bind :: --directory /srv/data >/var/log/http6.log 2>&1 &
fi
exec "$@"
