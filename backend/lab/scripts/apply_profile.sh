#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="${1:?Usage: $0 PROFILE_NUMBER}"
CONF="$ROOT/lab/configs/p${PROFILE}.conf"
[[ -f "$CONF" ]] || { echo "Profile configuration not found: $CONF" >&2; exit 2; }
PSK='IPsec-ML-Lab-PSK-2026-DoNotReuse'
for c in managed-ipsec-left managed-ipsec-right; do
  docker cp "$CONF" "$c:/etc/ipsec.conf"
  printf '%s\n' "@left @right : PSK \"$PSK\"" | docker exec -i "$c" sh -c 'cat >/etc/ipsec.secrets && chmod 600 /etc/ipsec.secrets'
  docker exec "$c" pkill -f 'aiosmtpd|smtp_server.py|websocket' >/dev/null 2>&1 || true
done
for c in managed-ipsec-left managed-ipsec-right; do
  docker exec "$c" ipsec stop >/dev/null 2>&1 || true
done
# A stopped daemon can leave its PID/socket files behind after an interrupted
# capture.  Remove only those runtime files before starting one clean daemon.
for c in managed-ipsec-left managed-ipsec-right; do
  docker exec "$c" sh -c 'rm -f /run/charon.pid /var/run/charon.pid /run/charon.ctl /var/run/charon.ctl'
done
sleep 1
docker exec managed-ipsec-right ipsec start >/dev/null
sleep 1
docker exec managed-ipsec-left ipsec start >/dev/null
sleep 2
for _ in $(seq 1 10); do
  docker exec managed-ipsec-left ipsec up lab >/dev/null 2>&1 || true
  if docker exec managed-ipsec-left ipsec statusall | grep -q 'INSTALLED'; then
    docker exec managed-ipsec-left ipsec statusall
    exit 0
  fi
  sleep 1
done
echo "P${PROFILE} did not establish an IPsec CHILD_SA." >&2
docker exec managed-ipsec-left ipsec statusall >&2
exit 1
