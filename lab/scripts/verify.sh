#!/bin/sh
set -eu
profile=${1:?profile path required}
python3 lab/scripts/profile.py "$profile" >/dev/null
python3 lab/scripts/render.py "$profile"
docker compose -f lab/compose.yaml ps --status running --services | grep -qx left
docker compose -f lab/compose.yaml ps --status running --services | grep -qx right
docker compose -f lab/compose.yaml exec -T left swanctl --load-all >/dev/null
docker compose -f lab/compose.yaml exec -T right swanctl --load-all >/dev/null
left=$(docker compose -f lab/compose.yaml exec -T left swanctl --list-sas 2>&1 || true)
right=$(docker compose -f lab/compose.yaml exec -T right swanctl --list-sas 2>&1 || true)
printf '%s\n%s\n' "$left" "$right" | grep -Eqi 'ESTABLISHED|INSTALLED' || { echo "IPsec SA is not established; refusing capture" >&2; exit 1; }
