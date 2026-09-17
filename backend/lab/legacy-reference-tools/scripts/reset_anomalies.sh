#!/usr/bin/env bash
# Remove generated anomaly samples only.  An archive directory, if present,
# is deliberately untouched.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ANOMALY_DIR="$ROOT/pcaps/anomaly"

find "$ANOMALY_DIR" -maxdepth 1 -type f -name '*.pcap' -print -delete
find "$ANOMALY_DIR" -maxdepth 1 -type f -name '*.partial' -print -delete
python3 "$ROOT/lab/scripts/migrate_metadata.py"
echo 'Generated anomaly captures and their metadata rows were removed. Any archive directory was left untouched.'
