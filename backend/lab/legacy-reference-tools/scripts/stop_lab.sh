#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT/lab"
docker compose down --remove-orphans
echo 'Lab containers and their dedicated network stopped; dataset files were retained.'
