#!/bin/sh
set -eu
mkdir -p lab/runtime/left lab/runtime/right lab/output
# Build local StrongSwan images first. This prevents Compose from attempting
# to pull a nonexistent `alchemist-ipsec-lab-strongswan` repository.
docker compose -f lab/compose.yaml build left right
docker compose -f lab/compose.yaml up -d --no-build --remove-orphans
