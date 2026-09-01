#!/bin/sh
set -eu

exec python -m src.grpc_server \
  --host "${ML_GRPC_HOST:-0.0.0.0}" \
  --port "${ML_GRPC_PORT:-50051}" \
  "$@"
