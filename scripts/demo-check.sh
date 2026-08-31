#!/usr/bin/env bash
set -euo pipefail

core_url="${CORE_HTTP_URL:-http://127.0.0.1:8080}"
pcap_path="${1:-ipsec_esp/ipsec_esp_capture_1/capture.pcap}"

if [[ ! -f "$pcap_path" ]]; then
  echo "PCAP not found: $pcap_path" >&2
  exit 1
fi

json_field() {
  local field="$1"
  python3 -c "import json, sys; print(json.load(sys.stdin)['$field'])"
}

echo "Checking Core at $core_url ..."
curl --fail --silent --show-error "$core_url/live" >/dev/null

echo "Uploading $pcap_path ..."
upload="$(curl --fail --silent --show-error --request POST --form "pcap=@$pcap_path" "$core_url/api/v1/pcap")"
source_id="$(printf '%s' "$upload" | json_field source_id)"

echo "Starting ML-enabled analysis ..."
created="$(curl --fail --silent --show-error --request POST --header 'content-type: application/json' --data "{\"source_id\":\"$source_id\",\"enable_ml\":true}" "$core_url/api/v1/analyses")"
analysis_id="$(printf '%s' "$created" | json_field analysis_id)"

for _ in $(seq 1 60); do
  result="$(curl --fail --silent --show-error "$core_url/api/v1/analyses/$analysis_id")"
  state="$(printf '%s' "$result" | json_field state)"
  case "$state" in
    ANALYSIS_STATE_COMPLETED)
      printf '%s\n' "$result"
      echo "Demo passed: analysis $analysis_id completed."
      exit 0
      ;;
    ANALYSIS_STATE_FAILED|ANALYSIS_STATE_CANCELLED)
      printf '%s\n' "$result" >&2
      echo "Demo failed: analysis $analysis_id ended in $state." >&2
      exit 1
      ;;
  esac
  sleep 1
done

echo "Demo timed out waiting for analysis $analysis_id." >&2
exit 1
