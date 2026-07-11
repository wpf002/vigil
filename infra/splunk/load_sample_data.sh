#!/usr/bin/env bash
#
# Push the sample security events into Splunk via HEC (HTTP Event Collector).
# Splunk must be up first: docker compose -f infra/splunk/docker-compose.yml up -d
#
# Usage: bash infra/splunk/load_sample_data.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# HEC listens over HTTPS by default (self-signed cert → curl -k).
HEC_URL="${HEC_URL:-https://localhost:8088}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-vigil-hec-token-00000000}"
INDEX="${SPLUNK_INDEX:-vigil_test}"
SOURCETYPE="${SPLUNK_SOURCETYPE:-vigil:winsecurity}"

echo "Loading sample events into Splunk index '$INDEX' via $HEC_URL ..."

count=0
while IFS= read -r line; do
  [ -z "$line" ] && continue
  # Wrap each raw event dict in a HEC envelope.
  payload=$(python3 - "$line" "$INDEX" "$SOURCETYPE" <<'PY'
import json, sys, time
event = json.loads(sys.argv[1])
# Promote host to the HEC envelope (becomes Splunk's single host metadata field)
# and drop it from the body so it isn't also auto-extracted → no multivalue host.
host = event.pop("host", None)
env = {"event": event, "sourcetype": sys.argv[3], "index": sys.argv[2], "time": time.time()}
if host:
    env["host"] = host
print(json.dumps(env))
PY
)
  curl -s -k "$HEC_URL/services/collector/event" \
    -H "Authorization: Splunk $HEC_TOKEN" \
    -d "$payload" > /dev/null
  count=$((count + 1))
done < "$HERE/sample_events.jsonl"

echo "Sent $count events. Verify in Splunk Web:  index=$INDEX | stats count by process_name"
