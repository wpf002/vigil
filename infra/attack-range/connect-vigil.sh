#!/usr/bin/env bash
#
# Point VIGIL's ingestor at an external Splunk Attack Range instance (in AWS) —
# a TRUE external SIEM connection. VIGIL's SEARCH-mode poller pulls the range's
# Sysmon telemetry and runs VIGIL's detections over it.
#
# Usage:
#   bash connect-vigil.sh <splunk_public_ip> <splunk_password> [--railway]
#
#   (default)   prints an .env you drop into services/ingestor/.env for a LOCAL
#               ingestor  (whitelist YOUR IP in attack_range.yml ip_whitelist).
#   --railway   sets the vars on the deployed Railway `ingestor` service instead
#               (whitelist 0.0.0.0/0 or use the range VPN, since Railway egress
#               is not a static IP).
#
set -euo pipefail

IP="${1:?usage: connect-vigil.sh <splunk_public_ip> <splunk_password> [--railway]}"
PASS="${2:?splunk password required}"
MODE="${3:-local}"

# Attack Range indexes Windows/Sysmon telemetry (adjust if your build differs —
# check with:  | eventcount summarize=false index=* ).
INDEX="${SPLUNK_INDEX:-main}"
TENANT="${VIGIL_TENANT_ID:-4780f220-57aa-4453-9448-958fc23ab60b}"

read -r -d '' VARS <<EOF || true
SIEM_MODE=search
SPLUNK_HOST=https://${IP}:8089
SPLUNK_USERNAME=admin
SPLUNK_PASSWORD=${PASS}
SPLUNK_VERIFY_SSL=false
SPLUNK_SEARCH_INDEX=${INDEX}
SPLUNK_POLL_INTERVAL_SECONDS=30
TENANT_ID=${TENANT}
EOF

if [[ "$MODE" == "--railway" ]]; then
  echo "Pointing the Railway ingestor at Attack Range Splunk ${IP} ..."
  args=()
  while IFS= read -r line; do [[ -n "$line" ]] && args+=(--set "$line"); done <<< "$VARS"
  railway variables --service ingestor "${args[@]}"
  railway up services/ingestor --path-as-root --service ingestor --ci
  echo "Done. VIGIL now polls the external Attack Range Splunk."
else
  echo "# Append to services/ingestor/.env, then run the ingestor locally:"
  echo "#   cd services/ingestor && .venv/bin/python run.py"
  echo "$VARS"
fi
