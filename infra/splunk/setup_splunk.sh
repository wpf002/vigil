#!/usr/bin/env bash
#
# One-time Splunk setup for the VIGIL test harness:
#   1. create the `vigil_test` index (where sample data lands)
#   2. enable the HEC token used by load_sample_data.sh
#   3. create a scheduled saved-search ALERT that flags suspicious process
#      creation — this is what the VIGIL ingestor's Splunk-core connector polls
#      (via /services/alerts/fired_alerts).
#
# Requires the 60-day Enterprise trial (default) — Splunk Free disables alerting.
#
# Usage: bash infra/splunk/setup_splunk.sh
#
set -euo pipefail

MGMT="${SPLUNK_MGMT:-https://localhost:8089}"
USER="${SPLUNK_USER:-admin}"
PASS="${SPLUNK_PASSWORD:-Changeme123!}"
HEC_TOKEN="${SPLUNK_HEC_TOKEN:-vigil-hec-token-00000000}"
INDEX="${SPLUNK_INDEX:-vigil_test}"
C=(curl -sk -u "$USER:$PASS")

echo "1/4 creating index '$INDEX'..."
"${C[@]}" "$MGMT/services/data/indexes" -d name="$INDEX" >/dev/null || true

echo "2/4 enabling HEC + token..."
"${C[@]}" "$MGMT/services/data/inputs/http/http" -d disabled=0 >/dev/null || true
"${C[@]}" "$MGMT/services/data/inputs/http" \
  -d name=vigil-hec -d token="$HEC_TOKEN" -d index="$INDEX" -d disabled=0 >/dev/null 2>&1 || true

echo "3/4 creating/updating the VIGIL saved-search alert 'VIGIL - Suspicious Process Creation'..."
NAME="VIGIL - Suspicious Process Creation"
NAME_ENC="VIGIL%20-%20Suspicious%20Process%20Creation"
# Broad kill-chain coverage: execution, download, priv-esc, persistence,
# credential access, discovery, lateral movement, collection/exfil.
SPL='search index='"$INDEX"' (
  (process_name=powershell.exe AND (CommandLine="*-enc*" OR CommandLine="*FromBase64*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*Compress-Archive*"))
  OR process_name=fodhelper.exe
  OR process_name=certutil.exe
  OR (process_name=sc.exe AND CommandLine="*create*")
  OR (process_name=reg.exe AND CommandLine="*CurrentVersion\\Run*")
  OR CommandLine="*lsass*" OR CommandLine="*sekurlsa*" OR process_name=mimikatz.exe
  OR CommandLine="*ntds*"
  OR process_name=psexec.exe
  OR (process_name=net.exe AND CommandLine="*/domain*")
  OR (process_name=whoami.exe AND CommandLine="*/priv*")
  OR process_name=nltest.exe
) | table _time host user process_name CommandLine'

# Create if new (ignore 409), then always PUT the current SPL/schedule so re-runs update it.
"${C[@]}" "$MGMT/services/saved/searches" \
  --data-urlencode name="$NAME" --data-urlencode search="$SPL" >/dev/null 2>&1 || true
"${C[@]}" "$MGMT/services/saved/searches/$NAME_ENC" \
  --data-urlencode search="$SPL" \
  -d dispatch.earliest_time="-24h" \
  -d cron_schedule="*/5 * * * *" \
  -d is_scheduled=1 \
  -d "alert_type=number of events" \
  -d "alert_comparator=greater than" \
  -d alert_threshold=0 \
  -d "alert.track=1" >/dev/null || true

echo "4/4 done."
echo
echo "Next:"
echo "  bash infra/splunk/load_sample_data.sh    # push sample events"
echo "  point the VIGIL ingestor at this Splunk (see vigil-ingestor.env.example)"
