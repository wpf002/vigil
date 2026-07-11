# Free Splunk test harness for VIGIL

Stand up a **free** Splunk in Docker and feed VIGIL real SIEM data. Isolated
from the main VIGIL compose stack so it can't interfere with the app.

## Cost

**$0.** The `splunk/splunk` image runs a **60-day Enterprise trial** on first
boot — full features, including the scheduled saved-search *alerts* the VIGIL
ingestor polls. After 60 days it auto-reverts to **Splunk Free** (500 MB/day
indexing, free forever). Caveat: Splunk Free *disables* alerting/scheduled
searches, so for ongoing alert polling either recreate the container (fresh
trial) or switch the ingestor to the ad-hoc search path. There is no paid tier
involved and nothing asks for a credit card.

## 1. Start Splunk

```bash
docker compose -f infra/splunk/docker-compose.yml up -d
# first boot takes ~1–2 min; watch health:
docker inspect --format '{{.State.Health.Status}}' vigil-splunk
```

Web UI: <http://localhost:8000>  (user `admin`, password `Changeme123!`).
Override the password/HEC token via env before `up`:
`SPLUNK_PASSWORD=... SPLUNK_HEC_TOKEN=... docker compose -f infra/splunk/docker-compose.yml up -d`.

Ports: `8000` web · `8088` HEC (data in) · `8089` management REST (VIGIL polls this).

## 2. Configure Splunk + load sample data

```bash
bash infra/splunk/setup_splunk.sh        # index + HEC token + the VIGIL alert
bash infra/splunk/load_sample_data.sh    # push sample Windows security events
```

`sample_events.jsonl` contains process-creation events crafted to trip real
detections (encoded PowerShell, fodhelper UAC bypass, `sc.exe create`, LSASS
dump, domain discovery, PsExec) plus benign noise. The saved search **"VIGIL -
Suspicious Process Creation"** runs every 5 min and fires an alert on the
suspicious ones.

Verify in Splunk Web (Search):  `index=vigil_test | stats count by process_name`

## 3. Point VIGIL at Splunk

Copy the settings from [`vigil-ingestor.env.example`](vigil-ingestor.env.example)
into `services/ingestor/.env`, then restart the ingestor:

```bash
docker compose up -d --force-recreate ingestor    # if running the app in compose
# or, host-run: re-run the ingestor via dev.sh
```

The ingestor's Splunk-**core** connector polls `/services/alerts/fired_alerts`
every 30s, normalizes each fired alert to a CDM event, and publishes it to
`vigil.signals.raw` — exactly the same pipeline the demo/ES modes feed. From
there it flows through correlation into Active Threats.

## 4. Tear down

```bash
docker compose -f infra/splunk/docker-compose.yml down          # keep data
docker compose -f infra/splunk/docker-compose.yml down -v       # wipe data
```

## Notes

- Local Splunk uses a self-signed cert — `SPLUNK_VERIFY_SSL=false` is expected in dev.
- Splunk is deliberately **not** added to the main `docker-compose.yml`; run it
  from this file only when you want to test against Splunk.
- The saved search here is a minimal example. Author your own to exercise
  specific detections; the connector picks up any VIGIL-owned fired alert.
