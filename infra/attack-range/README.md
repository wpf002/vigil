# VIGIL × Splunk Attack Range (true external SIEM connection)

Stand up a **real instrumented lab in AWS** with [Splunk Attack Range](https://github.com/splunk/attack_range)
— a Splunk server + a Windows victim with Sysmon — detonate attacks against it,
and have VIGIL ingest that telemetry over a genuine **external** connection
(VIGIL on Railway ⇄ Splunk in your AWS VPC). This complements the in-repo
Railway Splunk (`infra/splunk-railway`, co-located) with a real, distributed setup.

> **This part runs in YOUR AWS account and costs real money** (EC2 t3.large/xlarge,
> ~$0.30–0.50/hr while running). I set up the VIGIL-side glue and config; you run
> the AWS spin-up and **`attack_range destroy` when done**. Nothing here is billed
> until you build.

## Prerequisites (one-time)
- An AWS account + credentials (`aws configure`).
- Python 3.9+, Terraform, and Attack Range:
  ```bash
  git clone https://github.com/splunk/attack_range && cd attack_range
  pip install -r requirements.txt          # or: poetry install
  attack_range configure                    # walks you through AWS region, key, etc.
  ```

## 1. Build the range (one command)
```bash
cp /path/to/vigil/infra/attack-range/attack_range.yml ./attack_range.yml   # edit passwords first
attack_range build
attack_range show          # note the Splunk server PUBLIC IP
```
This provisions the VPC, the Splunk server, and a Windows Server 2022 endpoint
with Sysmon forwarding to Splunk. The `ip_whitelist` in `attack_range.yml` is the
**VPC allow rule** — set it to the source that will run VIGIL's ingestor (your
workstation `x.x.x.x/32`, or `0.0.0.0/0` for a short test, or use the built-in VPN).

## 2. Connect VIGIL to the range's Splunk
```bash
# LOCAL ingestor (recommended for the external test — whitelist your own IP):
bash infra/attack-range/connect-vigil.sh <splunk_public_ip> <password>
#   -> prints ingestor env; drop into services/ingestor/.env and run it

# or repoint the deployed Railway ingestor:
bash infra/attack-range/connect-vigil.sh <splunk_public_ip> <password> --railway
```
VIGIL's ingestor uses **SEARCH mode** (added for the Railway Splunk) to poll the
range's index, normalize Sysmon events, and run VIGIL's detections — no changes
needed beyond pointing `SPLUNK_HOST` at the AWS Splunk. Attacks surface in VIGIL
Active Threats exactly as with the Railway feed, and the "View source logs in
Splunk" deep-link works against the range's Splunk too (set `VITE_SPLUNK_URL`).

## 3. Attack it
```bash
attack_range simulate -e T1003.001              # Atomic Red Team: LSASS dump
attack_range simulate -e T1059.001,T1021.002    # encoded PowerShell, PsExec lateral
```
The Windows victim runs the real techniques → Sysmon → Splunk → VIGIL detects them.

## 4. Tear down (stop paying)
```bash
attack_range destroy
```

## Notes
- Attack Range's own Splunk ships ES/ESCU detections; VIGIL polls the raw index
  independently, so both can analyze the same telemetry.
- The victim's Sysmon `Image` is a full path — VIGIL's normalizer basenames it so
  `equals`-style rules (e.g. `fodhelper.exe`) match, and `contains`/`regex` rules
  (lsass, `-enc`, `psexec`) match as-is.
- Adjust `SPLUNK_SEARCH_INDEX` if your build indexes Windows data somewhere other
  than `main` (check: `| eventcount summarize=false index=*`).
