# Real Windows telemetry for VIGIL (EVTX + Atomic Red Team)

Two ways VIGIL is fed genuine Windows attack telemetry through Splunk.

## 1. Recorded telemetry (already live)

Real events are bundled and replayed into Splunk automatically by the
`log-generator` service on startup — `services/log-generator/datasets/real_telemetry.jsonl`:

- **EVTX attack samples** — parsed from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
  (real Sysmon/Security logs: LSASS access/dump, mimikatz sekurlsa, renamed PsExec, net discovery, wmic exec).
- **Atomic Red Team runs** — parsed from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)
  atomic captures (comsvcs LSASS dump, PsExec LSA-secrets dump, Empire mimikatz logonpasswords).

These are normalized to VIGIL's event shape (indicator surfaced into `CommandLine`)
and replayed with current timestamps, so the ingestor's SEARCH poll runs VIGIL's
detections over them and surfaces credential-access / lateral-movement attacks.

The scratch scripts that produced the bundle (parse EVTX with the `evtx` lib,
unzip mordor JSON) are one-off; the committed artifact is the normalized JSONL.

## 2. Live Atomic Red Team execution (bring your own Windows host)

`Send-AtomicToSplunk.ps1` runs Atomic Red Team **for real** on a Windows lab VM
and ships the resulting process telemetry to Splunk HEC:

```powershell
./Send-AtomicToSplunk.ps1 `
  -SplunkHecUrl https://<splunk-hec-host>:8088 `
  -HecToken <hec-token> `
  -Technique T1003.001,T1059.001
```

Requirements:
- A Windows VM you own and can safely detonate techniques on (ART runs real commands).
- **Sysmon** installed (EventID 1) or "Audit Process Creation" enabled (Security 4688).
- Splunk HEC reachable from the host. On the Railway demo, HEC (8088) is exposed via
  a Railway **TCP proxy** — pass that `host:port` as `-SplunkHecUrl`. (Railway allows
  one TCP proxy per service; the Splunk service's proxy currently points at HEC 8088.
  The proxy host:port and HEC token are shown in the Railway dashboard / provided
  separately — they are not committed here.) Or point at an on-prem Splunk.

The ingestor uses an overlapping look-back poll window with de-dup, so a bursty
live ART run (many events in a few seconds) is reliably caught, not missed at a
window boundary. Verified end-to-end: a 5-technique burst → HEC → Splunk →
ingestor (`matched=5`) → attack in VIGIL Active Threats.

VIGIL's ingestor polls `vigil_test`, applies detections, and the attack appears
in Active Threats — genuinely from your own ART execution.
