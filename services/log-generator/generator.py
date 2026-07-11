"""Continual security-log generator for the VIGIL Splunk demo.

An always-on worker that pushes realistic Windows process-creation events into
Splunk HEC on a schedule: a steady stream of benign noise, plus a full attack
kill-chain injected every few minutes. VIGIL's ingestor polls the index, runs
its detections, and surfaces the attacks — so demo activity is continuously and
legitimately driven by Splunk logs.

Config via env:
  SPLUNK_HEC_URL     (default https://splunk.railway.internal:8088)
  SPLUNK_HEC_TOKEN   (required)
  SPLUNK_INDEX       (default vigil_test)
  BENIGN_INTERVAL_SECONDS  (default 20)
  ATTACK_INTERVAL_SECONDS  (default 420 ~7 min)
"""

from __future__ import annotations

import json
import os
import random
import time

import httpx

HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://splunk.railway.internal:8088").rstrip("/")
HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
INDEX = os.getenv("SPLUNK_INDEX", "vigil_test")
SOURCETYPE = "vigil:winsecurity"
BENIGN_INTERVAL = int(os.getenv("BENIGN_INTERVAL_SECONDS", "20"))
ATTACK_INTERVAL = int(os.getenv("ATTACK_INTERVAL_SECONDS", "420"))

HOSTS = ["WKS-FINANCE-04", "WKS-ENG-11", "WKS-HR-02", "FILESERVER-03",
         "SRV-DB-05", "WKS-SALES-07", "WKS-MKTG-03"]
USERS = ["jdoe", "asmith", "bwilson", "mgarcia", "tlee", "kpatel"]
ATTACK_HOSTS = ["WKS-FINANCE-04", "WKS-ENG-11", "WKS-SALES-07", "WKS-HR-02"]
ATTACK_USERS = ["jdoe", "asmith", "tlee", "kpatel"]

# Benign day-to-day process activity (process_name, command_line, parent).
BENIGN = [
    ("chrome.exe", "chrome.exe --type=renderer", "explorer.exe"),
    ("msedge.exe", "msedge.exe --type=renderer", "explorer.exe"),
    ("outlook.exe", "outlook.exe", "explorer.exe"),
    ("Teams.exe", "Teams.exe", "explorer.exe"),
    ("notepad.exe", "notepad.exe C:\\Users\\Public\\notes.txt", "explorer.exe"),
    ("excel.exe", "excel.exe Q3_Budget.xlsx", "explorer.exe"),
    ("winword.exe", "winword.exe Report.docx", "explorer.exe"),
    ("git.exe", "git.exe pull origin main", "cmd.exe"),
    ("svchost.exe", "svchost.exe -k netsvcs", "services.exe"),
    ("sqlservr.exe", "sqlservr.exe -sMSSQLSERVER", "services.exe"),
    ("explorer.exe", "explorer.exe", "userinit.exe"),
    ("OneDrive.exe", "OneDrive.exe /background", "explorer.exe"),
]

# Attack kill-chain — each line trips a VIGIL detection (D5/D7/D6/D1/D8/D4).
ATTACK_CHAIN = [
    ("powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", None),
    ("fodhelper.exe", "C:\\Windows\\System32\\fodhelper.exe", None),
    ("sc.exe", "sc.exe create UpdaterSvc binPath= C:\\ProgramData\\updater.exe start= auto", None),
    ("rundll32.exe", "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full", None),
    ("net.exe", 'net group "Domain Admins" /domain', None),
    ("psexec.exe", "psexec.exe \\\\FILESERVER-03 -u corp\\administrator -p Summer2026! cmd.exe", "10.0.20.30"),
]


def send(events: list[dict]) -> None:
    lines = []
    for ev in events:
        host = ev.pop("host", None)
        env = {"event": ev, "sourcetype": SOURCETYPE, "index": INDEX, "time": time.time()}
        if host:
            env["host"] = host
        lines.append(json.dumps(env))
    try:
        httpx.post(
            f"{HEC_URL}/services/collector/event",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            content="\n".join(lines),
            verify=False,
            timeout=15.0,
        )
    except Exception as e:  # noqa: BLE001 — best-effort feeder
        print(f"[generator] send failed: {e}", flush=True)


def benign_batch() -> list[dict]:
    out = []
    for _ in range(random.randint(2, 5)):
        pn, cl, parent = random.choice(BENIGN)
        out.append({
            "host": random.choice(HOSTS), "user": random.choice(USERS),
            "process_name": pn, "CommandLine": cl, "ParentImage": parent,
            "EventCode": "4688",
        })
    return out


def attack_chain() -> tuple[str, list[dict]]:
    host = random.choice(ATTACK_HOSTS)
    user = random.choice(ATTACK_USERS)
    out = []
    for pn, cl, dst in ATTACK_CHAIN:
        ev = {"host": host, "user": user, "process_name": pn, "CommandLine": cl,
              "ParentImage": "cmd.exe", "EventCode": "4688"}
        if dst:
            ev["dest_ip"] = dst
        out.append(ev)
    return host, out


def main() -> None:
    print(f"[generator] feeding {HEC_URL} index={INDEX} "
          f"benign/{BENIGN_INTERVAL}s attack/{ATTACK_INTERVAL}s", flush=True)
    last_attack = time.monotonic() - ATTACK_INTERVAL + 60  # first attack ~1 min in
    while True:
        send(benign_batch())
        if time.monotonic() - last_attack >= ATTACK_INTERVAL:
            host, chain = attack_chain()
            send(chain)
            last_attack = time.monotonic()
            print(f"[generator] injected attack chain on {host}", flush=True)
        time.sleep(BENIGN_INTERVAL)


if __name__ == "__main__":
    main()
