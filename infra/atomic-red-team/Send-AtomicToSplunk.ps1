<#
.SYNOPSIS
  Run Atomic Red Team technique(s) on a Windows host and ship the resulting
  process-creation telemetry to VIGIL's Splunk HEC, so VIGIL detects genuinely
  self-executed attacks (not recorded datasets).

.DESCRIPTION
  1. Installs Atomic Red Team (invoke-atomicredteam) if missing.
  2. Executes the requested ATT&CK technique(s) — REAL commands, run only on a
     lab/VM you own and can safely detonate on.
  3. Reads the process-creation events they produced (Sysmon EventID 1, else
     Security 4688) and POSTs them to the Splunk HEC as index=vigil_test events.

  VIGIL's ingestor polls that index, runs its detections, and surfaces attacks.

.PARAMETER SplunkHecUrl
  HEC base URL, e.g. https://<your-splunk>:8088  (Railway HEC must be reachable —
  expose port 8088 via a Railway TCP proxy, or run against an on-prem Splunk).

.PARAMETER HecToken   Splunk HEC token.
.PARAMETER Technique  ATT&CK id(s), default T1003.001 (LSASS dump). Comma-separate for several.
.PARAMETER Index      Splunk index (default vigil_test).

.EXAMPLE
  ./Send-AtomicToSplunk.ps1 -SplunkHecUrl https://x.proxy.rlwy.net:12345 `
      -HecToken <token> -Technique T1003.001,T1059.001
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$SplunkHecUrl,
  [Parameter(Mandatory = $true)][string]$HecToken,
  [string[]]$Technique = @("T1003.001"),
  [string]$Index = "vigil_test"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }  # self-signed HEC

if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
  Write-Host "[*] Installing Atomic Red Team..."
  IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
  Install-AtomicRedTeam -getAtomics -Force
}
Import-Module invoke-atomicredteam -Force

$start = Get-Date
foreach ($t in $Technique) {
  Write-Host "[*] Executing atomic $t ..."
  Invoke-AtomicTest $t -GetPrereqs -ErrorAction SilentlyContinue
  Invoke-AtomicTest $t -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 5
Write-Host "[*] Collecting process-creation events since $start ..."

# Prefer Sysmon EventID 1; fall back to Security 4688.
$events = @()
try {
  $events = Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 1; StartTime = $start } -ErrorAction Stop
} catch {
  $events = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4688; StartTime = $start } -ErrorAction SilentlyContinue
}

$payloads = foreach ($e in $events) {
  $x = [xml]$e.ToXml()
  $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  $img = $d["Image"]; if (-not $img) { $img = $d["NewProcessName"] }
  $evt = @{
    host         = $env:COMPUTERNAME
    user         = if ($d["User"]) { $d["User"] } else { $d["SubjectUserName"] }
    process_name = if ($img) { Split-Path $img -Leaf } else { "unknown.exe" }
    CommandLine  = $d["CommandLine"]
    ParentImage  = if ($d["ParentImage"]) { Split-Path $d["ParentImage"] -Leaf } else { $null }
    EventCode    = "$($e.Id)"
    source_feed  = "atomic-red-team-live"
  }
  (@{ event = $evt; sourcetype = "vigil:winsecurity"; index = $Index; host = $env:COMPUTERNAME } | ConvertTo-Json -Compress)
}

if (-not $payloads) { Write-Warning "No process events captured (enable Sysmon or Audit Process Creation)."; return }

$body = ($payloads -join "`n")
Invoke-RestMethod -Method Post -Uri "$SplunkHecUrl/services/collector/event" `
  -Headers @{ Authorization = "Splunk $HecToken" } -Body $body | Out-Null
Write-Host "[+] Shipped $($payloads.Count) events to Splunk index=$Index. Watch VIGIL Active Threats."
