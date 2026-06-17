# Attack Simulation 03 — Credential Dumping Simulation

**Simulation ID:** SIM-003 | **MITRE:** T1003.001 | **Tactic:** Credential Access | **Severity:** Critical

> ⚠️ **SAFETY NOTE:** This simulation generates only Sysmon telemetry for LSASS handle access indicators. No actual credentials are extracted. The simulation uses a benign test process to open a read handle to LSASS — this generates the same Sysmon Event ID 10 that real credential dumping tools produce, without any credential extraction occurring.

## Objective
Generate Sysmon Event ID 10 (ProcessAccess) telemetry showing a non-system process accessing lsass.exe with memory-read access rights — the primary telemetry indicator for credential dumping tool activity.

## MITRE ATT&CK Technique
- **Technique:** T1003.001 — OS Credential Dumping: LSASS Memory
- **Reference:** https://attack.mitre.org/techniques/T1003/001/

## Lab-Only Simulation Method

### Option A — Atomic Red Team (Recommended)
```powershell
# Install Atomic Red Team if not present
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam

# Run T1003.001 — test #1 generates handle open to LSASS without dumping
Invoke-AtomicTest T1003.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 1
```
Atomic Test 1 uses a benign method to open LSASS handle — no creds extracted.

### Option B — Manual PowerShell Handle Test
```powershell
# Opens a handle to lsass.exe with a limited access mask — generates Sysmon Event 10
# Run as Administrator on WIN10-VICTIM
$lsass = Get-Process lsass
$handle = [System.Runtime.InteropServices.Marshal]::GetIUnknownForObject($lsass)
Write-Host "Handle test complete — check Sysmon Event 10 in Splunk"
# This is a benign handle operation — no memory is read
```

## Expected Event IDs
| Event | Log | Key Fields |
|-------|-----|-----------|
| Sysmon 10 | Sysmon Operational | `TargetImage: lsass.exe`, `SourceImage: [test process]`, `GrantedAccess` |
| WinEvent 4656 | Security | `ObjectName: \Device\HarddiskVolume...\lsass.exe`, `AccessMask` |

## Detection SPL (Reference)
See: `detections/credential-dumping-simulation.spl`

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=10
TargetImage="*\\lsass.exe"
NOT SourceImage IN ("*\\MsMpEng.exe","*\\svchost.exe","*\\csrss.exe","*\\wininit.exe","*\\services.exe")
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess, CallTrace
```

## Defensive Takeaway
LSASS protection (PPL — Protected Process Light) and Credential Guard are the two most effective mitigations. With Credential Guard enabled, LSASS credentials are isolated in a virtualization-based security container that no user-mode process can access — Mimikatz and similar tools fail completely. Detection via Sysmon Event 10 provides a backstop for environments where these controls cannot yet be deployed.
