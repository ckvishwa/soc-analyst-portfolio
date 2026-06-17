# Attack Simulation 01 — PowerShell Suspicious Execution

**Simulation ID:** SIM-001  
**Status:** ✅ Lab Validated  
**Safety Level:** Safe — benign test commands only  
**Estimated Time:** 15–20 minutes

---

## Objective

Simulate a malicious PowerShell execution pattern to generate Windows and Sysmon telemetry that can be detected by the lab's SPL detection rules. The goal is to produce Event ID 4104 (Script Block Logging) and Sysmon Event ID 1 (Process Creation) entries that match the signatures in `detections/powershell-suspicious-execution.spl`.

---

## MITRE ATT&CK Technique

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Technique ID** | T1059.001 |
| **Technique Name** | Command and Scripting Interpreter: PowerShell |
| **Reference** | https://attack.mitre.org/techniques/T1059/001/ |

**What real attackers do:** Use PowerShell to download and execute payloads from memory using download cradles, bypass execution policy restrictions, hide console windows during execution, and encode commands to evade basic string-matching defenses.

---

## Lab-Only Simulation Method

> ⚠️ **SAFETY NOTE:** All commands below are explicitly safe. They do not download malware, steal credentials, establish persistence, or perform any harmful action. They exist solely to generate telemetry patterns that match malicious PowerShell signatures.

### Pre-Simulation Checklist
- [ ] Confirm you are on WIN10-VICTIM lab VM only
- [ ] Confirm Sysmon is running: `Get-Service Sysmon`
- [ ] Confirm Script Block Logging GPO is applied: Check Event Viewer > Applications and Services Logs > Microsoft > Windows > PowerShell > Operational
- [ ] Confirm Splunk UF is forwarding: Check `inputs.conf` includes PowerShell Operational log

---

### Simulation Step 1 — Basic Encoded Command (Sysmon Event 1)

Open **Command Prompt** on WIN10-VICTIM and run:

```cmd
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand V3JpdGUtSG9zdCAiU2ltdWxhdGlvbiAwMSAtIFNhZmUgdGVzdCBjb21tYW5k"
```

**What this does:** Launches PowerShell with flags commonly used by attackers. The encoded string decodes to:
```
Write-Host "Simulation 01 - Safe test command"
```

**Telemetry generated:**
- Sysmon Event ID 1 with `CommandLine` containing `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`
- Parent process: `cmd.exe`

---

### Simulation Step 2 — Spawn from Unusual Parent (wscript.exe)

Create a test VBScript file (benign):

```vbs
' Save as: C:\Temp\test_sim01.vbs
' Content:
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command Write-Host 'Sim01 wscript spawn'", 0, True
```

Run from Command Prompt:
```cmd
wscript.exe C:\Temp\test_sim01.vbs
```

**What this does:** Forces the parent-child relationship `wscript.exe → powershell.exe`, which is a high-confidence suspicious spawn chain.

**Telemetry generated:**
- Sysmon Event ID 1 with `ParentImage: wscript.exe` and `Image: powershell.exe`

---

### Simulation Step 3 — Download Cradle Pattern (with Internal Lab Server)

> Only run this if you have a local lab web server running at 192.168.10.99. Set it up with a benign text file.

```powershell
# Run in PowerShell on WIN10-VICTIM
$wc = New-Object Net.WebClient
$content = $wc.DownloadString("http://192.168.10.99/test.txt")
Write-Host $content
```

**What this does:** Generates a `Net.WebClient.DownloadString` pattern — the same code used in malicious download cradles — but downloads a benign text file from the internal lab server.

**Telemetry generated:**
- Sysmon Event ID 1: `CommandLine` includes `Net.WebClient`
- Sysmon Event ID 3: Outbound TCP connection from `powershell.exe` to 192.168.10.99:80
- Windows Event ID 4104: Script block logged with `DownloadString` in content

---

### Simulation Step 4 — IEX Pattern (Invoke-Expression)

```powershell
# Run in PowerShell on WIN10-VICTIM — safe: only prints text
$cmd = "Write-Host 'IEX simulation - safe'"
IEX $cmd
```

**What this does:** Uses `Invoke-Expression (IEX)` — a common in-memory execution technique — to execute a safe string variable. The script block log will capture the full content.

**Telemetry generated:**
- Windows Event ID 4104: ScriptBlockText will contain `IEX`

---

## Expected Windows Event IDs

| Event ID | Log | Field of Interest | Expected Value |
|---------|-----|-----------------|---------------|
| 4104 | Microsoft-Windows-PowerShell/Operational | ScriptBlockText | Contains `IEX`, `DownloadString`, `Write-Host`, or other script content |
| 4103 | Microsoft-Windows-PowerShell/Operational | Payload | Module logging data (if module logging also enabled) |
| 4688 | Security | NewProcessName | `powershell.exe`, CommandLine contains flags |

---

## Expected Sysmon Event IDs

| Event ID | Description | Key Fields |
|---------|-------------|-----------|
| 1 | Process Creation | `Image: powershell.exe`, `CommandLine: -EncodedCommand -ExecutionPolicy Bypass -WindowStyle Hidden`, `ParentImage: wscript.exe or cmd.exe` |
| 3 | Network Connection | `Image: powershell.exe`, `DestinationIp: 192.168.10.99`, `DestinationPort: 80` (Step 3 only) |
| 7 | Image Load | DLL loads by powershell.exe — useful for advanced correlation |

---

## Expected Splunk Logs

After simulation, run this in Splunk to confirm telemetry:

```spl
index=endpoint ComputerName="WIN10-VICTIM"
(EventID=1 Image="*powershell.exe*") OR (EventID=4104)
| table _time, EventID, User, Image, ParentImage, CommandLine, ScriptBlockText
| sort _time
```

Expected output: 4–8 events showing the simulation activity.

---

## Detection Logic

The detection triggers on:
1. PowerShell command line containing any of: `-EncodedCommand`, `-enc`, `-ExecutionPolicy Bypass`, `-ep bypass`, `-WindowStyle Hidden`, `-w hidden`
2. PowerShell spawned from: `wscript.exe`, `cscript.exe`, `mshta.exe`, `winword.exe`, `excel.exe`, or any Office application
3. Script block content (Event 4104) containing: `IEX`, `Invoke-Expression`, `DownloadString`, `Net.WebClient`, `FromBase64String`

---

## SPL Query (Reference)

See: `detections/powershell-suspicious-execution.spl`

Quick validation query:
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
Image="*\\powershell.exe"
ComputerName="WIN10-VICTIM"
| search CommandLine="*-EncodedCommand*" OR CommandLine="*-ExecutionPolicy Bypass*"
| table _time, User, ParentImage, CommandLine
```

---

## Investigation Steps

After the detection fires:

1. Identify the triggering event in Splunk and note the full `CommandLine`
2. If `-EncodedCommand` present: decode the Base64 payload
3. Review parent process — is the parent expected or suspicious?
4. Check for follow-on Sysmon Event ID 3 (network connections)
5. Review Event ID 4104 script block logs for full script content
6. Check for persistence (Sysmon Event 13 — registry, Event 4698 — scheduled tasks)
7. Document findings in investigation report template

---

## Screenshots to Capture

Store in `screenshots/splunk-searches/` and `screenshots/sysmon-events/`

- [ ] Splunk search results showing Event ID 1 with suspicious CommandLine
- [ ] Splunk search results showing `ParentImage: wscript.exe` → `powershell.exe`
- [ ] Event ID 4104 script block content in Splunk
- [ ] Sysmon Event ID 3 (network connection) from powershell.exe
- [ ] Windows Event Viewer showing PowerShell Operational events (for context)

---

## False Positives

| Scenario | Why It Fires | Tuning Recommendation |
|---------|-------------|----------------------|
| IT automation scripts | Admin scripts use `-ExecutionPolicy Bypass` legitimately | Whitelist known admin accounts + approved script paths |
| SCCM/Intune deployments | Software deployment uses hidden window and bypass flags | Exclude `ccmexec.exe` and `serviceui.exe` as parent processes |
| Scheduled maintenance | Maintenance PowerShell tasks run silently at odd hours | Time-window exclusions during maintenance windows |

---

## Tuning Ideas

1. **Combine flags for higher confidence** — A single `-ExecutionPolicy Bypass` alone may be too noisy. Require TWO flags (e.g., bypass + encoded OR bypass + hidden) before alerting
2. **Weight parent process heavily** — Office parent + PowerShell = near-certainty of abuse. wscript + PowerShell = high confidence. cmd + PowerShell = worth reviewing
3. **Add network correlation** — If PowerShell makes a network connection within 30 seconds of launch, escalate severity automatically

---

## Defensive Takeaway

PowerShell is one of the most abused tools in post-exploitation. Organizations that have not enabled **Script Block Logging** and **Constrained Language Mode** are flying blind. Detections based on command line flags alone are insufficient — they can be trivially renamed or obfuscated. The most durable detections combine:
- Parent process analysis (behavioral)
- Script block content inspection (4104)
- Network connection correlation (Sysmon 3)
- Execution timing context (interactive vs. non-interactive hours)
