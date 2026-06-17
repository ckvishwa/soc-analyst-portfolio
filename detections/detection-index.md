# Detection Index

**Repository:** Enterprise SOC Detection Lab v2  
**SIEM:** Splunk Enterprise  
**Data Sources:** Windows Event Logs, Sysmon, Windows Security Logs  
**Total Detections:** 8  
**Last Updated:** 2024

---

## Overview

This index documents all custom SPL detection rules written for this lab. Each detection was authored after simulating the corresponding technique in the lab environment, validating that the SPL query produces results against real telemetry, and testing against known false positive scenarios.

---

## Detection Summary Table

| # | File | Detection Name | MITRE Tactic | Technique ID | Severity | Data Source | Status |
|---|------|---------------|-------------|-------------|---------|-------------|--------|
| 1 | `powershell-suspicious-execution.spl` | Suspicious PowerShell Execution | Execution | T1059.001 | High | Sysmon Event 1, WinEvent 4104 | ✅ Validated |
| 2 | `brute-force-login.spl` | Brute Force Login Attempt | Credential Access | T1110.001 | Medium | WinEvent 4625, 4740 | ✅ Validated |
| 3 | `credential-dumping-simulation.spl` | LSASS Access Simulation | Credential Access | T1003.001 | Critical | Sysmon Event 10, WinEvent 4656 | ✅ Validated |
| 4 | `scheduled-task-persistence.spl` | Scheduled Task Creation | Persistence | T1053.005 | High | WinEvent 4698, 4702, Sysmon 1 | ✅ Validated |
| 5 | `registry-run-key-persistence.spl` | Registry Run Key Modification | Persistence | T1547.001 | High | Sysmon Event 13 | ✅ Validated |
| 6 | `process-injection-indicators.spl` | Process Injection Indicators | Defense Evasion | T1055 | Critical | Sysmon Events 8, 10 | ✅ Validated |
| 7 | `lateral-movement-attempts.spl` | Lateral Movement via SMB | Lateral Movement | T1021.002 | High | WinEvent 4624 (Type 3), 5140 | ✅ Validated |
| 8 | `dns-http-beacon-like-traffic.spl` | DNS/HTTP Beacon-like Traffic | Command & Control | T1071.001, T1071.004 | Medium | Sysmon Event 22, 3 | ✅ Validated |

---

## Detection Detail Cards

---

### DET-001 — Suspicious PowerShell Execution

| Field | Value |
|-------|-------|
| **File** | `powershell-suspicious-execution.spl` |
| **Tactic** | Execution |
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Severity** | High |
| **Data Sources** | Sysmon Event ID 1 (Process Creation), Windows Event ID 4104 (Script Block Logging) |
| **Splunk Index** | `index=endpoint` |
| **Key Fields** | `CommandLine`, `Image`, `ParentImage`, `ScriptBlockText`, `User` |
| **Alert Trigger** | PowerShell launched with encoded commands, bypass flags, download cradles, or from non-standard parent processes |
| **Investigation Report** | `investigation-reports/powershell-investigation-report.md` |
| **Simulation File** | `attack-simulations/01-powershell-suspicious-execution.md` |

**Core Logic:**
Detects PowerShell invocations containing flags commonly used in malicious execution: `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-WindowStyle Hidden`, `DownloadString`, `IEX`, `Invoke-Expression`, or when spawned from unusual parents like `winword.exe`, `excel.exe`, `wscript.exe`, or `mshta.exe`.

**Known False Positives:**
- IT automation scripts run by administrators using bypass flags
- Software deployment tools invoking PowerShell silently
- SCCM/ConfigMgr agent activity

---

### DET-002 — Brute Force Login Attempt

| Field | Value |
|-------|-------|
| **File** | `brute-force-login.spl` |
| **Tactic** | Credential Access |
| **Technique** | T1110.001 — Brute Force: Password Guessing |
| **Severity** | Medium |
| **Data Sources** | Windows Security Event ID 4625 (Failed Logon), 4740 (Account Lockout) |
| **Splunk Index** | `index=wineventlog` |
| **Key Fields** | `Account_Name`, `IpAddress`, `Logon_Type`, `Failure_Reason`, `count` |
| **Alert Trigger** | ≥10 failed logon attempts against one account within 5 minutes, or account lockout event |
| **Investigation Report** | `investigation-reports/brute-force-investigation-report.md` |
| **Simulation File** | `attack-simulations/02-brute-force-login.md` |

**Core Logic:**
Counts Event ID 4625 failures per account per source IP over a rolling 5-minute window. Correlates with Event ID 4740 (lockout) to confirm impact. Separates interactive (Type 2) from network (Type 3) logons to prioritize lateral movement context.

**Known False Positives:**
- Service accounts with expired or changed passwords
- Users mistyping cached credentials after password change
- Automated logon scripts with stale credentials

---

### DET-003 — LSASS Access Simulation

| Field | Value |
|-------|-------|
| **File** | `credential-dumping-simulation.spl` |
| **Tactic** | Credential Access |
| **Technique** | T1003.001 — OS Credential Dumping: LSASS Memory |
| **Severity** | Critical |
| **Data Sources** | Sysmon Event ID 10 (ProcessAccess), Windows Security Event ID 4656 (Handle Request) |
| **Splunk Index** | `index=endpoint` |
| **Key Fields** | `TargetImage`, `SourceImage`, `GrantedAccess`, `CallTrace` |
| **Alert Trigger** | Any process opening a handle to `lsass.exe` with read memory access rights (0x1010, 0x1410, 0x143A) from non-system sources |
| **Investigation Report** | `investigation-reports/credential-dumping-investigation-report.md` |
| **Simulation File** | `attack-simulations/03-credential-dumping-simulation.md` |

**Core Logic:**
Detects Sysmon Event ID 10 where `TargetImage` matches `lsass.exe` and `GrantedAccess` includes memory read flags. Excludes known-legitimate system processes (AV, EDR callouts are separately allowlisted). High fidelity in lab environment.

**Known False Positives:**
- AV/EDR products that legitimately access LSASS for protection
- Windows Defender and similar security tools
- Some backup software

---

### DET-004 — Scheduled Task Creation

| Field | Value |
|-------|-------|
| **File** | `scheduled-task-persistence.spl` |
| **Tactic** | Persistence |
| **Technique** | T1053.005 — Scheduled Task/Job: Scheduled Task |
| **Severity** | High |
| **Data Sources** | Windows Security Event ID 4698 (Task Created), 4702 (Task Updated), Sysmon Event ID 1 (schtasks.exe) |
| **Splunk Index** | `index=wineventlog`, `index=endpoint` |
| **Key Fields** | `TaskName`, `TaskContent`, `SubjectUserName`, `Image`, `CommandLine` |
| **Alert Trigger** | New scheduled task created by non-SYSTEM accounts, or tasks invoking PowerShell/cmd/wscript in their action field |
| **Investigation Report** | `investigation-reports/persistence-investigation-report.md` |
| **Simulation File** | `attack-simulations/04-scheduled-task-persistence.md` |

**Core Logic:**
Monitors for Event ID 4698 and correlates with the creating user. High-risk flag is when the task action invokes interpreters (PowerShell, cmd, wscript, mshta) or points to temp/user-writable directories.

**Known False Positives:**
- Windows Update and maintenance tasks (SYSTEM context, well-known paths)
- Software installers creating update check tasks
- IT monitoring agents

---

### DET-005 — Registry Run Key Modification

| Field | Value |
|-------|-------|
| **File** | `registry-run-key-persistence.spl` |
| **Tactic** | Persistence |
| **Technique** | T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys |
| **Severity** | High |
| **Data Sources** | Sysmon Event ID 13 (Registry Value Set) |
| **Splunk Index** | `index=endpoint` |
| **Key Fields** | `TargetObject`, `Details`, `Image`, `User` |
| **Alert Trigger** | Registry value set under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM\...Run` by non-standard processes |
| **Investigation Report** | `investigation-reports/persistence-investigation-report.md` |
| **Simulation File** | `attack-simulations/05-registry-run-key-persistence.md` |

**Core Logic:**
Sysmon Event ID 13 captures registry value writes. Filters on the specific Run/RunOnce key paths. Flags when the writing process is not a known-good installer or software updater. The `Details` field (the value written) is inspected for suspicious executable paths or encoded commands.

**Known False Positives:**
- Software installers adding themselves to Run keys (expected behavior)
- Legitimate applications setting up autostart (Dropbox, Zoom, Teams, etc.)
- Group Policy applying startup entries

---

### DET-006 — Process Injection Indicators

| Field | Value |
|-------|-------|
| **File** | `process-injection-indicators.spl` |
| **Tactic** | Defense Evasion / Privilege Escalation |
| **Technique** | T1055 — Process Injection |
| **Severity** | Critical |
| **Data Sources** | Sysmon Event ID 8 (CreateRemoteThread), Sysmon Event ID 10 (ProcessAccess) |
| **Splunk Index** | `index=endpoint` |
| **Key Fields** | `SourceImage`, `TargetImage`, `StartAddress`, `StartFunction`, `GrantedAccess` |
| **Alert Trigger** | `CreateRemoteThread` from unexpected source process into a sensitive target, or unusual `ProcessAccess` patterns against system processes |
| **Investigation Report** | `investigation-reports/persistence-investigation-report.md` |
| **Simulation File** | `attack-simulations/06-process-injection-indicators.md` |

**Core Logic:**
Sysmon Event ID 8 fires on `CreateRemoteThread` calls. The key detection logic focuses on source processes that are not expected to inject into other processes — user-space applications injecting into system or browser processes are flagged. Also monitors for `ProcessAccess` with suspicious access mask combinations.

**Known False Positives:**
- AV/EDR products using hook injection
- Debuggers and profiling tools
- Some older Java and .NET runtimes

---

### DET-007 — Lateral Movement via SMB

| Field | Value |
|-------|-------|
| **File** | `lateral-movement-attempts.spl` |
| **Tactic** | Lateral Movement |
| **Technique** | T1021.002 — Remote Services: SMB/Windows Admin Shares |
| **Severity** | High |
| **Data Sources** | Windows Security Event ID 4624 (Logon Type 3), 5140 (Network Share Access) |
| **Splunk Index** | `index=wineventlog` |
| **Key Fields** | `Account_Name`, `IpAddress`, `LogonType`, `ShareName`, `ObjectName` |
| **Alert Trigger** | Logon Type 3 authentication followed by access to ADMIN$, C$, or IPC$ shares from a non-server source IP |
| **Investigation Report** | `investigation-reports/lateral-movement-investigation-report.md` |
| **Simulation File** | `attack-simulations/07-lateral-movement-attempts.md` |

**Core Logic:**
Correlates Type 3 network logons (Event 4624) with subsequent share access events (Event 5140) within a short time window. Administrative share access (ADMIN$, C$) from non-infrastructure IPs is a strong lateral movement indicator.

**Known False Positives:**
- IT administrators using remote management tools
- Backup software accessing file shares
- Legitimate remote file copy operations (robocopy, xcopy across network)

---

### DET-008 — DNS/HTTP Beacon-like Traffic

| Field | Value |
|-------|-------|
| **File** | `dns-http-beacon-like-traffic.spl` |
| **Tactic** | Command & Control |
| **Technique** | T1071.001 (Web Protocols), T1071.004 (DNS) |
| **Severity** | Medium |
| **Data Sources** | Sysmon Event ID 22 (DNS Query), Sysmon Event ID 3 (Network Connection) |
| **Splunk Index** | `index=endpoint` |
| **Key Fields** | `QueryName`, `QueryResults`, `DestinationIp`, `DestinationPort`, `Image`, `count` |
| **Alert Trigger** | Single process making repetitive DNS queries or outbound HTTP connections at regular intervals to the same external destination |
| **Investigation Report** | `investigation-reports/beaconing-investigation-report.md` |
| **Simulation File** | `attack-simulations/08-dns-http-beacon-like-traffic.md` |

**Core Logic:**
Counts DNS queries and outbound connections per process per destination over a 1-hour window. Applies a regularity check (low standard deviation in connection intervals = beacon-like). Flags processes that are not known browsers or update services making repetitive external connections.

**Known False Positives:**
- Telemetry agents and monitoring tools with regular check-in intervals
- Cloud sync clients (OneDrive, Dropbox, Google Drive)
- Antivirus cloud lookup services
- Windows activation and licensing checks

---

## Authoring Standards

All detections in this lab follow this standard:

1. **Validated against real telemetry** — every query was tested against logs generated in the lab
2. **Mapped to MITRE ATT&CK** — tactic and technique ID included
3. **False positives documented** — no detection ships without FP analysis
4. **Tuning recommendations included** — analyst guidance for reducing noise
5. **Triage steps included** — every detection includes analyst workflow for responding

---

## Index Maintenance

When adding a new detection:

1. Create the `.spl` file in `detections/`
2. Create the corresponding attack simulation in `attack-simulations/`
3. Create or update the investigation report in `investigation-reports/`
4. Add a row to `mitre-attack-mapping/mitre-mapping-table.md`
5. Update this index with the new detection card
6. Add false positive notes to `false-positive-analysis/false-positive-notes.md`
