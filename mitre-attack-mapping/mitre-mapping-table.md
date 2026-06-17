# MITRE ATT&CK Mapping Table

**Project:** Enterprise SOC Detection Lab v2  
**Framework Version:** MITRE ATT&CK v14  
**Coverage:** 9 Techniques across 6 Tactics  
**Last Updated:** 2024

---

## Coverage Summary by Tactic

| Tactic | Techniques Covered |
|--------|-------------------|
| Execution | 1 |
| Credential Access | 2 |
| Persistence | 2 |
| Defense Evasion | 1 |
| Lateral Movement | 1 |
| Command & Control | 2 |
| **Total** | **9** |

---

## Full Mapping Table

| # | Simulation | Tactic | Technique ID | Technique Name | Sub-Technique | Data Source | Detection Logic Summary | SPL File | Investigation Report |
|---|-----------|--------|-------------|---------------|--------------|-------------|------------------------|---------|---------------------|
| 1 | PowerShell Suspicious Execution | Execution | T1059.001 | Command and Scripting Interpreter | PowerShell | Sysmon Event 1, WinEvent 4104 | Detects PowerShell launched with `-EncodedCommand`, `-ExecutionPolicy Bypass`, download cradles, or from unusual parent processes (Office, wscript, mshta) | `powershell-suspicious-execution.spl` | `powershell-investigation-report.md` |
| 2 | Brute Force Login | Credential Access | T1110.001 | Brute Force | Password Guessing | WinEvent 4625, 4740 | Counts failed logon attempts ≥10 per account per source IP within 5 minutes; correlates with account lockout Event 4740 | `brute-force-login.spl` | `brute-force-investigation-report.md` |
| 3 | Credential Dumping Simulation | Credential Access | T1003.001 | OS Credential Dumping | LSASS Memory | Sysmon Event 10, WinEvent 4656 | Detects process handle opens to `lsass.exe` with memory read access rights from non-system/non-AV processes | `credential-dumping-simulation.spl` | `credential-dumping-investigation-report.md` |
| 4 | Scheduled Task Persistence | Persistence | T1053.005 | Scheduled Task/Job | Scheduled Task | WinEvent 4698, 4702, Sysmon Event 1 | Detects new scheduled task creation (Event 4698) where task action invokes PowerShell, cmd, wscript, or mshta | `scheduled-task-persistence.spl` | `persistence-investigation-report.md` |
| 5 | Registry Run Key Persistence | Persistence | T1547.001 | Boot or Logon Autostart Execution | Registry Run Keys / Startup Folder | Sysmon Event 13 | Detects registry value writes to `HKCU\...\Run` or `HKLM\...\Run` paths from non-standard writing processes | `registry-run-key-persistence.spl` | `persistence-investigation-report.md` |
| 6 | Process Injection Indicators | Defense Evasion | T1055 | Process Injection | (Multiple sub-techniques) | Sysmon Event 8, 10 | Detects `CreateRemoteThread` calls (Event 8) from unexpected source processes, and unusual `ProcessAccess` patterns against sensitive targets | `process-injection-indicators.spl` | `persistence-investigation-report.md` |
| 7 | Lateral Movement via SMB | Lateral Movement | T1021.002 | Remote Services | SMB/Windows Admin Shares | WinEvent 4624 (Type 3), 5140 | Correlates network logon events with subsequent access to ADMIN$, C$, IPC$ shares from non-infrastructure source IPs | `lateral-movement-attempts.spl` | `lateral-movement-investigation-report.md` |
| 8 | DNS Beacon-like Traffic | Command & Control | T1071.004 | Application Layer Protocol | DNS | Sysmon Event 22 | Detects high-frequency or periodic DNS queries from non-browser processes to the same external domain | `dns-http-beacon-like-traffic.spl` | `beaconing-investigation-report.md` |
| 9 | HTTP Beacon-like Traffic | Command & Control | T1071.001 | Application Layer Protocol | Web Protocols | Sysmon Event 3 | Detects periodic outbound HTTP/HTTPS connections from non-browser processes at regular intervals to the same external IP | `dns-http-beacon-like-traffic.spl` | `beaconing-investigation-report.md` |

---

## Technique Detail Cards

---

### T1059.001 — PowerShell

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Full Technique Name** | Command and Scripting Interpreter: PowerShell |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1059/001/ |
| **What adversaries do** | Use PowerShell to execute commands, download payloads, establish persistence, and interact with the Windows API while leveraging built-in OS functionality |
| **Why hard to detect** | PowerShell is a legitimate admin tool — distinguishing malicious use from legitimate use requires command-line inspection, parent process analysis, and script content review |
| **Lab simulation method** | Safe encoded command with benign decode (`Write-Host`) launched from `wscript.exe` to simulate macro-to-PowerShell chain |
| **Key detection fields** | `CommandLine`, `ParentImage`, `Image`, `ScriptBlockText` (Event 4104) |
| **Blind spots** | AMSI bypass techniques, CLSID-based COM invocation of PowerShell, PowerShell remoting without explicit powershell.exe |

---

### T1110.001 — Brute Force: Password Guessing

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **Full Technique Name** | Brute Force: Password Guessing |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1110/001/ |
| **What adversaries do** | Attempt to authenticate using lists of common passwords, previously breached passwords, or passwords derived from OSINT about the target |
| **Why hard to detect** | At low rates (slow brute force / password spray), failures may blend with normal user error patterns. Requires statistical thresholds, not just individual event detection |
| **Lab simulation method** | Manual failed logon loop from Kali Linux using `hydra` against the lab Windows Server RDP endpoint with a known-bad credential list |
| **Key detection fields** | `Account_Name`, `IpAddress`, `Logon_Type`, `Failure_Reason`, count over time |
| **Blind spots** | Password spray (one attempt per account across many accounts) at very low rates; Kerberos pre-authentication failures (Event 4771) vs. NTLM failures (4625) |

---

### T1003.001 — LSASS Memory

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **Full Technique Name** | OS Credential Dumping: LSASS Memory |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1003/001/ |
| **What adversaries do** | Access the LSASS process memory to extract plaintext credentials, NTLM hashes, and Kerberos tickets using tools like Mimikatz, ProcDump, or Task Manager |
| **Why hard to detect** | LSASS is legitimately accessed by AV/EDR products, making allowlisting essential. Access right masks (GrantedAccess) provide high signal — most legitimate access doesn't require read memory rights |
| **Lab simulation method** | Safe test using Sysmon `ProcessAccess` event simulation — no actual credentials dumped. Used a benign process to open a handle to LSASS with logged access masks |
| **Key detection fields** | `TargetImage` (lsass.exe), `SourceImage`, `GrantedAccess` (0x1010, 0x1410, 0x143A, 0x1438) |
| **Blind spots** | Kernel-mode credential dumping, custom LSASS plugins, SSP injection — these bypass user-mode Sysmon visibility entirely |

---

### T1053.005 — Scheduled Task

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Full Technique Name** | Scheduled Task/Job: Scheduled Task |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1053/005/ |
| **What adversaries do** | Create scheduled tasks that execute malicious payloads at login, system startup, or on a timer — providing persistence through reboots and enabling privilege escalation via SYSTEM-context tasks |
| **Why hard to detect** | Windows creates many legitimate scheduled tasks. The signal is in the creator account, the task's action (what it runs), and the task's trigger conditions |
| **Lab simulation method** | Used `schtasks.exe` from a standard user account to create a task invoking `powershell.exe` — safe test content, no malicious payload |
| **Key detection fields** | `TaskName`, `SubjectUserName` (Event 4698), `CommandLine` of `schtasks.exe` (Sysmon Event 1) |
| **Blind spots** | COM-based task creation (doesn't generate Event 4698 in all configurations), tasks created directly via XML import |

---

### T1547.001 — Registry Run Keys

| Field | Value |
|-------|-------|
| **Tactic** | Persistence |
| **Full Technique Name** | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1547/001/ |
| **What adversaries do** | Write a registry value under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (user-level) or `HKLM\...Run` (system-level) to execute a payload on every login or boot |
| **Why hard to detect** | Many legitimate applications use Run keys for auto-start. Detection requires filtering known-good values and focusing on unusual writing processes and payload paths |
| **Lab simulation method** | Used `reg.exe` to write a benign value (pointing to `calc.exe`) to the HKCU Run key — no malicious payload, generates Sysmon Event 13 |
| **Key detection fields** | `TargetObject` (registry path), `Details` (value written), `Image` (writing process) |
| **Blind spots** | Registry writes via WMI or .NET API may not be captured by Sysmon Event 13 without proper configuration |

---

### T1055 — Process Injection

| Field | Value |
|-------|-------|
| **Tactic** | Defense Evasion / Privilege Escalation |
| **Full Technique Name** | Process Injection |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1055/ |
| **What adversaries do** | Inject code into a running process (often a trusted one like explorer.exe or svchost.exe) to execute in the context of that process — evading detection and potentially gaining elevated privileges |
| **Why hard to detect** | Many security tools themselves use similar API calls. Detection requires focusing on unexpected sources (user-space applications) injecting into sensitive targets |
| **Lab simulation method** | Sysmon Event 8 (CreateRemoteThread) indicator review using benign test — confirmed that Sysmon captures the event. No actual shellcode or malicious code injected |
| **Key detection fields** | `SourceImage`, `TargetImage`, `StartAddress`, `StartFunction` (Event 8); `GrantedAccess` (Event 10) |
| **Blind spots** | APC injection, thread hijacking, process hollowing — these use different API call patterns that may not generate Event 8 |

---

### T1021.002 — SMB/Windows Admin Shares

| Field | Value |
|-------|-------|
| **Tactic** | Lateral Movement |
| **Full Technique Name** | Remote Services: SMB/Windows Admin Shares |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1021/002/ |
| **What adversaries do** | Authenticate to remote systems over SMB using stolen credentials and access administrative shares (ADMIN$, C$, IPC$) to copy files, execute tools remotely, or deploy additional implants |
| **Why hard to detect** | Legitimate IT administration uses SMB extensively. Detection requires correlating authentication source, share accessed, and frequency — not just the fact that SMB occurred |
| **Lab simulation method** | Used `net use` from the Kali VM (after obtaining lab credentials) to connect to lab Windows Server admin shares — safe, no exploitation |
| **Key detection fields** | `LogonType` (3 = network), `IpAddress`, `ShareName` (ADMIN$, C$), `Account_Name` |
| **Blind spots** | SMB over non-standard ports, credential abuse that appears as legitimate admin activity (LOLBAS), pre-existing admin sessions |

---

### T1071.001 — Web Protocols (HTTP/S Beaconing)

| Field | Value |
|-------|-------|
| **Tactic** | Command & Control |
| **Full Technique Name** | Application Layer Protocol: Web Protocols |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1071/001/ |
| **What adversaries do** | Use HTTP or HTTPS for C2 communication to blend with normal web traffic. Modern implants implement jitter, domain fronting, and legitimate-looking User-Agent strings to evade detection |
| **Why hard to detect** | Most environments have massive volumes of HTTP traffic. Behavioral detection (regularity/interval analysis) rather than signature matching is required |
| **Lab simulation method** | Used a Python script making periodic GET requests at 60-second intervals to a lab web server — simulates beacon jitter without any actual C2 capability |
| **Key detection fields** | `DestinationIp`, `DestinationPort`, `Image` (process), connection count and interval analysis |
| **Blind spots** | HTTPS (encrypted content), domain fronting through CDNs, legitimate-interval traffic from cloud clients |

---

### T1071.004 — DNS (Beacon-like Queries)

| Field | Value |
|-------|-------|
| **Tactic** | Command & Control |
| **Full Technique Name** | Application Layer Protocol: DNS |
| **ATT&CK URL** | https://attack.mitre.org/techniques/T1071/004/ |
| **What adversaries do** | Use DNS queries as a covert C2 channel — encoding commands in subdomain labels, exfiltrating data in DNS TXT records, or using high-frequency DNS queries to a single domain as a heartbeat |
| **Why hard to detect** | DNS traffic is ubiquitous and often unmonitored. Detection requires baselining normal DNS query patterns per host/process and flagging deviations |
| **Lab simulation method** | Used `nslookup` in a loop from a PowerShell script making periodic queries to a lab DNS name — simulates C2 DNS beacon without actual data encoding |
| **Key detection fields** | `QueryName`, `Image` (Sysmon Event 22), query frequency per process per destination |
| **Blind spots** | DNS over HTTPS (DoH) bypasses Sysmon Event 22 entirely; encrypted DNS channels |

---

## Coverage Gap Analysis

### Techniques NOT covered in this lab version:

| Technique ID | Name | Why Not Covered | Planned |
|-------------|------|----------------|---------|
| T1078 | Valid Accounts | Requires more AD setup | v3 |
| T1566.001 | Spearphishing Attachment | Requires email infrastructure | v3 |
| T1027 | Obfuscated Files | Partially covered via PowerShell encoding | v2.1 |
| T1036 | Masquerading | Not yet simulated | v3 |
| T1070.004 | File Deletion | Not yet simulated | v3 |
| T1087 | Account Discovery | Basic AD enumeration | v2.1 |

---

## ATT&CK Navigator Export Note

> The techniques covered in this lab can be visualized using the MITRE ATT&CK Navigator.
> To create a coverage layer:
> 1. Visit https://mitre-attack.github.io/attack-navigator/
> 2. Create a new layer for Enterprise ATT&CK
> 3. Enable the following technique IDs and color them green (detected):
>    T1059.001, T1110.001, T1003.001, T1053.005, T1547.001, T1055, T1021.002, T1071.001, T1071.004
> 4. Screenshot the Navigator view and save to `screenshots/dashboards/mitre-coverage.png`
