# Enterprise SOC Detection Lab

![Splunk](https://img.shields.io/badge/Splunk-10.4.0-green)
![Sysmon](https://img.shields.io/badge/Sysmon-v15.20-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red)
![AD](https://img.shields.io/badge/Active%20Directory-SOCLAB.LOCAL-orange)
![Kali](https://img.shields.io/badge/Attacker-Kali%20Linux-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Vishva Teja Chikoti** | Cybersecurity | SOC Analyst  
[LinkedIn](https://linkedin.com/in/vishvack) • [Email](mailto:vchik2@unh.newhaven.edu) • Open to SOC Analyst L1 / Detection Engineer roles

> A multi-VM enterprise SOC lab built on Active Directory with a dedicated Kali Linux attacker machine. Real attacks simulated across the network, detected using Sysmon + Splunk, and documented as structured analyst investigations. Covers the full detection engineering lifecycle: simulate → collect → detect → investigate → tune → report.

---

## Portfolio Stats

| Metric | Value |
|--------|-------|
| Total Labs / Simulations | 14 (8 enterprise AD + 6 standalone) |
| Real Security Events Analyzed | 8,000+ Windows + Sysmon events |
| MITRE ATT&CK Techniques Mapped | 25 techniques across 9 tactics |
| Custom SPL Detection Rules | 14 rules |
| Investigation Reports | 8 structured analyst reports |
| Attack Phases Covered | Initial Access → Recon → Execution → Credential Access → Lateral Movement → Persistence → C2 |
| Lab Environment | 3-VM Active Directory domain (DC + Endpoint + Kali attacker) |
| Attacker Machine | Kali Linux — real cross-machine attacks |

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Lab Network: 192.168.10.0/24                │
│                  Domain: SOCLAB.LOCAL                        │
│                                                              │
│  ┌──────────────────────┐   ┌──────────────────────┐        │
│  │  Windows Server 2019 │   │    Windows 10        │        │
│  │  Domain Controller   │◄──│    Victim Endpoint   │        │
│  │  192.168.10.10       │   │    192.168.10.20     │        │
│  │  AD DS + DNS         │   │    Sysmon v15.20     │        │
│  │  Splunk Enterprise   │   │    Splunk UF         │        │
│  │  Sysmon v15.20       │   │    jsmith (domain)   │        │
│  └──────────┬───────────┘   └──────────┬───────────┘        │
│             │     log forwarding        │                    │
│             └──────────┬───────────────┘                    │
│                        ▼  port 9997                         │
│              ┌─────────────────┐                            │
│              │ Splunk indexes  │                            │
│              │ endpoint        │                            │
│              │ wineventlog     │                            │
│              └─────────────────┘                            │
│                                                              │
│  ┌──────────────────────┐                                   │
│  │  Kali Linux          │ ← Real attacker machine           │
│  │  192.168.10.50       │   brute force, SMB, recon        │
│  └──────────────────────┘                                   │
└──────────────────────────────────────────────────────────────┘
```

---

## Part 1 — Enterprise AD Detection Lab (v2)

3-VM Active Directory environment. Real cross-machine attacks from Kali. All telemetry collected in Splunk.

### Lab Setup
- Windows Server 2019 promoted to Domain Controller (`SOCLAB.LOCAL`)
- Windows 10 endpoint domain-joined as `SOCLAB\jsmith`
- Kali Linux attacker on same network segment
- Sysmon v15.20 deployed on both Windows machines
- Splunk Enterprise receiving 4,000+ events from endpoint

### Attack Simulations & Detections

| # | Simulation | MITRE Technique | Tactic | Attacker | Detection | Status |
|---|-----------|----------------|--------|---------|-----------|--------|
| 01 | PowerShell Suspicious Execution | T1059.001 | Execution | Win10 | DET-001 ✅ Fired | ✅ |
| 02 | Brute Force Login | T1110.001 | Credential Access | **Kali Linux** | DET-002 ✅ Fired | ✅ |
| 03 | Credential Dumping Simulation | T1003.001 | Credential Access | Win10 | DET-003 ✅ Fired | ✅ |
| 04 | Scheduled Task Persistence | T1053.005 | Persistence | Win10 | DET-004 ✅ Fired | ✅ |
| 05 | Registry Run Key Persistence | T1547.001 | Persistence | Win10 | DET-005 ✅ Fired | ✅ |
| 06 | Process Injection Indicators | T1055 | Defense Evasion | Win10 | DET-006 ✅ Fired | ✅ |
| 07 | Lateral Movement via SMB | T1021.002 | Lateral Movement | **Kali Linux** | DET-007 ✅ Fired | ✅ |
| 08 | DNS/HTTP Beacon-like Traffic | T1071.001/004 | Command & Control | Win10 | DET-008 ✅ Fired | ✅ |

### Validated Detections

**DET-001 — Suspicious PowerShell Execution** ✅ Live in Splunk
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
"<EventID>1</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| search Image="*powershell*"
    (CommandLine="*EncodedCommand*" OR CommandLine="*ExecutionPolicy Bypass*"
     OR CommandLine="*WindowStyle Hidden*" OR CommandLine="*DownloadString*")
| table _time, host, User, Image, ParentImage, CommandLine
| sort -_time
```
**Result:** Fired on `SOCLAB\jsmith` running encoded PowerShell from `cmd.exe` — True Positive confirmed.

**DET-002 — Brute Force Login** ✅ Live in Splunk
```spl
index=wineventlog EventCode=4625
| stats count AS failures BY Account_Name, Source_Network_Address
| where failures >= 3
| sort -failures
```
**Result:** Detected 11 failed SMB logon attempts from Kali Linux (192.168.10.50) against `testuser01` — account lockout (Event 4740) confirmed.

**See all 8 detection rules:** [`detections/`](detections/)

---

## Part 2 — Standalone Detection Labs (v1)

Single-VM labs covering additional attack phases with real Windows telemetry.

### Complete Attack Chain

```
[Lab 4] Initial Access
Phishing email → weaponized PDF.exe → credential harvesting
        ↓
[Lab 1] Reconnaissance
whoami → ipconfig → systeminfo → netstat → tasklist
        ↓
[Lab 2] Execution
Malicious PowerShell → Base64 obfuscation → encoded command execution
RuntimeBroker.exe → PowerShell (anomalous parent — suspected injection, not confirmed)
        ↓
[Lab 3] Credential Access
Brute force → 10 attempts in 5 sec via svchost
        ↓
[Lab 5] Lateral Movement
cmdkey credential enumeration → EventCode 4648 (explicit credential use) → local RDP session
        ↓
[Lab 6] Persistence
Run Key + Fake Service + Winlogon Hijack = 3 simultaneous persistence mechanisms
```

### Labs

| # | Lab | MITRE Techniques | Key Finding | Status |
|---|-----|-----------------|-------------|--------|
| 1 | [Recon Detection](./labs/Lab1-Recon-Detection.md) | T1033, T1016, T1082 | Recon commands observed under SYSTEM and user context — possible dual foothold | ✅ |
| 2 | [PowerShell Detection](./labs/Lab2-PowerShell-Detection.md) | T1059.001, T1027 | RuntimeBroker.exe → PowerShell — anomalous parent-child relationship (T1055 suspected, not confirmed) | ✅ |
| 3 | [Brute Force Detection](./labs/Lab3-Brute-Force-Detection.md) | T1110.001, T1078 | 10 failed attempts in 5 sec from localhost via svchost | ✅ |
| 4 | [Phishing Triage](./labs/Lab4-Phishing-Triage.md) | T1566.001, T1027, T1036.007 | Base64 URL decoded to evil.com/steal + pdf.exe attachment | ✅ |
| 5 | [RDP Auth & Explicit Credential Detection](./labs/Lab5-RDP-Lateral-Movement.md) | T1021.001, T1078 | EventCode 4648 — explicit credential use via cmdkey observed on local host | ✅ |
| 6 | [Persistence Hunt](./labs/Lab6-Persistence-Hunt.md) | T1547.001, T1543.003, T1547.004 | 3 simultaneous persistence mechanisms detected | ✅ |

---

## Full MITRE ATT&CK Coverage

| Tactic | Technique ID | Technique Name | Lab/Sim | Detected |
|--------|-------------|---------------|---------|---------|
| Initial Access | T1566.001 | Spearphishing Attachment | Lab 4 | ✅ |
| Execution | T1059.001 | PowerShell | Lab 2, SIM-001 | ✅ |
| Execution | T1027 | Obfuscated Files | Lab 2, Lab 4 | ✅ |
| Credential Access | T1110.001 | Brute Force: Password Guessing | Lab 3, SIM-002 | ✅ |
| Credential Access | T1078 | Valid Accounts | Lab 3, Lab 5 | ✅ |
| Credential Access | T1003.001 | LSASS Memory (simulated) | SIM-003 | ✅ |
| Persistence | T1547.001 | Registry Run Keys | Lab 6, SIM-005 | ✅ |
| Persistence | T1543.003 | Windows Service | Lab 6 | ✅ |
| Persistence | T1547.004 | Winlogon Helper | Lab 6 | ✅ |
| Persistence | T1053.005 | Scheduled Task | SIM-004 | ✅ |
| Defense Evasion | T1055 | Process Injection | SIM-006 | ✅ |
| Defense Evasion | T1036.007 | Masquerading | Lab 4 | ✅ |
| Discovery | T1033 | System Owner Discovery | Lab 1 | ✅ |
| Discovery | T1016 | System Network Config | Lab 1 | ✅ |
| Discovery | T1082 | System Info Discovery | Lab 1 | ✅ |
| Lateral Movement | T1021.001 | Remote Services: RDP | Lab 5 | ✅ |
| Lateral Movement | T1021.002 | SMB Admin Shares | SIM-007 | ✅ |
| Command & Control | T1071.001 | Web Protocols | SIM-008 | ✅ |
| Command & Control | T1071.004 | DNS | SIM-008 | ✅ |

> **Note on T1055 (Lab 2):** RuntimeBroker.exe → PowerShell is an anomalous parent-child relationship. T1055 is assessed as suspected based on this observation. Confirmation requires Sysmon Event ID 8 (CreateRemoteThread) or Event ID 10 (ProcessAccess) evidence.

> **Note on T1550.002:** Removed. cmdkey references credentials stored in Windows Credential Manager — this is not Pass-the-Hash. Pass-the-Hash requires authenticating with a raw NTLM hash without the plaintext password, which was not demonstrated.

**25 techniques mapped. 25 detected.**

---

## Tools Used

| Tool | Role | Version |
|------|------|---------|
| Splunk Enterprise | SIEM — indexing, search, dashboards, alerts | 10.4.0 |
| Sysmon | Advanced endpoint telemetry | v15.20 |
| Windows Server 2019 | Domain Controller (AD DS, DNS) | Evaluation |
| Windows 10 | Victim endpoint | 21H2 |
| Kali Linux | Attacker — real cross-machine attacks | 2024.x |
| CyberChef | Base64 decode, IOC analysis | Online |
| VirusTotal | Hash and URL reputation | Online |
| MITRE ATT&CK Navigator | Coverage visualization | v14 |
| hydra / smbclient | Brute force simulation (lab only) | Kali built-in |

---

## Detection Engineering Workflow

```
Kali / Win10          Sysmon + Windows        Splunk SPL
Attack Simulation ──► Event Log Telemetry ──► Detection Query
      │                                              │
      ▼                                              ▼
Attack Simulation     MITRE ATT&CK            Tune + Save Alert
Documentation    ◄─── Mapping            ◄─── + FP Analysis
      │
      ▼
Investigation Report
(analyst POV — timeline,
artifacts, decision)
```

---

## Key Findings

| Simulation/Lab | Finding | Severity |
|---------------|---------|---------|
| SIM-001 PowerShell | `cmd.exe → powershell.exe -EncodedCommand -ExecutionPolicy Bypass` — Sysmon Event 1 | HIGH |
| SIM-002 Brute Force | 11 SMB failures from Kali 192.168.10.50 — testuser01 locked out (Event 4740) | HIGH |
| SIM-003 LSASS | rundll32.exe + comsvcs.dll → lsass.exe access — Sysmon Event 10 | CRITICAL |
| SIM-004 Sched Task | schtasks /create by SOCLAB\jsmith — Sysmon Event 1 | HIGH |
| SIM-005 Registry | reg.exe writing to HKCU\...\Run — Sysmon Event 13 | HIGH |
| SIM-006 Injection | mavinject.exe → notepad.exe CreateRemoteThread — Sysmon Event 8 | CRITICAL |
| SIM-007 Lateral | SMB ADMIN$ access from Kali 192.168.10.50 — Event 4624 Type 3 on DC | HIGH |
| SIM-008 Beaconing | backgroundTaskHost.exe — 5+ periodic DNS queries — Sysmon Event 22 | MEDIUM |
| Lab 1 Recon | Recon commands observed under SYSTEM and user context — possible dual foothold or single attacker in multiple security contexts | HIGH |
| Lab 2 PowerShell | RuntimeBroker.exe → PowerShell — anomalous parent-child relationship — T1055 suspected, not confirmed without Event 8/10 | HIGH |
| Lab 3 Brute Force | 10 failed logon attempts in 5 sec from localhost via svchost | CRITICAL |
| Lab 4 Phishing | Base64 URL decoded to evil.com/steal — pdf.exe attachment identified | CRITICAL |
| Lab 5 RDP | EventCode 4648 — explicit credential use via cmdkey observed — local host scope | HIGH |
| Lab 6 Persistence | 3 simultaneous persistence mechanisms detected: Run Key + Service + Winlogon | CRITICAL |

---

## Key Lessons Learned

1. **Sysmon Event ID 1 is the highest-value detection source** — `ParentImage` + `CommandLine` + `User` together resolve most ambiguity in triage
2. **Real cross-machine attacks look different from local simulations** — Kali brute force generates Type 3 network logon events vs. Type 2 interactive from local sims
3. **False positives are the real engineering work** — the initial PowerShell detection fired on Splunk UF's own processes; tuning required baseline analysis before the rule was useful
4. **Account lockout is a detection in itself** — Event 4740 is a high-fidelity brute force confirmation that requires zero tuning
5. **Anomalous parent-child relationships require corroboration** — RuntimeBroker → PowerShell is suspicious but not self-confirming; Event ID 8 or 10 is needed before asserting T1055
6. **Event ID 4648 is a signal, not a verdict** — explicit credential use can be legitimate; always correlate with process name, target server, and account context
7. **3 simultaneous persistence mechanisms** are harder to detect than one — defenders must hunt across Run keys, services, and Winlogon simultaneously

---

## Resume Bullet

> Built a multi-VM enterprise SOC detection lab on Active Directory (`SOCLAB.LOCAL`) using Splunk Enterprise, Sysmon v15, and Kali Linux as a dedicated attacker to simulate and detect adversary techniques across 9 MITRE ATT&CK tactics; wrote custom SPL detection rules validated against real cross-machine telemetry, produced structured investigation reports per alert, and documented false positive tuning recommendations — covering the full detection engineering lifecycle from attack simulation to analyst triage.

---

## Repository Structure

```
soc-analyst-portfolio/
├── README.md
├── lab-setup/              ← VM build, network diagram, Splunk + Sysmon install
├── configs/                ← sysmonconfig.xml, inputs.conf, indexes.conf
├── detections/             ← 8 SPL detection rules + detection index
├── attack-simulations/     ← 8 enterprise AD simulation docs
├── investigation-reports/  ← structured analyst reports per detection
├── mitre-attack-mapping/   ← full MITRE ATT&CK mapping table
├── dashboards/             ← Splunk dashboard SPL panels
├── false-positive-analysis/ ← FP notes and tuning recommendations
├── resume-linkedin/        ← resume bullets, LinkedIn post, talking points
├── labs/                   ← v1 standalone lab markdown files
├── reports/                ← executive incident report
├── detection/              ← v1 SPL correlation searches
├── references/             ← tools used, glossary
└── screenshots/
    ├── lab-architecture/   ← DC setup, domain join, network proof
    ├── splunk-searches/    ← all 8 detection results + FP evidence
    ├── alerts/             ← saved Splunk alerts
    └── sysmon-events/      ← Sysmon telemetry verification
```

---

## Disclaimer

> This project is built entirely for educational and defensive security research purposes. All attack simulations are performed in an isolated private lab environment with no connection to production systems or third-party networks. No real credentials were harvested, no real malware was deployed, and no unauthorized access was performed at any point. All techniques are framed from a detection and defense perspective only.