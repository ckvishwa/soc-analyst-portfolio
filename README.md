# Enterprise SOC Detection Lab

![Splunk](https://img.shields.io/badge/Splunk-10.4.0-green)
![Sysmon](https://img.shields.io/badge/Sysmon-v15.20-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red)
![AD](https://img.shields.io/badge/Active%20Directory-SOCLAB.LOCAL-orange)
![Kali](https://img.shields.io/badge/Attacker-Kali%20Linux-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Vishva Teja Chikoti** | Cybersecurity | SOC Analyst  
[LinkedIn](https://linkedin.com/in/vishvack) • [Email](mailto:vchik2@unh.newhaven.edu) • Open to SOC Analyst L1 / Detection Engineer roles

> A multi-VM enterprise SOC lab built on Active Directory with a dedicated Kali Linux attacker machine. Attack simulations are collected with Sysmon and Windows logs, analyzed in Splunk, and documented as analyst investigations. The project follows the workflow: simulate → collect → detect → investigate → tune → report.

---

## Portfolio Stats

| Metric | Value |
|--------|-------|
| Total Labs / Simulations | 14 planned and completed exercises (8 enterprise AD + 6 standalone) |
| Security Events Analyzed | 8,000+ Windows and Sysmon events |
| MITRE ATT&CK Coverage | Validated and planned techniques documented separately below |
| Custom SPL Detection Rules | 14 planned/implemented rules with validation status shown per detection |
| Investigation Reports | 8 structured analyst reports |
| Attack Phases Covered | Initial Access → Discovery → Execution → Credential Access → Persistence → Lateral Movement → C2 |
| Lab Environment | 3-VM Active Directory domain (DC + Endpoint + Kali attacker) |
| Attacker Machine | Kali Linux for authorized cross-machine lab simulations |

---

## Lab Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                  Lab Network: 192.168.10.0/24                │
│                  Domain: SOCLAB.LOCAL                        │
│                                                             │
│  ┌──────────────────────┐   ┌──────────────────────┐        │
│  │  Windows Server 2019 │   │    Windows 10        │        │
│  │  Domain Controller   │◄──│    Victim Endpoint   │        │
│  │  192.168.10.10       │   │    192.168.10.20     │        │
│  │  AD DS + DNS         │   │    Sysmon v15.20     │        │
│  │  Splunk Enterprise   │   │    Splunk UF         │        │
│  │  Sysmon v15.20       │   │    jsmith (domain)   │        │
│  └──────────┬───────────┘   └──────────┬───────────┘        │
│             │     log forwarding        │                   │
│             └──────────┬───────────────┘                   │
│                        ▼  port 9997                         │
│              ┌─────────────────┐                            │
│              │ Splunk indexes  │                            │
│              │ endpoint        │                            │
│              │ wineventlog     │                            │
│              └─────────────────┘                            │
│                                                             │
│  ┌──────────────────────┐                                  │
│  │  Kali Linux          │ ← Authorized attacker machine     │
│  │  192.168.10.50       │   brute force, SMB, recon        │
│  └──────────────────────┘                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Part 1 — Enterprise AD Detection Lab (v2)

Three-VM Active Directory environment with authorized cross-machine attack simulations from Kali Linux. Telemetry is collected in Splunk.

### Lab Setup

- Windows Server 2019 promoted to Domain Controller (`SOCLAB.LOCAL`)
- Windows 10 endpoint domain-joined as `SOCLAB\jsmith`
- Kali Linux attacker on the same isolated network segment
- Sysmon v15.20 deployed on both Windows systems
- Splunk Enterprise receiving endpoint and Windows Security telemetry

### Attack Simulations and Detections

| # | Simulation | MITRE Technique | Tactic | Attacker | Detection | Status |
|---|------------|-----------------|--------|----------|-----------|--------|
| 01 | Suspicious PowerShell Execution | T1059.001 | Execution | Win10 | DET-001 fired | ✅ Validated |
| 02 | Brute Force Login | T1110.001 | Credential Access | Kali Linux | DET-002 fired | ✅ Validated |
| 03 | Credential Dumping Simulation | T1003.001 | Credential Access | Win10 | DET-003 | ⬜ In progress |
| 04 | Scheduled Task Persistence | T1053.005 | Persistence | Win10 | DET-004 | ⬜ In progress |
| 05 | Registry Run Key Persistence | T1547.001 | Persistence | Win10 | DET-005 | ⬜ In progress |
| 06 | Process Injection Indicators | T1055 | Defense Evasion | Win10 | DET-006 | ⬜ In progress |
| 07 | Lateral Movement via SMB | T1021.002 | Lateral Movement | Kali Linux | DET-007 | ⬜ In progress |
| 08 | DNS/HTTP Beacon-like Traffic | T1071.001 / T1071.004 | Command and Control | Win10 | DET-008 | ⬜ In progress |

### Validated Detections

#### DET-001 — Suspicious PowerShell Execution

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

**Observed result:** `SOCLAB\jsmith` ran encoded PowerShell from `cmd.exe`. The suspicious PowerShell behavior was confirmed by command-line telemetry.

#### DET-002 — Brute Force Login

```spl
index=wineventlog EventCode=4625
| stats count AS failures BY Account_Name, Source_Network_Address
| where failures >= 3
| sort -failures
```

**Observed result:** 11 failed SMB logon attempts from Kali Linux (`192.168.10.50`) targeted `testuser01`; Event ID 4740 confirmed account lockout.

---

## Part 2 — Standalone Detection Labs (v1)

Single-VM exercises covering additional security telemetry and investigation scenarios. These labs are not all equivalent to cross-host enterprise attack movement.

### Exercise Sequence

```text
[Lab 4] Initial Access / Phishing Triage
Phishing artifact → suspicious attachment and encoded URL analysis
        ↓
[Lab 1] Discovery
whoami → ipconfig → systeminfo → netstat → tasklist
        ↓
[Lab 2] Execution
PowerShell → Base64 obfuscation → suspicious download behavior
RuntimeBroker.exe → PowerShell (anomalous parent-child relationship)
        ↓
[Lab 3] Credential Access
Repeated authentication attempts and account activity
        ↓
[Lab 5] Authentication
Stored credential target enumeration → Event ID 4648 → localhost RDP workflow
        ↓
[Lab 6] Persistence
Run Key + Service + Winlogon modification
```

### Labs

| # | Lab | MITRE Techniques | Evidence-Based Finding | Status |
|---|-----|------------------|------------------------|--------|
| 1 | [Recon Detection](./labs/Lab1-Recon-Detection.md) | T1033, T1016, T1082 | Discovery commands observed under user and SYSTEM contexts; multiple footholds not independently confirmed | ✅ |
| 2 | [PowerShell Detection](./labs/Lab2-PowerShell-Detection.md) | T1059.001, T1027, T1087.001, T1057 | Suspicious PowerShell confirmed; RuntimeBroker-to-PowerShell relationship is anomalous, not confirmed injection | ✅ |
| 3 | [Brute Force Detection](./labs/Lab3-Brute-Force-Detection.md) | T1110.001, T1078 | Repeated authentication activity observed in the lab | ✅ |
| 4 | [Phishing Triage](./labs/Lab4-Phishing-Triage.md) | T1566.001, T1027, T1036.007 | Encoded URL and masquerading attachment artifacts analyzed | ✅ |
| 5 | [RDP Authentication and Credential Detection](./labs/Lab5-RDP-Lateral-Movement.md) | T1021.001, T1078 | Event ID 4648 confirmed explicit credential use; localhost activity did not demonstrate lateral movement | ✅ |
| 6 | [Persistence Hunt](./labs/Lab6-Persistence-Hunt.md) | T1547.001, T1543.003, T1547.004 | Multiple persistence mechanisms observed in the controlled lab | ✅ |

---

## MITRE ATT&CK Coverage

The table distinguishes validated evidence from planned simulations. A technique is not marked detected merely because a related indicator appeared.

| Tactic | Technique ID | Technique Name | Lab / Simulation | Status |
|--------|--------------|----------------|------------------|--------|
| Initial Access | T1566.001 | Spearphishing Attachment | Lab 4 | ✅ Validated lab evidence |
| Execution | T1059.001 | PowerShell | Lab 2, SIM-001 | ✅ Validated |
| Defense Evasion | T1027 | Obfuscated/Compressed Files and Information | Lab 2, Lab 4 | ✅ Validated |
| Credential Access | T1110.001 | Brute Force: Password Guessing | Lab 3, SIM-002 | ✅ Validated |
| Defense Evasion | T1078 | Valid Accounts | Lab 3, Lab 5 | ✅ Valid-account usage observed |
| Credential Access | T1003.001 | LSASS Memory | SIM-003 | ⬜ In progress |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Lab 6, SIM-005 | ✅ Validated in Lab 6 |
| Persistence | T1543.003 | Windows Service | Lab 6 | ✅ Validated |
| Persistence | T1547.004 | Winlogon Helper DLL | Lab 6 | ✅ Validated |
| Persistence | T1053.005 | Scheduled Task / Job | SIM-004 | ⬜ In progress |
| Defense Evasion | T1055 | Process Injection | SIM-006 | ⬜ Not confirmed in Lab 2; simulation in progress |
| Defense Evasion | T1036.007 | Double File Extension | Lab 4 | ✅ Validated lab artifact |
| Discovery | T1033 | System Owner/User Discovery | Lab 1 | ✅ Validated |
| Discovery | T1016 | System Network Configuration Discovery | Lab 1 | ✅ Validated |
| Discovery | T1082 | System Information Discovery | Lab 1 | ✅ Validated |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | Lab 5 | ⚠️ RDP workflow observed; no cross-host movement |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | SIM-007 | ⬜ In progress |
| Command and Control | T1071.001 | Web Protocols | SIM-008 | ⬜ In progress |
| Command and Control | T1071.004 | DNS | SIM-008 | ⬜ In progress |

**Important exclusions:**

- T1550.002 Pass the Hash was removed because the lab did not use an NTLM hash.
- T1055 Process Injection is not claimed from the RuntimeBroker-to-PowerShell process relationship alone.
- Localhost RDP is not counted as lateral movement between systems.

---

## Tools Used

| Tool | Role | Version |
|------|------|---------|
| Splunk Enterprise | SIEM indexing, search, dashboards, and alerts | 10.4.0 |
| Sysmon | Endpoint telemetry | v15.20 |
| Windows Server 2019 | Domain Controller, AD DS, and DNS | Evaluation |
| Windows 10 | Victim endpoint | 21H2 |
| Kali Linux | Authorized attacker host | 2024.x |
| CyberChef | Encoding and IOC analysis | Online |
| VirusTotal | Hash and URL reputation enrichment | Online |
| MITRE ATT&CK Navigator | Coverage visualization | v14 |
| Hydra / smbclient | Authorized brute-force and SMB simulations | Kali built-in |

---

## Detection Engineering Workflow

```text
Kali / Win10          Sysmon + Windows        Splunk SPL
Attack Simulation ──► Event Log Telemetry ──► Detection Query
      │                                              │
      ▼                                              ▼
Document Evidence      MITRE ATT&CK            Tune + Validate
      ◄────────────── Mapping and Scope ◄────────────┘
      │
      ▼
Investigation Report
(timeline, artifacts,
assessment, confidence)
```

---

## Key Findings

| Simulation / Lab | Finding | Confidence / Status |
|------------------|---------|---------------------|
| SIM-001 PowerShell | `cmd.exe → powershell.exe -EncodedCommand -ExecutionPolicy Bypass` observed through Sysmon Event ID 1 | High confidence |
| SIM-002 Brute Force | 11 SMB failures from Kali `192.168.10.50`; Event ID 4740 confirmed account lockout | Confirmed |
| Lab 1 Recon | Discovery commands ran under user and SYSTEM contexts | Observed; separate footholds not confirmed |
| Lab 2 PowerShell | RuntimeBroker-to-PowerShell is an anomalous parent-child relationship | Suspicious; injection not confirmed |
| Lab 3 Brute Force | Repeated authentication attempts occurred in the controlled lab | High confidence |
| Lab 4 Phishing | Encoded URL and suspicious attachment artifacts were identified | High confidence |
| Lab 5 RDP | Event ID 4648 recorded explicit credential use during localhost RDP testing | Confirmed explicit use; maliciousness and lateral movement not confirmed |
| Lab 6 Persistence | Run Key, service, and Winlogon persistence modifications were observed | High confidence in controlled lab |

---

## Analyst Language Standard

Reports in this repository use the following evidence labels:

- **Observed:** Directly present in logs, commands, screenshots, or artifacts.
- **Assessed:** Analyst interpretation supported by the available evidence.
- **Suspected:** Plausible explanation requiring more telemetry.
- **Confirmed:** Supported by direct, technique-specific evidence or multiple corroborating sources.
- **Not confirmed:** Evidence is insufficient to make the stronger claim.

---

## Key Lessons Learned

1. Sysmon Event ID 1 becomes most useful when `ParentImage`, `CommandLine`, `User`, `IntegrityLevel`, and `ProcessGuid` are evaluated together.
2. A suspicious parent-child process relationship is an investigation lead, not automatic confirmation of process injection.
3. Event ID 4648 records explicit credential use and must be interpreted with process, account, source, destination, and surrounding logon events.
4. Local and cross-machine simulations create different telemetry and should not be described as equivalent.
5. False-positive analysis and narrow tuning are essential parts of detection engineering.
6. Script Block Logging Event ID 4104 improves visibility into PowerShell content, especially when commands are encoded.

---

## Resume Bullet

> Built a multi-VM enterprise SOC detection lab on Active Directory (`SOCLAB.LOCAL`) using Splunk Enterprise, Sysmon v15, Windows Security logs, and Kali Linux; simulated authorized attack behaviors, developed SPL detections, correlated endpoint and authentication telemetry, mapped validated evidence to MITRE ATT&CK, and produced structured investigations with false-positive analysis and confidence-based conclusions.

---

## Repository Structure

```text
enterprise-soc-detection-lab-v2/
├── README.md
├── lab-setup/               ← VM build, network diagram, Splunk + Sysmon setup
├── configs/                 ← sysmonconfig.xml, inputs.conf, indexes.conf
├── detections/              ← SPL rules and detection index
├── attack-simulations/      ← enterprise AD simulations
├── investigation-reports/   ← analyst reports per detection
├── mitre-attack-mapping/     ← technique mapping and validation status
├── dashboards/              ← Splunk dashboard SPL panels
├── false-positive-analysis/ ← tuning notes and recommendations
├── resume-linkedin/         ← resume and interview material
├── labs/                    ← standalone lab reports
└── screenshots/             ← Splunk, Sysmon, and attack evidence
```

---

## Disclaimer

> This project is built entirely for educational and defensive security research. All simulations are performed in an isolated private lab with no connection to production systems or third-party networks. No unauthorized access was performed. All offensive techniques are used only to generate defensive telemetry and improve detection and investigation skills.
