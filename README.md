# SOC Analyst Portfolio
![Splunk](https://img.shields.io/badge/Splunk-10.2.0-green)
![Sysmon](https://img.shields.io/badge/Sysmon-15.15-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Windows](https://img.shields.io/badge/OS-Windows%2010-blue)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Vishva Teja Chikoti** | Cybersecurity  | SOC Analyst

> Real attacks simulated on Windows VM, detected using Sysmon + Splunk.
> Each lab documents the full attack chain: simulation → detection → analysis → response.

---

## Labs

| # | Lab | Attack Technique | MITRE ID | Tools | Status |
|---|-----|-----------------|----------|-------|--------|
| 1 | [Recon Detection](./labs/Lab1-Recon-Detection.md) | Post-Exploitation Recon | T1033, T1016, T1082 | Splunk, Sysmon | ✅ |
| 2 | [PowerShell Detection](./labs/Lab2-PowerShell-Detection.md) | Malicious PowerShell | T1059.001, T1027, T1055 | Splunk, Sysmon | ✅ |
| 3 | [Brute Force Detection](./labs/Lab3-Brute-Force-Detection.md) | Password Guessing | T1110.001, T1078 | Splunk, Sysmon | ✅ |
| 4 | [Phishing Triage](./labs/Lab4-Phishing-Triage.md) | Spearphishing + Obfuscation | T1566.001, T1027, T1036.007 | CyberChef, VirusTotal | ✅ |
| 5 | [RDP Lateral Movement](./labs/Lab5-RDP-Lateral-Movement.md) | Credential Abuse + RDP | T1021.001, T1550.002, T1078 | Splunk, Sysmon | ✅ |
| 6 | [Persistence Hunt](./labs/Lab6-Persistence-Hunt.md) | Registry + Winlogon Hijack | T1547.001, T1543.003, T1547.004 | Splunk, Sysmon | ✅ |
| 7 | Malware Dropper Simulation | Process Injection + C2 | T1055, T1071 | Splunk, Sysmon | 🔄 |
| 8 | Full Incident Case Study | Full Attack Chain | T1566→T1059→T1021→T1547 | Splunk, Sysmon | 🔄 |

---

## Portfolio Stats

| Metric | Value |
|--------|-------|
| Total Labs | 6 complete / 8 planned |
| Security Events Analyzed | 4,123+ real Windows events |
| MITRE ATT&CK Techniques Mapped | 18 techniques across 6 labs |
| Custom SPL Detection Rules | 6 rules |
| Attack Phases Covered | Recon → Execution → Credential Access → Lateral Movement → Persistence |
| Persistence Methods Detected | 3 simultaneous (Run Key, Service, Winlogon Hijack) |
| Mean Time to Triage | <15 min per investigation |

---

## Key Findings Across Labs

| Lab | Critical Finding | Impact |
|-----|-----------------|--------|
| Recon | SYSTEM + Aura both running recon = dual foothold | HIGH |
| PowerShell | RuntimeBroker.exe → PowerShell = process injection | CRITICAL |
| Brute Force | 10 attempts in 5 sec from localhost via svchost | CRITICAL |
| Phishing | Base64 URL decoded to evil.com/steal + pdf.exe attachment | CRITICAL |
| RDP | EventCode 4648 = explicit credential abuse via cmdkey | HIGH |
| Persistence | 3 simultaneous backdoors: Run key + Service + Winlogon hijack | CRITICAL |

---

## Complete Attack Chain

All 6 labs form a realistic full kill chain:
```
[Lab 4] Initial Access
Phishing email → weaponized PDF.exe → credential harvesting
        ↓
[Lab 1] Reconnaissance
whoami → ipconfig → systeminfo → netstat → tasklist
        ↓
[Lab 2] Execution
Malicious PowerShell → Base64 obfuscation → C2 beaconing
RuntimeBroker.exe → PowerShell (process injection)
        ↓
[Lab 3] Credential Access
Brute force from localhost → 10 attempts/5 sec via svchost
        ↓
[Lab 5] Lateral Movement
cmdkey stored creds → EventCode 4648 → RDP pivot
        ↓
[Lab 6] Persistence
Run Key (WindowsUpdate) + Fake Service (WindowsHelper)
+ Winlogon Userinit Hijack = 3 redundant backdoors
```

---

## Detection Rules Library

6 custom SPL rules covering all attack phases:
[View Detection Rules →](./detection/splunk-queries.md)

---

## Environment

| Component | Tool | Version |
|-----------|------|---------|
| SIEM | Splunk Enterprise | 10.2.0 |
| Endpoint Monitoring | Sysmon | 15.15 |
| OS | Windows 10 VM | DESKTOP-G908C2D |
| Log Forwarding | Splunk Universal Forwarder | Latest |
| Analysis Tools | CyberChef, VirusTotal | Online |

---

## Skills Demonstrated

- Real Windows telemetry analysis (4,123+ events)
- SPL query writing + alert tuning
- MITRE ATT&CK mapping (18 techniques)
- Full incident documentation with analyst narratives
- Detection rule creation + false positive analysis
- Attack chain correlation across 6 phases
- Base64 decoding + IOC extraction
- Registry persistence hunting
- Authentication log analysis (4624/4625/4648)
- Process injection detection

---

## Contact
[LinkedIn](https://linkedin.com/in/vishvack) • [Email](mailto:vchik2@unh.newhaven.edu) • Open to SOC Analyst L1 roles
```
