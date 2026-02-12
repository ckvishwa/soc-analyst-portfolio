# SOC Analyst Portfolio
![Splunk](https://img.shields.io/badge/Splunk-10.2.0-green)
![Sysmon](https://img.shields.io/badge/Sysmon-15.15-blue)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**Vishva Teja Chikoti** | Cybersecurity Graduate Student | SOC Analyst

> Real attacks simulated on Windows VM, detected using Sysmon + Splunk.
> Each lab documents the full attack chain: simulation → detection → analysis → response.

---

## Labs

| # | Lab | Attack Technique | MITRE ID | Tools | Status |
|---|-----|-----------------|----------|-------|--------|
| 1 | [Recon Detection](./labs/Lab1-Recon-Detection.md) | Post-Exploitation Recon | T1033, T1016, T1082 | Splunk, Sysmon | ✅ |
| 2 | [PowerShell Detection](./labs/Lab2-PowerShell-Detection.md) | Malicious PowerShell | T1059.001, T1027, T1055 | Splunk, Sysmon | ✅ |
| 3 | [Brute Force Detection](./labs/Lab3-Brute-Force-Detection.md) | Password Guessing | T1110.001, T1078 | Splunk, Sysmon | ✅ |
| 4 | Phishing Investigation | Spearphishing | T1566.001 | Splunk, Wireshark | 🔄 |
| 5 | Lateral Movement Detection | Pass-the-Hash | T1550.002 | Splunk, Sysmon | 🔄 |

---

## Key Findings Across Labs

| Lab | Critical Finding | Impact |
|-----|-----------------|--------|
| Recon | 2 accounts (SYSTEM + Aura) running recon = dual foothold | HIGH |
| PowerShell | RuntimeBroker.exe spawning PowerShell = process injection | CRITICAL |
| Brute Force | Attack from localhost via svchost = already inside network | CRITICAL |

---

## Detection Rules
All SPL queries used across labs:
[View Detection Rules](./detection/splunk-queries.md)

---

## Attack Chain
These 3 labs form a complete post-exploitation sequence:
```
Initial Access
     ↓
[Lab 1] Recon → whoami, ipconfig, systeminfo, netstat
     ↓
[Lab 2] Execution → Malicious PowerShell, Process Injection
     ↓
[Lab 3] Credential Access → Brute Force from inside machine
```

---

## Environment

| Component | Tool | Version |
|-----------|------|---------|
| SIEM | Splunk Enterprise | 10.2.0 |
| Endpoint Monitoring | Sysmon | 15.15 |
| OS | Windows 10 | VM |
| Log Forwarding | Splunk Universal Forwarder | Latest |

---

## Skills Demonstrated
- Alert triage (TP/FP classification)
- SPL query writing
- MITRE ATT&CK mapping
- Incident documentation
- Detection rule creation
- Attack chain correlation

---

## Contact
[LinkedIn](#) • [Email](#) • Open to SOC Analyst opportunities
```

---

**Commit message:**
```
Upgrade README with full portfolio showcase
