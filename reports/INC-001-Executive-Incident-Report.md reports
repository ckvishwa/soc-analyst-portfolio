# INC-001 — Executive Incident Report

**Classification:** TLP:GREEN — Internal Distribution  
**Report Date:** 2026-02-12  
**Prepared By:** Vishva Teja Chikoti, SOC Analyst L1  
**Reviewed By:** SOC L2 — Incident Response Team  
**Status:** Closed — Contained  

---

## Executive Summary

On 2026-02-12, SOC monitoring detected a multi-stage intrusion
on endpoint DESKTOP-G908C2D. The attacker demonstrated a complete
post-exploitation sequence spanning reconnaissance, malicious code
execution, credential brute force, lateral movement preparation,
and persistence establishment.

All activity was detected, triaged, and escalated within 15
minutes of initial alert. No data exfiltration was confirmed.
Three simultaneous persistence mechanisms were identified and
documented for remediation.

**Severity:** CRITICAL  
**Affected Systems:** 1 endpoint (DESKTOP-G908C2D)  
**Detection Time:** <15 minutes  
**Containment Status:** Contained  

---

## Incident Timeline

| Time (UTC) | Phase | Event |
|---|---|---|
| 02:10:00 | Recon | whoami, ipconfig, systeminfo executed |
| 02:15:00 | Execution | Malicious PowerShell — Base64 encoded payload |
| 02:20:00 | Execution | RuntimeBroker.exe spawned PowerShell (injection) |
| 03:45:22 | Credential Access | 10 failed logins in 5 sec via svchost.exe |
| 04:00:00 | Lateral Movement | cmdkey stored creds — EventID 4648 |
| 04:30:00 | Persistence | Run Key + Fake Service + Winlogon hijack |
| 04:45:00 | Detection | Splunk alert fired — SOC L1 notified |
| 04:58:00 | Triage | Alert classified HIGH — Jira SOC-001 opened |
| 05:00:00 | Escalation | Full handoff package sent to L2-IR |

---

## Attack Chain Summary
```
[Recon] → [Execution] → [Credential Access] → [Lateral Movement] → [Persistence]
  T1033      T1059.001       T1110.001            T1550.002           T1547.001
  T1016      T1027           T1078                T1021.001           T1543.003
  T1082      T1055                                                    T1546.002
```

---

## Affected Assets

| Asset | Type | Impact |
|---|---|---|
| DESKTOP-G908C2D | Windows 10 Endpoint | Compromised — persistence installed |
| Administrator account | Local Account | Targeted in brute force |
| Aura account | Local Account | Targeted in brute force |

---

## Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Process | svchost.exe | Brute force origin |
| Process | RuntimeBroker.exe | PowerShell injection parent |
| Registry Key | HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate | Persistence |
| Service | WindowsHelper | Fake service persistence |
| Registry Key | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon | Winlogon hijack |
| File | C:\Users\Public\test-malware.txt | EICAR test — Defender detected |
| Network | ::1 (localhost) | Internal brute force origin |
| Command | powershell -enc [base64] | Obfuscated execution |

---

## Detection Sources

| Source | Signal | Confidence |
|---|---|---|
| Splunk (Sysmon EventID 1) | Process creation — recon + PowerShell | HIGH |
| Splunk (Security EventID 4625) | 10 failed logins in 5 seconds | HIGH |
| Splunk (Security EventID 4648) | Explicit credential use — lateral movement | HIGH |
| Splunk (Sysmon EventID 13) | Registry persistence — Run key | HIGH |
| Windows Defender (EventID 1117) | Malware quarantined | CONFIRMED |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | System Owner Discovery | T1033 |
| Reconnaissance | Network Configuration Discovery | T1016 |
| Reconnaissance | System Information Discovery | T1082 |
| Execution | PowerShell | T1059.001 |
| Execution | Obfuscated Files | T1027 |
| Execution | Process Injection | T1055 |
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Credential Access | Valid Accounts | T1078 |
| Lateral Movement | Use Alternate Auth Material | T1550.002 |
| Lateral Movement | Remote Desktop Protocol | T1021.001 |
| Persistence | Registry Run Keys | T1547.001 |
| Persistence | Windows Service | T1543.003 |
| Persistence | Winlogon Helper DLL | T1546.002 |

---

## Response Actions Taken

| Action | Status | Owner |
|---|---|---|
| Alert triaged in Splunk | ✅ Complete | SOC L1 |
| Jira ticket SOC-001 opened | ✅ Complete | SOC L1 |
| IOCs extracted and documented | ✅ Complete | SOC L1 |
| L2 escalation handoff delivered | ✅ Complete | SOC L1 |
| Defender quarantine confirmed | ✅ Complete | EDR Auto |
| Persistence mechanisms documented | ✅ Complete | SOC L1 |
| Remediation recommended to L2 | ✅ Complete | SOC L1 |

---

## Recommendations

| Priority | Action | Owner |
|---|---|---|
| CRITICAL | Remove 3 persistence mechanisms | L2-IR |
| CRITICAL | Reset compromised account passwords | IT Admin |
| HIGH | Audit all accounts for unauthorized access | L2-IR |
| HIGH | Hunt for lateral movement to other hosts | L2-IR |
| MEDIUM | Tune SPL rules to reduce FP noise | SOC L1 |
| MEDIUM | Add cloud IAM monitoring | SOC Engineering |
| LOW | Schedule endpoint reimaging | IT Admin |

---

## Lessons Learned

- Internal brute force via svchost = attacker already inside
- Three simultaneous persistence = sophisticated actor
- SIEM + EDR correlation increased verdict confidence
- Sub-15 min triage time achieved across full kill chain

---

## NIST SP 800-61 Phase Completion

| Phase | Status |
|---|---|
| Preparation | ✅ Detection rules pre-built |
| Detection & Analysis | ✅ Completed in <15 min |
| Containment | ✅ EDR auto-quarantine + L1 actions |
| Eradication | 🔄 Handed to L2-IR |
| Recovery | 🔄 Pending L2-IR |
| Post-Incident | ✅ This report |

---

**Report prepared by:** Vishva Teja Chikoti — SOC Analyst L1  
**GitHub:** github.com/ckvishwa  
**LinkedIn:** linkedin.com/in/ckvishwa
