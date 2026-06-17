# SOC Detection Labs

Standalone SOC investigations covering Windows discovery, suspicious PowerShell, authentication attacks, phishing triage, explicit credential use, and persistence detection.

Each lab includes:

* Attack or behavior simulation
* Splunk detection queries
* Evidence-based analyst findings
* MITRE ATT&CK mapping
* False-positive analysis
* Response recommendations
* Low — Lab4 has no real screenshots

## Labs

| Lab                                                                                         | Detection Focus                                                                                     | MITRE ATT&CK                                                   | Primary Data Sources                                           | Status     |
| ------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------- | ---------- |
| [Lab 1: Windows Discovery Command Detection](./Lab1-Recon-Detection.md)                     | Burst of system, account, network, process, and registry discovery commands                         | T1033, T1016, T1082, T1087.001, T1069.001, T1049, T1057, T1012 | Sysmon Event ID 1, Splunk                                      | ✅ Complete |
| [Lab 2: Suspicious PowerShell Execution Detection](./Lab2-PowerShell-Detection.md)          | Encoded PowerShell, download behavior, discovery commands, and anomalous parent-child relationships | T1059.001, T1027, T1087.001, T1057, T1055 (suspected — not confirmed)                             | Sysmon Event IDs 1, 8, 10; Windows Defender                    | ✅ Complete |
| [Lab 3: Windows Password Guessing Detection](./Lab3-Brute-Force-Detection.md)               | Rapid failed authentication attempts against one account                                            | T1110.001                                                      | Windows Security Event IDs 4624, 4625, 4740                    | ✅ Complete |
| [Lab 4: Phishing Email Triage](./Lab4-Phishing-Triage.md)                                   | Brand impersonation, suspicious link, encoded URL, and double-extension attachment                  | T1566.001, T1566.002, T1036.007, T1027                         | Email gateway, proxy, DNS, Sysmon, Windows Defender            | ✅ Complete |
| [Lab 5: RDP Workflow and Explicit Credential Use Detection](./Lab5-RDP-Lateral-Movement.md) | Event ID 4648, localhost authentication, Credential Manager enumeration, and RDP-client activity    | T1021.001 and T1078 — partial simulation only                  | Windows Security Event IDs 4624, 4625, 4648; Sysmon Event ID 1 | ✅ Complete |
| [Lab 6: Windows Persistence Mechanism Detection](./Lab6-Persistence-Hunt.md)                | Registry Run key, Windows service, and Winlogon `Userinit` persistence                              | T1547.001, T1543.003, T1547.004, T1036.005, T1112              | Sysmon Event IDs 1, 11, 13; Windows Security Event ID 4697     | ✅ Complete |

## Evidence Standard

The reports distinguish between:

* **Observed:** Directly present in logs, commands, or artifacts
* **Assessed:** Analyst interpretation supported by available evidence
* **Confirmed:** Supported by direct technique-specific or corroborating evidence
* **Not confirmed:** Available evidence is insufficient for the stronger conclusion

## Important Scope Notes

* Lab 2 does not claim confirmed process injection based only on the `RuntimeBroker.exe → powershell.exe` relationship.
* Lab 3 demonstrates password guessing, not password spraying.
* Lab 4 uses simulated indicators and reserved example infrastructure.
* Lab 5 uses localhost and therefore does not demonstrate lateral movement between hosts.
* Lab 6 detects additional content after the normal Winlogon `userinit.exe,` value rather than alerting on the normal trailing comma.
