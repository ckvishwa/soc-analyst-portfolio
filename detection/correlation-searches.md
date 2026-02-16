# SPL Correlation Searches

**Analyst:** Vishva Teja Chikoti  
**Last Updated:** 2026-02-15  
**Purpose:** Cross-event correlation to detect multi-stage attacks  

---

## CORR-001 — Full Kill Chain Correlation

**What it detects:** Single host exhibiting recon → execution → 
credential access → lateral movement → persistence within 1 hour.  
**Severity:** CRITICAL  
**MITRE:** T1033, T1059.001, T1110.001, T1550.002, T1547.001  
```splunk
index=main
| eval phase=case(
    EventCode=1 AND match(CommandLine,"whoami|ipconfig|systeminfo|netstat|tasklist"), "1-Recon",
    EventCode=1 AND match(CommandLine,"powershell|encoded|bypass|hidden|downloadstring"), "2-Execution",
    EventCode=4625, "3-CredentialAccess",
    EventCode=4648, "4-LateralMovement",
    EventCode IN (13,11) AND match(TargetObject,"Run|Services|Winlogon"), "5-Persistence"
)
| where isnotnull(phase)
| stats values(phase) as phases, values(CommandLine) as commands,
  min(_time) as first_seen, max(_time) as last_seen
  by ComputerName
| eval attack_duration_min=round((last_seen-first_seen)/60,1)
| where mvcount(phases) >= 3
| eval threat_score=mvcount(phases)*20
| table ComputerName, phases, threat_score, attack_duration_min,
  first_seen, last_seen, commands
| sort -threat_score
```

**Alert threshold:** threat_score >= 60 (3+ phases on same host)  
**Expected result:** DESKTOP-G908C2D showing all 5 phases  

---

## CORR-002 — Brute Force Followed by Successful Login

**What it detects:** Failed logins then success = brute force succeeded.  
**Severity:** CRITICAL  
**MITRE:** T1110.001, T1078  
```splunk
index=main (EventCode=4625 OR EventCode=4624)
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| eval outcome=if(EventCode=4625,"FAIL","SUCCESS")
| stats values(outcome) as outcomes, count by TargetUser, ComputerName
| where mvcount(outcomes) > 1
| where mvfind(outcomes,"SUCCESS") >= 0
| eval verdict="BRUTE FORCE SUCCEEDED - CRITICAL"
| table ComputerName, TargetUser, outcomes, verdict
```

---

## CORR-003 — PowerShell Spawned from Suspicious Parent

**What it detects:** PowerShell launched by non-standard parent process.  
**Severity:** HIGH  
**MITRE:** T1059.001, T1055  
```splunk
index=main EventCode=1
| rex field=_raw "Image:\s+(?<ChildProcess>[^\r\n]+)"
| rex field=_raw "ParentImage:\s+(?<ParentProcess>[^\r\n]+)"
| search ChildProcess="*powershell*"
| where NOT match(ParentProcess,
  "explorer\.exe|cmd\.exe|powershell\.exe|svchost\.exe")
| table _time, ComputerName, ParentProcess, ChildProcess, CommandLine
| sort -_time
```

---

## CORR-004 — EDR + SIEM Combined Alert

**What it detects:** Defender quarantine event correlated with 
Sysmon process creation — confirms malware execution attempt.  
**Severity:** HIGH  
**MITRE:** T1204.002  
```splunk
index=main (source="WinEventLog:Microsoft-Windows-Windows Defender/Operational"
AND (EventCode=1116 OR EventCode=1117))
OR (EventCode=1 AND match(CommandLine,"*.exe*"))
| eval source_type=if(EventCode=1116 OR EventCode=1117,
  "EDR-Defender","SIEM-Sysmon")
| stats values(source_type) as signal_sources,
  values(EventCode) as event_codes
  by ComputerName
| where mvcount(signal_sources) > 1
| eval verdict="SIEM+EDR CORRELATED — HIGH CONFIDENCE"
| table ComputerName, signal_sources, event_codes, verdict
```

---

## CORR-005 — Persistence After Brute Force

**What it detects:** Registry/service persistence within 30 min 
of brute force activity on same host.  
**Severity:** CRITICAL  
**MITRE:** T1110.001, T1547.001, T1543.003  
```splunk
index=main
| eval event_type=case(
    EventCode=4625, "BruteForce",
    EventCode IN (11,13) AND
    match(TargetObject,"Run|Services|Winlogon"), "Persistence"
)
| where isnotnull(event_type)
| stats values(event_type) as types,
  min(_time) as first_seen,
  max(_time) as last_seen
  by ComputerName
| eval time_gap_min=round((last_seen-first_seen)/60,1)
| where mvcount(types) > 1 AND time_gap_min <= 30
| eval verdict="POST-BRUTE FORCE PERSISTENCE DETECTED"
| table ComputerName, types, time_gap_min, verdict
```

---

## False Positive Tuning

| Query | Known FP | Tuning Applied |
|---|---|---|
| CORR-001 | Sysadmin running recon tools legitimately | Whitelist admin accounts |
| CORR-002 | Password manager retry bursts | Threshold >5 fails in 60s |
| CORR-003 | Legit automation scripts | Whitelist known script paths |
| CORR-004 | AV scan triggering detection | Check file path = temp/public |
| CORR-005 | Software install writing to Run key | Verify parent = installer process |

---

## Whitelist Template
```splunk
| where NOT (TargetUser="admin_service" OR
             TargetUser="backup_agent" OR
             ComputerName="PATCH-SERVER")
```

---

## MITRE ATT&CK Coverage Map

| Technique | ID | Covered By |
|---|---|---|
| Recon Commands | T1033, T1016, T1082 | CORR-001 |
| PowerShell Execution | T1059.001 | CORR-001, CORR-003 |
| Brute Force | T1110.001 | CORR-001, CORR-002 |
| Brute Force Success | T1078 | CORR-002 |
| Process Injection | T1055 | CORR-003 |
| Malware Execution | T1204.002 | CORR-004 |
| Registry Persistence | T1547.001 | CORR-001, CORR-005 |
| Service Persistence | T1543.003 | CORR-005 |
