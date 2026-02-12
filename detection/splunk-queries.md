# SPL Detection Rules

> Custom Splunk queries written during lab investigations.
> Each rule includes trigger logic, false positive notes, and severity.

---

## Rule 1: Post-Exploitation Recon Detection
**Severity:** HIGH
**MITRE:** T1033, T1016, T1082
```splunk
index=main EventCode=1
| search CommandLine="*whoami*" 
  OR CommandLine="*net user*" 
  OR CommandLine="*ipconfig*" 
  OR CommandLine="*systeminfo*" 
  OR CommandLine="*netstat*" 
  OR CommandLine="*tasklist*"
| stats count by User, CommandLine, ParentImage
| where count > 1
| sort -count
```

**Trigger when:** 3+ recon commands, same user, within 10 min  
**False positives:** IT admins, helpdesk diagnostics  

---

## Rule 2: Malicious PowerShell Detection
**Severity:** CRITICAL
**MITRE:** T1059.001, T1027
```splunk
index=main EventCode=1 Image="*powershell*"
NOT Image="*SplunkUniversalForwarder*"
NOT Image="*Splunk\bin*"
| search CommandLine="*IEX*" 
  OR CommandLine="*DownloadString*" 
  OR CommandLine="*EncodedCommand*"
  OR CommandLine="*bypass*"
| table _time, User, CommandLine, ParentImage, IntegrityLevel
| sort _time
```

**Trigger when:** PowerShell uses download/encode/bypass keywords  
**False positives:** Legitimate admin scripts (whitelist known hashes)  

---

## Rule 3: Suspicious PowerShell Parent Process
**Severity:** CRITICAL
**MITRE:** T1055
```splunk
index=main EventCode=1 Image="*powershell*"
| search ParentImage="*RuntimeBroker*" 
  OR ParentImage="*explorer.exe*"
  OR ParentImage="*mshta.exe*"
  OR ParentImage="*wscript.exe*"
| table _time, User, CommandLine, ParentImage
| sort _time
```

**Trigger when:** PowerShell spawned by unusual parent process  
**False positives:** Rare. Investigate every hit.  

---

## Rule 4: Brute Force Detection
**Severity:** HIGH
**MITRE:** T1110.001
```splunk
index=main EventCode=4625
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| bucket _time span=1m
| stats count by _time, TargetUser
| where count > 5
| sort -count
```

**Trigger when:** 5+ failed logins same account within 1 minute  
**False positives:** User forgot password (usually <5 attempts)  

---

## Rule 5: Brute Force Success (Critical)
**Severity:** CRITICAL
**MITRE:** T1078
```splunk
index=main (EventCode=4625 OR EventCode=4624)
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| transaction TargetUser maxspan=5m
| search EventCode=4625 AND EventCode=4624
| table _time, TargetUser, duration
```

**Trigger when:** Failed logins followed by successful login  
**False positives:** User finally remembered password  
**Note:** Every hit requires immediate investigation  

---

## Rule 6: Internal Brute Force Indicator
**Severity:** CRITICAL
**MITRE:** T1110.001
```splunk
index=main EventCode=4625
| rex field=_raw "Source Network Address:\s+(?<SrcIP>\S+)"
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| where SrcIP="::1" OR SrcIP="127.0.0.1"
| stats count by SrcIP, TargetUser
| where count > 3
```

**Trigger when:** Brute force originates from localhost  
**False positives:** Almost none  
**Note:** Internal origin = attacker already inside network  
```
