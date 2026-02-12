# Lab 5: RDP Lateral Movement Detection

**Date:** 2026-02-12
**Analyst:** Vishva Teja Chikoti
**Severity:** HIGH
**Difficulty:** Intermediate

---

## Objective
Simulate RDP-based lateral movement using stored Windows
credentials. Detect authentication events using Windows
Security logs in Splunk. Identify attacker pivot patterns
using EventCode correlation.

---

## Lab Setup

| Component | Detail |
|-----------|--------|
| Environment | Windows 10 VM |
| Data Source | Windows Security Event Logs |
| Tools Used | Splunk 10.2.0, cmdkey, mstsc |
| Key Event IDs | 4624, 4625, 4648 |

---

## Analyst Narrative

During investigation of authentication logs, I identified
a critical sequence at 04:16:55 AM: two interactive logins
from 127.0.0.1 (LogonType 2) immediately followed by
EventCode 4648 (explicit credential use) at the exact same
timestamp.

This pattern indicates an attacker who:
1. Discovered stored credentials via cmdkey /list
2. Used those credentials explicitly to authenticate
3. Initiated a local RDP session (127.0.0.1)

The 4648 event is the smoking gun — it fires when credentials
are explicitly passed rather than using the current session
token. Normal users don't trigger 4648. Attackers do.

Key differentiator: 81 total auth events, but only 3 are
suspicious. The rest (LogonType 5) are normal service logons.
This is exactly the needle-in-haystack scenario SOC analysts
face daily.

---

## Attack Simulation
```cmd
# Check stored credentials (attacker reconnaissance)
cmdkey /list

# Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Connect via RDP using stored credentials
mstsc /v:127.0.0.1
```

**What cmdkey revealed:**
```
Target: WindowsLive:target=virtualapp/didlogical
Type:   Generic
User:   02eafqtbefhzxohn
Local machine persistence
```
Stored credential = attacker's free ticket to authenticate
without knowing the password.

---

## Detection Query
```splunk
index=main (EventCode=4624 OR EventCode=4625 OR EventCode=4648)
| rex field=_raw "Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| rex field=_raw "Source Network Address:\s+(?<SrcIP>\S+)"
| table _time, EventCode, TargetUser, SrcIP, LogonType, ComputerName
| sort _time
```

### Lateral Movement Alert Query
```splunk
index=main EventCode=4648
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| rex field=_raw "Target Server Name:\s+(?<TargetServer>\S+)"
| table _time, TargetUser, TargetServer, ComputerName
| sort _time
```

### RDP-Specific Detection (LogonType 10)
```splunk
index=main EventCode=4624
| rex field=_raw "Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "Account Name:\s+(?<TargetUser>\S+)"
| rex field=_raw "Source Network Address:\s+(?<SrcIP>\S+)"
| where LogonType=10
| table _time, TargetUser, SrcIP, ComputerName
| sort _time
```

---

## Findings

**Total Events:** 81 authentication events
**Timeframe:** 04:16:43 - 07:06:33 AM
**Suspicious Events:** 3 (needle in haystack)

### Critical Event Sequence:

| Time | EventCode | LogonType | SrcIP | Significance |
|------|-----------|-----------|-------|-------------|
| 04:16:55 | 4624 | 2 | 127.0.0.1 | Interactive local login |
| 04:16:55 | 4624 | 2 | 127.0.0.1 | Duplicate session token |
| 04:16:55 | 4648 | - | - | 🚨 Explicit credential use |

### Normal vs Suspicious:

| LogonType | Count | Classification |
|-----------|-------|---------------|
| 5 (Service) | 78 | ✅ Normal service logons |
| 2 (Interactive) from 127.0.0.1 | 2 | 🚨 Suspicious local RDP |
| 4648 (Explicit creds) | 1 | 🚨 Credential abuse |

---

## EventCode Reference

| EventCode | Meaning | SOC Relevance |
|-----------|---------|---------------|
| 4624 | Successful logon | Check LogonType |
| 4625 | Failed logon | Brute force indicator |
| 4648 | Explicit credential logon | Lateral movement indicator |
| LogonType 2 | Interactive | Local console/RDP |
| LogonType 5 | Service | Normal, low priority |
| LogonType 10 | RemoteInteractive | RDP session |

---

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|----|-----------|---------|
| T1021.001 | RDP | mstsc /v:127.0.0.1 |
| T1550.002 | Pass the Hash/Creds | EventCode 4648 |
| T1078 | Valid Accounts | Stored credential abuse |
| T1552.001 | Credentials in Files | cmdkey stored creds |
| T1076 | RDP Hijacking | Local RDP via stored creds |

---

## Alert Rule Logic
```
IF EventCode=4648
AND followed by EventCode=4624 LogonType=10
WITHIN 60 seconds
THEN → CRITICAL: RDP Lateral Movement Detected

IF EventCode=4624 LogonType=2
AND SrcIP=127.0.0.1 OR SrcIP=::1
AND NOT known_admin_account
THEN → HIGH: Suspicious Local Interactive Login
```

---

## Risk Rating

**HIGH**

| Factor | Assessment |
|--------|-----------|
| Stored credentials discovered | CRITICAL |
| Explicit credential use (4648) | HIGH |
| Local RDP from localhost | HIGH |
| Potential for further pivoting | HIGH |

---

## Containment Actions
```
1. Identify all systems with stored credentials (cmdkey /list)
2. Clear credential manager on compromised host
3. Check for lateral movement to other hosts
4. Review all 4648 events across network
5. Disable RDP if not required
6. Reset credentials for affected accounts
7. Escalate to L2 for full forensic investigation
```

---

## False Positives

| Scenario | Mitigation |
|----------|------------|
| Admin using RunAs | Known admin accounts whitelist |
| Service account auth | Whitelist service account 4648 events |
| Remote management tools | Whitelist known IT management IPs |

---

## Lessons Learned

1. **4648 = red flag always** — explicit creds rarely legitimate
2. **cmdkey stores creds in plaintext** — attacker goldmine
3. **81 events, 3 suspicious** — filter noise or miss the attack
4. **Same timestamp cluster** — correlated events tell the story
5. **LogonType matters** — Type 5 = ignore, Type 2/10 = investigate
6. **127.0.0.1 as SrcIP** = attacker already inside the machine
```

