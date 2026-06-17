# Attack Simulation 07 — Lateral Movement Attempts

**Simulation ID:** SIM-007 | **MITRE:** T1021.002 | **Tactic:** Lateral Movement | **Severity:** High

## Objective
Simulate lateral movement via SMB by authenticating from the Kali or Windows endpoint to the lab Domain Controller using lab credentials and accessing administrative shares. Generates Windows Security Event ID 4624 (Logon Type 3) and Event ID 5140 (Share Access) on the target host.

## MITRE ATT&CK Technique
- **Technique:** T1021.002 — Remote Services: SMB/Windows Admin Shares
- **Reference:** https://attack.mitre.org/techniques/T1021/002/

> ⚠️ **SAFETY NOTE:** Only use lab credentials against lab machines on the isolated network. This simulation uses `net use` — a built-in Windows command — to connect to a lab share. No exploitation, no vulnerability abuse.

## Lab-Only Simulation Method

### From WIN10-VICTIM (net use to DC)
```cmd
REM Connect to lab DC administrative share using lab credentials
net use \\192.168.10.10\ADMIN$ /user:SOCLAB\Administrator LabAdminPass123!

REM Also test IPC$ (common in lateral movement recon)
net use \\192.168.10.10\IPC$ /user:SOCLAB\Administrator LabAdminPass123!

REM Cleanup
net use \\192.168.10.10\ADMIN$ /delete
net use \\192.168.10.10\IPC$ /delete
```

### From Kali (smbclient)
```bash
# Kali VM — lab network only
smbclient //192.168.10.10/ADMIN$ -U "SOCLAB\\Administrator%LabAdminPass123!"
# Then type: ls (to list share), then exit
```

## Expected Event IDs
| Event | Log | Host | Key Fields |
|-------|-----|------|-----------|
| 4624 | Security | DC (target) | `Logon_Type: 3`, `Account_Name`, `IpAddress` of source |
| 5140 | Security | DC (target) | `ShareName: \\*\ADMIN$`, `IpAddress`, `Account_Name` |
| 5145 | Security | DC (target) | Detailed share access — files/directories accessed |
| 4648 | Security | Source host | Explicit credential use (if runas or net use with credentials) |

## Detection SPL (Reference)
```spl
index=wineventlog sourcetype="WinEventLog:Security"
EventID=5140
ShareName IN ("*ADMIN$*","*C$*","*IPC$*")
| join type=left Account_Name
  [search index=wineventlog EventID=4624 Logon_Type=3 | table Account_Name, IpAddress, _time]
| where NOT IpAddress IN ("192.168.10.10","192.168.10.30")
| table _time, ComputerName, Account_Name, IpAddress, ShareName
```

## Defensive Takeaway
The most effective control against SMB lateral movement is disabling administrative shares (ADMIN$, C$) on workstations — these shares have no legitimate business use on endpoints. On servers, monitor for admin share access from non-server source IPs as high-confidence lateral movement activity.
