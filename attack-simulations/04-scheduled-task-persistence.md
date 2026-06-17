# Attack Simulation 04 — Scheduled Task Persistence

**Simulation ID:** SIM-004 | **MITRE:** T1053.005 | **Tactic:** Persistence | **Severity:** High

## Objective
Create a scheduled task using schtasks.exe that invokes PowerShell — generating Windows Security Event ID 4698 and Sysmon Event ID 1 telemetry that the scheduled task persistence detection rule captures.

## MITRE ATT&CK Technique
- **Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
- **Reference:** https://attack.mitre.org/techniques/T1053/005/

## Lab-Only Simulation Method

### Simulation Command (Run as standard user on WIN10-VICTIM)
```cmd
schtasks /create /tn "SimulationTask01" /tr "powershell.exe -Command Write-Host 'lab_sim_04'" /sc onlogon /ru SOCLAB\jsmith /f
```

**What this does:** Creates a scheduled task named "SimulationTask01" that runs a harmless PowerShell command at logon. Generates Event 4698 with the task name and XML content, plus Sysmon Event 1 for schtasks.exe execution.

### Cleanup After Testing
```cmd
schtasks /delete /tn "SimulationTask01" /f
```

## Expected Event IDs
| Event | Log | Key Fields |
|-------|-----|-----------|
| 4698 | Security | `TaskName`, `TaskContent` (XML with action field), `SubjectUserName` |
| 4702 | Security | Task updated (if modified after creation) |
| Sysmon 1 | Sysmon | `Image: schtasks.exe`, `CommandLine: /create /tn...` |

## Detection SPL (Reference)
```spl
index=wineventlog sourcetype="WinEventLog:Security"
EventID=4698
| rex field=_raw "<Command>(?<task_command>[^<]+)</Command>"
| where like(task_command, "%powershell%") OR like(task_command, "%cmd%") OR like(task_command, "%wscript%")
| table _time, ComputerName, SubjectUserName, TaskName, task_command
```

## Defensive Takeaway
Monitor scheduled task creation in real time. The combination of creator account (non-SYSTEM, non-known-software) and task action (interpreter invocation pointing to temp/user-writable paths) is the strongest signal. Legitimate software creates tasks at install time — unexpected tasks created at odd hours by standard user accounts are nearly always worth investigating.
