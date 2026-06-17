# Attack Simulation 05 — Registry Run Key Persistence

**Simulation ID:** SIM-005 | **MITRE:** T1547.001 | **Tactic:** Persistence | **Severity:** High

## Objective
Write a benign value to a Windows Registry Run key to generate Sysmon Event ID 13 (RegistryValueSet) telemetry matching the registry run key persistence detection rule.

## MITRE ATT&CK Technique
- **Technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
- **Reference:** https://attack.mitre.org/techniques/T1547/001/

## Lab-Only Simulation Method

### Simulation Commands (Run on WIN10-VICTIM)
```cmd
REM HKCU Run key — user-level persistence (no admin required)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SimPersist01" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

**What this does:** Adds a registry value named "SimPersist01" pointing to calc.exe — a completely benign executable — under the standard Run key. On next login, Windows would launch calc.exe (harmless). This generates Sysmon Event 13 with the exact key path, value name, and data that the detection rule monitors.

### Also Test HKLM (Requires Admin)
```cmd
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SimPersist02" /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f
```

### Cleanup After Testing
```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SimPersist01" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SimPersist02" /f
```

## Expected Event IDs
| Event | Log | Key Fields |
|-------|-----|-----------|
| Sysmon 13 | Sysmon | `TargetObject: HKCU\...\Run\SimPersist01`, `Details: C:\Windows\System32\calc.exe`, `Image: reg.exe` |
| Sysmon 1 | Sysmon | `Image: reg.exe`, `CommandLine: reg add HKCU\...` |

## Detection SPL (Reference)
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
TargetObject IN (
    "*\\CurrentVersion\\Run\\*",
    "*\\CurrentVersion\\RunOnce\\*",
    "*\\CurrentVersion\\RunOnceEx\\*"
)
NOT Image IN ("*\\msiexec.exe","*\\setup.exe","*\\install.exe")
| table _time, ComputerName, User, Image, TargetObject, Details
```

## Defensive Takeaway
Run key modifications are one of the oldest and most reliable persistence mechanisms. Despite their age, they remain effective because so many legitimate applications use them that defenders often cannot allowlist effectively. The path written in the `Details` field is the most important signal — legitimate software writes known installation paths, while attackers write temp directory paths, AppData paths, or encoded command strings.
