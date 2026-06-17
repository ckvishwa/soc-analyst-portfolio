# Splunk Dashboard Documentation — Enterprise SOC Detection Lab v2

## Overview

This document describes the Splunk dashboards built for the lab, including the SPL queries backing each panel.
Build these dashboards in Splunk using Dashboard Studio or the Classic Dashboard editor.

---

## Dashboard 1 — SOC Overview

**Purpose:** High-level summary of all detection activity across the lab environment.

### Panel 1 — Failed Logins (Last 24h)
```spl
index=wineventlog EventID=4625
| timechart count AS "Failed Logins" span=1h
```

### Panel 2 — PowerShell Activity (Last 24h)
```spl
index=endpoint EventID=1 Image="*\\powershell.exe"
| timechart count AS "PS Executions" span=1h
```

### Panel 3 — Top Suspicious Processes (Sysmon Event 1)
```spl
index=endpoint EventID=1
| top limit=10 Image
```

### Panel 4 — MITRE Technique Hit Count
```spl
index=endpoint OR index=wineventlog
| eval technique=case(
    EventID=4625, "T1110.001 Brute Force",
    (EventID=1 AND Image="*powershell*"), "T1059.001 PowerShell",
    EventID=4698, "T1053.005 Scheduled Task",
    EventID=10, "T1003.001 LSASS Access",
    1=1, "Other")
| stats count BY technique
| sort -count
```

---

## Dashboard 2 — Endpoint Telemetry

### Panel 1 — Process Creation Timeline
```spl
index=endpoint EventID=1
| timechart count BY ComputerName span=15m
```

### Panel 2 — Registry Modifications (Persistence Keys)
```spl
index=endpoint EventID=13 TargetObject="*\\CurrentVersion\\Run*"
| table _time, ComputerName, User, Image, TargetObject, Details
```

### Panel 3 — DNS Queries by Process
```spl
index=endpoint EventID=22
NOT Image IN ("*\\chrome.exe","*\\svchost.exe")
| stats count BY Image, QueryName
| sort -count
| head 20
```

---

## Dashboard 3 — Authentication Activity

### Panel 1 — Login Failures by Account
```spl
index=wineventlog EventID=4625
| stats count BY Account_Name
| sort -count
| head 10
```

### Panel 2 — Network Logons (Type 3)
```spl
index=wineventlog EventID=4624 Logon_Type=3
| stats count BY Account_Name, IpAddress
| sort -count
```

---

Screenshots: Save dashboard screenshots to `screenshots/dashboards/`
