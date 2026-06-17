# Sysmon Installation Guide

## Download
```
https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
```

## Install (Run as Administrator on WIN10-VICTIM and DC01)
```cmd
sysmon.exe -accepteula -i configs\sysmon\sysmonconfig.xml
```

## Verify Installation
```powershell
Get-Service Sysmon
# Status should be: Running

# Check events are generating
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## Update Config
```cmd
sysmon.exe -c configs\sysmon\sysmonconfig.xml
```

## Verify in Splunk
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count BY EventID
| sort EventID
```
Expected: Event IDs 1, 3, 7, 8, 10, 11, 12, 13, 22 all present.
