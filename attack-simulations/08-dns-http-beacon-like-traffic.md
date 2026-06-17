# Attack Simulation 08 — DNS/HTTP Beacon-like Traffic

**Simulation ID:** SIM-008 | **MITRE:** T1071.001, T1071.004 | **Tactic:** C2 | **Severity:** Medium

## Objective
Simulate beacon-like network behavior by generating periodic DNS queries and HTTP connections from a non-browser process at regular intervals. Produces Sysmon Event ID 22 (DNS) and Event ID 3 (Network Connection) telemetry.

## MITRE ATT&CK Techniques
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **Reference:** https://attack.mitre.org/techniques/T1071/001/

## Lab-Only Simulation Method

### DNS Beacon Simulation (PowerShell loop — safe)
```powershell
# Run on WIN10-VICTIM — makes DNS queries at 30-second intervals to lab DNS name
# Safe: lab-internal DNS name, no external connection
for ($i = 1; $i -le 20; $i++) {
    Resolve-DnsName "labtest.soclab.local" -ErrorAction SilentlyContinue
    Write-Host "DNS query $i of 20 — $(Get-Date)"
    Start-Sleep -Seconds 30
}
```
This generates 20 Sysmon Event 22 entries from PowerShell at 30-second intervals — matching beacon behavior.

### HTTP Beacon Simulation (PowerShell WebClient — safe)
```powershell
# Run on WIN10-VICTIM — periodic HTTP GET to internal lab web server
# No external connections — lab server at 192.168.10.99 only
$wc = New-Object Net.WebClient
for ($i = 1; $i -le 10; $i++) {
    try {
        $response = $wc.DownloadString("http://192.168.10.99/beacon-sim.txt")
        Write-Host "Beacon check-in $i — $(Get-Date)"
    } catch { Write-Host "Request $i failed" }
    Start-Sleep -Seconds 60
}
```
This generates 10 Sysmon Event 3 entries from PowerShell at 60-second intervals to the same destination — matching HTTP beacon behavior.

## Expected Event IDs
| Event | Log | Key Fields |
|-------|-----|-----------|
| Sysmon 22 | Sysmon | `Image: powershell.exe`, `QueryName: labtest.soclab.local`, count over time |
| Sysmon 3 | Sysmon | `Image: powershell.exe`, `DestinationIp: 192.168.10.99`, `DestinationPort: 80`, count over time |

## Detection SPL (Reference)
```spl
| Detection: Beacon-like Periodic Connections |
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=3
NOT Image IN ("*\\chrome.exe","*\\firefox.exe","*\\msedge.exe","*\\OneDrive.exe")
| bucket _time span=1h
| stats count AS connection_count, 
        dc(DestinationIp) AS unique_dests,
        values(DestinationPort) AS ports
  BY _time, Image, DestinationIp, ComputerName
| where connection_count >= 5 AND unique_dests == 1
| eval detection="Possible Beacon — Periodic Single-Dest Connections"
| sort -connection_count
```

## Defensive Takeaway
Beacon detection is fundamentally a statistical problem. Signatures and blacklists fail because C2 domains rotate constantly. The durable detection approach is behavioral: any non-browser process making connections to the same destination at regular intervals should be flagged. Add DNS monitoring (Event 22) alongside network connections (Event 3) to catch C2 that uses DNS as its transport layer — which completely bypasses HTTP-focused detection.
