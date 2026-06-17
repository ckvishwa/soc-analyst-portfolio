# Lab Network Diagram

## Network: 192.168.10.0/24 (Isolated Lab VLAN)

```
Internet
    │ (blocked for Kali; allowed for others during setup only)
    │
┌───┴─────────────────────────────────────────────────────────────┐
│                    Lab Network: 192.168.10.0/24                  │
│                                                                   │
│  ┌────────────────────┐      ┌────────────────────┐             │
│  │  DC01              │      │  WIN10-VICTIM       │             │
│  │  Windows Server    │◄────►│  Windows 10 Ent.    │             │
│  │  2022              │      │  21H2               │             │
│  │  192.168.10.10     │      │  192.168.10.20      │             │
│  │  Roles: AD DS, DNS │      │  Sysmon v15         │             │
│  │  Sysmon v15        │      │  Splunk UF          │             │
│  │  Splunk UF         │      └────────┬───────────┘             │
│  └────────┬───────────┘               │                          │
│           │          ┌────────────────┘                          │
│           └──────────┼──────────────────────┐                   │
│                      ▼                       │                   │
│           ┌────────────────────┐             │                   │
│           │  SPLUNK            │             │                   │
│           │  Splunk Enterprise │◄────────────┘                   │
│           │  192.168.10.30     │  (log collection)               │
│           │  9997 (HEC/fwd)    │                                 │
│           │  8000 (Web UI)     │                                 │
│           └────────────────────┘                                 │
│                                                                   │
│  ┌────────────────────┐                                          │
│  │  KALI-ATTACKER     │  ← Isolated: can reach lab VMs          │
│  │  Kali Linux 2024   │    but NOT the internet                  │
│  │  192.168.10.50     │                                          │
│  └────────────────────┘                                          │
└───────────────────────────────────────────────────────────────────┘

Log Flow:
  WIN10-VICTIM → Splunk UF → SPLUNK:9997 (index=endpoint, index=wineventlog)
  DC01         → Splunk UF → SPLUNK:9997 (index=wineventlog)
```

## Port Reference

| Port | Protocol | Service | Direction |
|------|---------|---------|---------|
| 9997 | TCP | Splunk forwarding | UF → Splunk server |
| 8000 | TCP | Splunk Web UI | Analyst browser → Splunk |
| 445 | TCP | SMB | Attacker → Victim (lateral movement simulation) |
| 3389 | TCP | RDP | Admin access to lab VMs |
| 389 | TCP | LDAP | Domain authentication |
| 53 | UDP | DNS | All VMs → DC01 |
