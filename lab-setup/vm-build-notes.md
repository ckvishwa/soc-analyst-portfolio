# VM Build Notes — Enterprise SOC Detection Lab v2

## Overview

This lab uses 4 virtual machines on a single hypervisor (VMware Workstation, VirtualBox, or Proxmox).

## Hypervisor Requirements

| Spec | Minimum | Recommended |
|------|---------|-------------|
| RAM | 16 GB | 32 GB |
| CPU | 4 cores | 8 cores |
| Storage | 200 GB | 500 GB |
| Hypervisor | VMware Workstation Pro / VirtualBox / Proxmox | VMware Workstation Pro |

## VM Specifications

| VM | OS | RAM | Storage | IP |
|----|-----|-----|---------|-----|
| DC01 | Windows Server 2022 Eval | 4 GB | 60 GB | 192.168.10.10 |
| WIN10-VICTIM | Windows 10 Enterprise Eval | 4 GB | 60 GB | 192.168.10.20 |
| SPLUNK | Windows Server or Ubuntu 22.04 | 6 GB | 100 GB | 192.168.10.30 |
| KALI-ATTACKER | Kali Linux 2024.x | 2 GB | 40 GB | 192.168.10.50 |

## Network Configuration

Create an isolated host-only network: `192.168.10.0/24`
- No NAT to internet for attacker VM (KALI)
- Internet access allowed for DC, WIN10, SPLUNK (for downloads during setup only)
- After setup: isolate lab network from internet for simulations

## Build Order

1. Build DC01 first — install AD DS, configure DNS, set static IP
2. Build WIN10-VICTIM — join to SOCLAB.LOCAL domain
3. Build SPLUNK — install Splunk Enterprise, configure indexes
4. Build KALI-ATTACKER — configure lab network only, no internet
5. Install Sysmon on DC01 and WIN10-VICTIM
6. Install Splunk Universal Forwarder on DC01 and WIN10-VICTIM
7. Validate log flow: Event IDs visible in Splunk from both endpoints

## Download Links (Official Only)

- Windows Server 2022 Eval: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022
- Windows 10 Enterprise Eval: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise
- Splunk Enterprise Free: https://www.splunk.com/en_us/download/splunk-enterprise.html
- Sysmon: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- Kali Linux: https://www.kali.org/get-kali/
