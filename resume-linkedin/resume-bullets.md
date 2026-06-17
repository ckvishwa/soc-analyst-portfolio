# Resume Bullets & LinkedIn Summary

**Project:** Enterprise SOC Detection Lab v2  
**Target Roles:** SOC Analyst L1, Junior Detection Engineer, Security Analyst

---

## Resume Bullets

---

### Version 1 — Short (1 line, ATS-safe)

> Built an enterprise SOC detection lab using Splunk, Sysmon, and MITRE ATT&CK to simulate, detect, and investigate 8 post-exploitation techniques across a Windows AD environment.

**Use when:** Space is limited (1-page resume), applying to generalist SOC roles, or listing in a Projects section with no room for detail.

---

### Version 2 — Medium (2 lines, detail-balanced)

> Designed and built an enterprise-style SOC detection lab in a virtualized Active Directory environment. Used Splunk Enterprise, Sysmon v15, and Windows Event Logs to simulate 8 MITRE ATT&CK-mapped attack techniques, write custom SPL detection rules, and produce structured investigation reports for each alert.

**Use when:** Applying to SOC Analyst L1 roles, mid-section of resume under Projects, or when the recruiter is technical.

---

### Version 3 — Strong Technical (3-4 lines, maximum signal)

> Built a multi-VM SOC detection lab (Windows Server 2022 DC, Windows 10 endpoint, Kali Linux attacker) to practice the full detection engineering lifecycle end-to-end. Deployed Splunk Enterprise with Sysmon v15 telemetry and Windows Event Forwarding to collect process creation, registry, network, and authentication logs. Simulated 8 MITRE ATT&CK techniques spanning Execution, Persistence, Credential Access, Lateral Movement, and C2 — including PowerShell encoded commands, LSASS access indicators, brute force login, registry Run key persistence, SMB lateral movement, and DNS/HTTP beaconing. Authored 8 custom SPL detection rules mapped to ATT&CK technique IDs, produced structured investigation reports with process trees and IOC documentation, and documented false positive tuning recommendations aligned with SOC analyst operational workflows.

**Use when:** Applying to Detection Analyst, Threat Detection Engineer, or technical SOC roles where the hiring manager is a practitioner. LinkedIn project section. Portfolio description.

---

### Version 3B — Strong Technical with Metrics Framing

> Engineered an enterprise-style SOC detection lab across a 3-VM Windows AD environment, deploying Splunk Enterprise, Sysmon v15, and Windows Event Forwarding as the telemetry stack. Simulated 8 post-exploitation techniques mapped to MITRE ATT&CK v14 (T1059.001, T1110.001, T1003.001, T1053.005, T1547.001, T1055, T1021.002, T1071.001/004), authored corresponding SPL detection rules, and produced full investigation reports per alert — including process trees, network IOCs, MITRE mappings, and false positive analysis. GitHub repository includes complete detection index, investigation report templates, Splunk dashboard documentation, and tuning recommendations.

**Use when:** Applying to positions that specifically mention detection engineering, threat detection, or Splunk/SIEM experience in the job description.

---

## Interview Talking Points

Use these when asked: *"Tell me about a project you built."*

---

### Opening Statement
"I built an enterprise-style SOC detection lab from scratch — a three-VM environment with a Windows Active Directory domain controller, a Windows 10 victim endpoint running Sysmon, and a Kali Linux attacker machine. I used Splunk Enterprise as the SIEM and built the whole thing to practice the detection engineering workflow end-to-end."

---

### What You Built (Depth Signals)
"I simulated 8 different attack techniques — everything from PowerShell encoded command execution to brute force logins, credential dumping indicators, scheduled task persistence, registry run key persistence, process injection indicators, lateral movement over SMB, and DNS/HTTP beaconing. For each one, I generated the actual telemetry in the lab, wrote a custom SPL detection rule to catch it, and then wrote an investigation report documenting what I found — exactly like I'd write one in a real SOC."

---

### What You Learned (Maturity Signals)
"The most valuable thing I learned was around false positives. My first version of the PowerShell detection was firing constantly because IT automation scripts use the exact same flags as attackers — bypass flags, encoded commands, hidden windows. The difference is context: parent process, user account, time of day, whether it made a network connection after. Tuning that down to high-fidelity required building exclusions based on real baseline analysis, not just adding `NOT` statements blindly."

---

### How It Connects to the Role (Signal to Interviewer)
"The goal was to build proof that I can actually do the work — not just say I understand Splunk or MITRE ATT&CK, but show a GitHub repo with real queries, real telemetry, and real investigation methodology. The detection engineering workflow I built here — simulate, detect, investigate, tune, document — is the same workflow a SOC uses on real alerts every day."

---

## LinkedIn Project Summary Post

---

### Post Version 1 — Announcement (Launch)

**Just published my Enterprise SOC Detection Lab v2 to GitHub.**

Here's what I built and why:

**The environment:**
3 VMs — Windows Server 2022 domain controller, Windows 10 endpoint with Sysmon, Kali Linux attacker. Splunk Enterprise as the SIEM with Windows Event Forwarding collecting logs from across the domain.

**What I simulated (lab-only, all safe):**
- PowerShell encoded command execution
- Brute force login attacks against AD
- LSASS access simulation (credential dumping indicator)
- Scheduled task and registry Run key persistence
- Process injection indicators
- Lateral movement via SMB admin shares
- DNS/HTTP beacon-like traffic

**What I built for each simulation:**
- A custom SPL detection rule mapped to MITRE ATT&CK
- A structured investigation report (analyst POV — timeline, artifacts, process tree, IOCs)
- False positive documentation and tuning recommendations

**What I learned:**
Detection engineering is mostly about tuning, not writing the initial rule. The first version of every detection I wrote was too noisy. Getting to high-fidelity required understanding the baseline first.

The full repository — SPL queries, investigation report templates, detection index, MITRE mapping table, and Splunk dashboard documentation — is on my GitHub.

Link in comments.

#Cybersecurity #SOC #DetectionEngineering #Splunk #MITREATTACK #Sysmon #BlueTeam #SecurityAnalyst #OpenToWork

---

### Post Version 2 — Insight Post (Engagement-Focused)

**The hardest part of SOC detection engineering isn't writing the query. It's killing your own detections.**

I just finished an enterprise SOC lab project and the lesson that hit hardest was this:

Every detection I wrote fired on legitimate activity first.

My PowerShell suspicious execution rule? Fired on IT automation scripts using the exact same bypass flags as a real attacker.

My brute force detection? Fired on service accounts with expired passwords.

My scheduled task persistence rule? Fired on Windows Update.

Good detection engineering means you have to understand the environment well enough to know what's noise before you can define what's signal.

My process for this project:
1. Simulate the attack technique (safe, lab-only)
2. Write the initial detection in Splunk
3. Run it in search mode for 24-48 hours
4. Document every false positive hit
5. Build targeted exclusions based on actual observed behavior
6. Re-validate that the real threat still fires

The result: 8 detection rules, all validated against real lab telemetry, all with documented FP analysis and tuning recommendations.

Repo is on my GitHub if you want to see the SPL queries, investigation reports, or MITRE ATT&CK mapping.

#SOC #DetectionEngineering #Splunk #CyberSecurity #BlueTeam #SIEM #MITREATTCKFramework

---

### Post Version 3 — Short Proof Post (Mobile-Friendly)

**Published: Enterprise SOC Detection Lab v2**

What's in it:
→ 8 MITRE ATT&CK-mapped attack simulations
→ 8 custom Splunk SPL detection rules
→ 6 structured investigation reports
→ Full false positive analysis and tuning notes
→ Windows AD + Sysmon + Splunk setup documentation

Stack: Splunk Enterprise, Sysmon v15, Windows Server 2022, Windows 10, Kali Linux, Atomic Red Team

Built to practice the full detection engineering lifecycle — not just theory, but telemetry, detection, investigation, and documentation.

GitHub link in comments.

#Cybersecurity #SOC #Splunk #BlueTeam #MITRE #DetectionEngineering

---

## Profile / About Section Addition

> Consider adding this to your LinkedIn About section or Featured section:

**Projects — Enterprise SOC Detection Lab v2**
Built a multi-VM SOC lab environment to practice detection engineering from the ground up. Environment includes Windows Active Directory, Sysmon endpoint telemetry, Splunk Enterprise SIEM, and a Kali Linux attacker machine. The lab covers 8 MITRE ATT&CK-mapped attack simulations with corresponding custom SPL detection rules, structured investigation reports, and false positive analysis. Full repository available on GitHub.

---

## GitHub Repository Description (for repo `About` field)

```
Enterprise SOC detection lab: Windows AD + Sysmon + Splunk + MITRE ATT&CK.
8 attack simulations, custom SPL detections, investigation reports, and FP analysis.
Built for SOC Analyst and Detection Engineer portfolio demonstration.
```

**Topics to add to GitHub repo:**
`splunk` `sysmon` `mitre-attack` `detection-engineering` `soc` `blue-team` `windows-security` `active-directory` `siem` `incident-response` `cybersecurity` `threat-detection`
