# RB-001 — Phishing Email Triage Runbook

**Version:** 1.0  
**Owner:** SOC L1  
**Last Updated:** 2026-02-15  
**Applies To:** All suspected phishing alerts  

---

## Trigger Conditions

Initiate this runbook when ANY of the following occur:
- SIEM alert fires on suspicious email attachment execution
- User reports suspicious email
- EDR flags process spawned from email client
- Splunk detects Base64 encoded URL in process args

---

## Step 1 — Initial Triage (0–5 min)

| Action | Tool | Expected Result |
|---|---|---|
| Identify alert source | Splunk | Alert name, time, endpoint |
| Pull raw event | Splunk SPL | Full log with process, user, host |
| Check sender domain | Manual | Legit domain or lookalike? |
| Check attachment name | Splunk | .exe, .pdf, .zip extensions |
| Open Jira ticket | Jira | Assign SOC-00X, set Priority |

**SPL — Pull phishing alert evidence:**
```splunk
index=main EventCode=1
| search CommandLine="*.pdf.exe*" OR CommandLine="*base64*"
| table _time, Image, CommandLine, ParentImage, User, ComputerName
| sort -_time
```

---

## Step 2 — Investigate (5–10 min)

| Action | Tool | Look For |
|---|---|---|
| Check parent process | Splunk/Sysmon | Email client spawning cmd/powershell |
| Decode Base64 if present | CyberChef | Malicious URL or payload |
| Check destination URL | VirusTotal | Known malicious domain |
| Check file hash | VirusTotal | Known malware signature |
| Correlate with EDR | Defender logs | Quarantine action taken? |

**SPL — Parent-child process chain:**
```splunk
index=main EventCode=1
| rex field=_raw "ParentImage:\s+(?<ParentProcess>[^\r\n]+)"
| rex field=_raw "Image:\s+(?<ChildProcess>[^\r\n]+)"
| search ParentProcess="*outlook*" OR ParentProcess="*thunderbird*"
| table _time, ParentProcess, ChildProcess, CommandLine, User
```

---

## Step 3 — Classify (10–12 min)

| Verdict | Criteria |
|---|---|
| **TRUE POSITIVE** | Malicious attachment executed, C2 contact, or credential harvesting confirmed |
| **FALSE POSITIVE** | Legitimate software, known-good hash, no malicious behavior |
| **INCONCLUSIVE** | Suspicious but unconfirmed — escalate to L2 |

---

## Step 4 — Containment Actions (L1 Authorized)

- [x] Isolate endpoint if active compromise confirmed
- [x] Block malicious URL/domain at proxy if identified
- [x] Preserve logs and memory artifacts before any remediation
- [x] Update Jira ticket with findings and containment taken

---

## Step 5 — Escalate to L2 (12–15 min)

**Escalate if ANY of the following:**
- Confirmed malicious payload executed
- C2 beacon detected
- Credential harvesting observed
- Multiple endpoints affected

**L2 Handoff Package:**
```
Ticket ID:     SOC-00X
Time:          [detection time UTC]
Endpoint:      [hostname]
User:          [affected user]
IOCs:          [file hash, URL, domain, IP]
Timeline:      [step by step what happened]
Actions Taken: [containment steps completed]
Recommended:   [next steps for L2]
MITRE:         T1566.001, T1059.001, T1027
```

---

## Step 6 — Close or Monitor

| Outcome | Action |
|---|---|
| FP confirmed | Close Jira ticket with documented reasoning |
| TP contained | Hand off to L2, update ticket to Escalated |
| Inconclusive | Keep open, set 24hr follow-up reminder |

---

## False Positive Scenarios

| Scenario | How to Identify | Action |
|---|---|---|
| IT sending test phishing email | Check sender = internal IT domain | Close as FP, note in ticket |
| PDF opened normally, no execution | No child process spawned | Close as FP |
| Macro-enabled doc from trusted vendor | Hash matches known-good | Close as FP, whitelist |

---

## MITRE ATT&CK Coverage

| Technique | ID | Runbook Step |
|---|---|---|
| Spearphishing Attachment | T1566.001 | Step 1 |
| Malicious File Execution | T1204.002 | Step 2 |
| Command & Scripting Interpreter | T1059.001 | Step 2 |
| Obfuscated Files (Base64) | T1027 | Step 2 |
| Email Collection | T1114 | Step 3 |

---

## NIST SP 800-61 Phase Mapping

| Phase | Runbook Step |
|---|---|
| Detection & Analysis | Steps 1–3 |
| Containment | Step 4 |
| Escalation | Step 5 |
| Recovery/Closure | Step 6 |

---

## Related Resources

- [Lab 4 — Phishing Investigation](../labs/Lab4-Phishing-Investigation.md)
- [Splunk Detection Queries](../detection/splunk-queries.md)
- [Jira SOC Board](https://quickmart027.atlassian.net)
