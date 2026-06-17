# Investigation Report — [ALERT NAME]

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Alert Name** | [Alert name from detection rule] |
| **Detection ID** | [DET-00X] |
| **Report ID** | [IR-YYYY-NNN] |
| **Date / Time (UTC)** | [YYYY-MM-DD HH:MM:SS UTC] |
| **Analyst** | [Your Name] |
| **Analyst Tier** | [SOC L1 / L2 / Detection Analyst] |
| **Severity** | [Critical / High / Medium / Low] |
| **Affected Host** | [Hostname (IP)] |
| **Affected User** | [DOMAIN\username] |
| **Domain** | [Domain name] |
| **Ticket/Case ID** | [INC-YYYY-NNNN] |
| **Status** | [Open / In Progress / Closed] |

---

## Executive Summary

[2-3 sentences: What fired, what was found, what decision was made. Written for a non-technical reader.]

---

## Initial Detection Query

```spl
[Paste the SPL query that generated this alert]
```

**Alert fired at:** [timestamp]
**Events returned:** [count]
**Alert severity:** [severity]

---

## Timeline of Events

| Time (UTC) | Event ID | Host | User | Description |
|-----------|---------|------|------|-------------|
| [time] | [event id] | [host] | [user] | [what happened] |
| [time] | [event id] | [host] | [user] | [what happened] |

---

## Key Artifacts

### Artifact 1 — [Name]
```
[Raw artifact: command line, registry value, file path, IP, etc.]
```
**Analysis:** [What this artifact means]

### Artifact 2 — [Name]
```
[Raw artifact]
```
**Analysis:** [What this artifact means]

---

## Process Tree

```
[Parent process]
  └─► [Child process] ← ALERT
        └─► [Follow-on activity]
```

---

## Network Indicators

| Indicator Type | Value | Context |
|---------------|-------|---------|
| [IP/Domain/Port] | [value] | [what it is] |

**Threat Intel Check:** [Results from VT, Shodan, or internal TI]

---

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | [Tactic] |
| **Technique ID** | [T1XXX.XXX] |
| **Technique Name** | [Technique Name] |
| **Observed Behaviors** | [Specific behaviors that map to this technique] |

---

## Analyst Findings

**What was observed:** [Factual description of what happened]

**What was confirmed:** [What you verified vs. what you inferred]

**What this would look like in a real attack:** [Context for severity assessment]

---

## False Positive Assessment

| Assessment | Decision |
|-----------|---------|
| **False Positive?** | [Yes / No / Inconclusive] |
| **True Positive?** | [Yes / No / Inconclusive] |
| **Reasoning** | [Why you made this call] |

---

## Recommended Remediation

| Priority | Action |
|---------|--------|
| Immediate | [action] |
| Short-term | [action] |
| Recovery | [action] |

---

## Detection Tuning Observations

[Did the detection perform correctly? Any adjustments needed?]

---

## Lessons Learned

1. [What you learned from this investigation]
2. [What you would do differently]

---

## Screenshots

> Store in `screenshots/` directory

- [ ] [Screenshot 1 description]
- [ ] [Screenshot 2 description]

---

## Report Sign-off

| Field | Value |
|-------|-------|
| **Analyst** | [Name] |
| **Review Date** | [Date] |
| **Disposition** | [True Positive / False Positive / Inconclusive] |
| **Escalation Required** | [Yes / No] |
| **Ticket Closed** | [Yes / No] |
