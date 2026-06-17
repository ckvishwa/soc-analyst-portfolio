# Investigation Report — Brute Force Detection

**Report ID:** IR-2024-00X | **Status:** ✅ Lab Simulation — True Positive

> Complete this report by running the corresponding attack simulation and filling in the fields using actual Splunk telemetry from your lab.
> Template: See `investigation-reports/template-investigation-report.md`

## Report Metadata

| Field | Value |
|-------|-------|
| **Alert Name** | [Fill from detection that fired] |
| **Detection ID** | [DET-00X] |
| **Report ID** | IR-2024-00X |
| **Date / Time (UTC)** | [Fill when you run the simulation] |
| **Analyst** | [Your Name] |
| **Severity** | [Fill based on detection] |
| **Affected Host** | WIN10-VICTIM (192.168.10.20) |
| **Affected User** | SOCLAB\testuser |
| **Status** | [Open — fill in when running simulation] |

## Initial Detection Query

```spl
[Paste query from the corresponding .spl file in detections/]
```

## Timeline of Events

| Time (UTC) | Event ID | Host | User | Description |
|-----------|---------|------|------|-------------|
| [Fill from Splunk] | | WIN10-VICTIM | | |

## Key Artifacts

[Fill from Splunk event data when running simulation]

## Process Tree

[Fill from Sysmon Event ID 1 parent-child chain in Splunk]

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | [See mitre-attack-mapping/mitre-mapping-table.md] |
| **Technique ID** | [T1XXX.XXX] |

## Analyst Findings

[Fill after running simulation and reviewing telemetry in Splunk]

## False Positive Assessment

**Decision:** True Positive (Lab Simulation Confirmed)
**Reasoning:** [Fill with your analysis]

## Lessons Learned

[Fill after completing the investigation]

## Screenshots

- [ ] Splunk search showing the alert event
- [ ] Splunk timeline of related events
- [ ] Key artifact detail view
