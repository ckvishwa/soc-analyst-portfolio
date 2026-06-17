# Lab 5: RDP Workflow and Explicit Credential Use Detection

**Date:** 2026-02-12
**Analyst:** Vishva Teja Chikoti
**Environment:** Windows 10 VM | Windows Security Logs | Sysmon | Splunk 10.2.0
**Difficulty:** Intermediate
**Alert Priority:** MEDIUM

---

## Objective

Simulate a localhost RDP workflow involving Windows Credential Manager and analyze the resulting authentication telemetry in Splunk.

This lab focuses on:

* Windows Event ID 4648 explicit credential use
* Successful and failed authentication events
* Logon Type analysis
* Process and target-server correlation
* Distinguishing localhost testing from real lateral movement
* Determining whether RDP and valid-account use were actually confirmed

> **Scope limitation:** The target was `127.0.0.1`, representing the same host. This lab does not demonstrate movement between separate systems.

---

## Data Sources and Splunk Indexes

| Data Source            | Splunk Index                | Purpose                                                |
| ---------------------- | --------------------------- | ------------------------------------------------------ |
| Windows Security Log   | `wineventlog`               | Event IDs 4624, 4625, 4648, and 4672                   |
| Sysmon Operational Log | `endpoint`                  | `mstsc.exe` process creation and process-tree analysis |
| RDP operational logs   | `wineventlog` when ingested | Additional RDP session validation                      |

The primary searches in this lab use:

```spl
index=wineventlog
source="WinEventLog:Security"
```

---

## NIST SP 800-61 Alignment

This lab demonstrates event detection, authentication analysis, evidence correlation, prioritization, scope determination, and response decision-making.

**Observed:** Event ID 4648 recorded explicit credential use, and successful local interactive logon events were present in the same investigation window.

**Assessed:** The activity occurred during a controlled workflow involving Credential Manager enumeration and invocation of the Windows RDP client.

**Not confirmed:** The available evidence does not independently prove that a listed stored credential was used, that an RDP session successfully authenticated, or that lateral movement occurred.

---

## Lab Setup

| Component              | Detail                           |
| ---------------------- | -------------------------------- |
| Environment            | Windows 10 VM                    |
| Security telemetry     | Windows Security Event Logs      |
| Endpoint telemetry     | Sysmon Event ID 1                |
| Tools                  | Splunk 10.2.0, `cmdkey`, `mstsc` |
| Key Security Event IDs | 4624, 4625, 4648, 4672           |
| RDP destination        | `127.0.0.1`                      |
| Scope                  | Single endpoint                  |

---

## Analyst Narrative

During authentication-log review, I identified two Event ID 4624 records with Logon Type 2 and one Event ID 4648 record at approximately the same timestamp.

The activity occurred during a controlled test in which:

1. Stored credential targets were enumerated with `cmdkey /list`.
2. RDP was enabled on the local test system.
3. The RDP client was launched with `mstsc /v:127.0.0.1`.

The events provide evidence of explicit credential use and local interactive authentication. However, the available data does not show a successful Logon Type 10 event, which would be stronger evidence of a remote-interactive RDP logon.

### Confidence Statement

**Observed:**

* `cmdkey /list` was run.
* `mstsc.exe` was invoked against `127.0.0.1`.
* Event ID 4648 recorded explicit credential use.
* Event ID 4624 Logon Type 2 events were present.
* The activity remained on one endpoint.

**Assessed:**

* The authentication events are temporally associated with the controlled test.
* Event ID 4648 indicates that a process attempted authentication using explicitly supplied credentials.
* The process, account, and target fields must be reviewed to determine the exact authentication context.

**Not confirmed:**

* The credential displayed by `cmdkey /list` was the credential used.
* A successful RDP Logon Type 10 session occurred.
* The credential was stolen or abused.
* Pass-the-Hash occurred.
* Lateral movement occurred.
* The activity was malicious.

---

## Attack Simulation

```cmd
:: Enumerate stored credential targets and usernames
cmdkey /list

:: Enable Remote Desktop in the isolated lab
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

:: Launch the RDP client against the same host
mstsc /v:127.0.0.1
```

### Credential Manager Scope

`cmdkey /list` may reveal:

* Stored credential targets
* Credential types
* Associated usernames

It does not display the stored password in plaintext.

Enumeration of a stored target does not prove that the credential was subsequently used. That conclusion requires correlation with:

* Event ID 4648 target account
* Event ID 4648 process name
* Event ID 4648 target server
* Event ID 4624 target account
* Logon Type
* Timestamp
* RDP client process telemetry

---

## Detection Queries

### Query 1 — Explicit Credential Use

```spl
index=wineventlog
source="WinEventLog:Security"
EventCode=4648
| rex field=_raw "(?s)Account Whose Credentials Were Used:.*?Account Name:\s+(?<TargetUser>[^\r\n]+)"
| rex field=_raw "(?s)Account Whose Credentials Were Used:.*?Account Domain:\s+(?<TargetDomain>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Target Server Name:\s+(?<TargetServer>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Process ID:\s+(?<ProcessId>0x[0-9A-Fa-f]+)"
| rex field=_raw "(?m)^\s*Process Name:\s+(?<ProcessName>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Network Address:\s+(?<SourceIP>[^\r\n]+)"
| table _time host TargetDomain TargetUser TargetServer ProcessId ProcessName SourceIP
| sort -_time
```

The account extraction is anchored to **Account Whose Credentials Were Used**. This prevents accidentally extracting the subject account that generated the event.

---

### Query 2 — Successful Logon Analysis

```spl
index=wineventlog
source="WinEventLog:Security"
EventCode=4624
| rex field=_raw "(?s)New Logon:.*?Account Name:\s+(?<TargetUser>[^\r\n]+)"
| rex field=_raw "(?s)New Logon:.*?Account Domain:\s+(?<TargetDomain>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "(?m)^\s*Workstation Name:\s+(?<WorkstationName>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Source Network Address:\s+(?<SourceIP>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Process Name:\s+(?<ProcessName>[^\r\n]+)"
| table _time host TargetDomain TargetUser LogonType SourceIP WorkstationName ProcessName
| sort -_time
```

---

### Query 3 — RDP Logon Type 10

```spl
index=wineventlog
source="WinEventLog:Security"
EventCode=4624
| rex field=_raw "(?s)New Logon:.*?Account Name:\s+(?<TargetUser>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "(?m)^\s*Source Network Address:\s+(?<SourceIP>[^\r\n]+)"
| where LogonType=10
| table _time host TargetUser SourceIP LogonType
| sort -_time
```

A Logon Type 10 event would provide stronger evidence of a RemoteInteractive logon.

Its absence does not necessarily prove that no RDP activity occurred if:

* Auditing was incomplete
* The event was not forwarded
* The search window was incorrect
* The session did not complete
* The connection failed before authentication

---

### Query 4 — Correlate 4648 With Logon Events

```spl
index=wineventlog
source="WinEventLog:Security"
(EventCode=4624 OR EventCode=4625 OR EventCode=4648)
| rex field=_raw "(?s)Account Whose Credentials Were Used:.*?Account Name:\s+(?<ExplicitTargetUser>[^\r\n]+)"
| rex field=_raw "(?s)New Logon:.*?Account Name:\s+(?<SuccessfulTargetUser>[^\r\n]+)"
| rex field=_raw "(?s)Account For Which Logon Failed:.*?Account Name:\s+(?<FailedTargetUser>[^\r\n]+)"
| eval TargetUser=coalesce(ExplicitTargetUser, SuccessfulTargetUser, FailedTargetUser)
| rex field=_raw "(?m)^\s*Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "(?m)^\s*Target Server Name:\s+(?<TargetServer>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Process Name:\s+(?<ProcessName>[^\r\n]+)"
| rex field=_raw "(?m)^\s*Source Network Address:\s+(?<SourceIP>[^\r\n]+)"
| table _time host EventCode TargetUser TargetServer ProcessName LogonType SourceIP
| sort _time
```

This query produces a timeline for analyst review. It does not automatically prove that the events belong to the same authentication transaction.

---

### Query 5 — Sysmon RDP Client Process

Sysmon telemetry is stored in `index=endpoint`.

```spl
index=endpoint
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(Image="*\\mstsc.exe" OR CommandLine="*mstsc*")
| table _time host User Image ParentImage CommandLine ProcessId ProcessGuid IntegrityLevel
| sort -_time
```

This confirms that the RDP client was launched. It does not independently prove that an RDP session authenticated successfully.

---

## Findings

**Total authentication events reviewed:** 81
**Investigation timeframe:** 04:16:43–07:06:33 AM
**Events selected for detailed review:** 3

| Time     | Event ID | Logon Type | Evidence                           | Analyst Interpretation                    |
| -------- | -------- | ---------- | ---------------------------------- | ----------------------------------------- |
| 04:16:55 | 4624     | 2          | Successful local interactive logon | Local authentication occurred             |
| 04:16:55 | 4624     | 2          | Additional successful logon event  | Requires Logon ID and account correlation |
| 04:16:55 | 4648     | N/A        | Explicit credential-use event      | Review process, account, and target       |

### Evidence Limitations

* The current findings show Logon Type 2, not Logon Type 10.
* The report does not currently show the Event ID 4648 process name.
* The report does not currently show the Event ID 4648 target server.
* The target account is not shown in the findings table.
* The report does not correlate Logon IDs or Logon GUIDs.
* The evidence does not prove that the credential enumerated through `cmdkey` was used.

---

## Analyst Verdict

**Confirmed:**

* Event ID 4648 recorded explicit credential use.
* Successful local interactive authentication events occurred.
* The activity remained on one endpoint.
* The RDP client was invoked during the controlled simulation if supported by Sysmon process evidence.

**Medium confidence:**

* The Event ID 4648 activity was associated with the controlled authentication workflow.

**Not confirmed:**

* Successful RDP authentication
* Logon Type 10 activity
* Stored-credential abuse
* Credential theft
* Pass-the-Hash
* Malicious activity
* Lateral movement

### Alert Priority

**MEDIUM**

Raise the priority to **HIGH** when explicit credential use is associated with:

* A remote target
* Logon Type 10
* An unusual or unsigned initiating process
* A privileged account
* An unexpected source system
* Post-authentication discovery or execution
* Multiple destination systems
* No valid administrative explanation

---

## Event Reference

| Event / Logon Type | Meaning                                            | Analyst Use                                                          |
| ------------------ | -------------------------------------------------- | -------------------------------------------------------------------- |
| Event ID 4624      | Successful logon                                   | Identify account, logon type, source, and Logon ID                   |
| Event ID 4625      | Failed logon                                       | Review failures preceding or following explicit credential use       |
| Event ID 4648      | Authentication attempted with explicit credentials | Identify target account, target server, process, and source          |
| Event ID 4672      | Special privileges assigned                        | Determine whether the authenticated session received elevated rights |
| Logon Type 2       | Interactive                                        | Local interactive authentication                                     |
| Logon Type 5       | Service                                            | Service authentication; baseline by host and account                 |
| Logon Type 10      | RemoteInteractive                                  | Commonly associated with RDP authentication                          |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique                                | Evidence                                  | Status                                             |
| ------------ | ---------------------------------------- | ----------------------------------------- | -------------------------------------------------- |
| T1021.001    | Remote Services: Remote Desktop Protocol | `mstsc.exe` invoked against localhost     | Partial simulation only; no remote-system movement |
| T1078        | Valid Accounts                           | Successful authentication events occurred | Adversary abuse not confirmed                      |

### Excluded Mappings

* **T1550.002 — Pass the Hash:** No NTLM hash was used.
* **T1552.001 — Credentials in Files:** Windows Credential Manager is not demonstrated as a plaintext credential file.
* **T1076 — RDP Hijacking:** Deprecated and not demonstrated.
* **Lateral Movement:** No host-to-host movement occurred.

### Portfolio Coverage Rule

Do not count T1021.001 or T1078 as fully validated adversary techniques from this lab alone.

Count them only after evidence confirms:

* A successful RDP connection to another host
* A known source and destination
* A specific authenticated account
* A Logon Type 10 or supporting RDP operational event
* Unauthorized or adversary-like use of the account

---

## Alert Logic

```text
IF Event ID 4648 occurs
THEN identify:
- Subject account
- Target account
- Target server
- Initiating process
- Source address
- Nearby successful and failed logons

IF Event ID 4648 is followed by Event ID 4624 Logon Type 10
for the same target account and remote destination
within a short time window
THEN HIGH: Explicit Credentials Preceding RDP Authentication

IF the destination is localhost
THEN classify as local authentication activity
and do not label it lateral movement

DO NOT classify Event ID 4648 alone as malicious
```

---

## False Positives and Tuning

| Legitimate Scenario                     | Validation Approach                                                   |
| --------------------------------------- | --------------------------------------------------------------------- |
| Administrator using `runas`             | Validate approved account, process, host, and change ticket           |
| Scheduled task using stored credentials | Confirm task name, account, host, and execution schedule              |
| Service authentication                  | Baseline expected source, destination, and service account            |
| RDP with saved credentials              | Validate account owner, destination, and normal behavior              |
| Remote-management tool                  | Validate signer, management server, process path, and approved window |
| Backup or deployment software           | Confirm service account, process, target, and expected schedule       |

Avoid globally allowlisting:

* All Event ID 4648 events
* Entire administrator accounts
* Entire service accounts
* Every event from `mstsc.exe`

Tune narrowly using:

* Process
* Account
* Source
* Destination
* Host role
* Logon type
* Logon ID or GUID
* Time window
* Change ticket

---

## Recommended Analyst Actions

1. Review the Event ID 4648 target account.
2. Review the Event ID 4648 process name.
3. Review the Event ID 4648 target server.
4. Correlate Event IDs 4624, 4625, and 4648 by time and account.
5. Correlate Logon IDs and Logon GUIDs where available.
6. Search for Logon Type 10 events.
7. Confirm `mstsc.exe` execution in `index=endpoint`.
8. Review RDP operational logs if they are ingested.
9. Determine whether the destination was local or remote.
10. Validate whether the activity was authorized.
11. Review post-authentication process and network activity.
12. Escalate only when the process, account, destination, or follow-on activity is anomalous.

---

## Screenshots



![RDP Authentication Events](../screenshots/splunk-searches/lab5-rdp-lateral-movement.png)


---

## Lessons Learned

1. Event ID 4648 records explicit credential use but is not automatically malicious.
2. The process, target account, and target server are critical investigation fields.
3. `cmdkey /list` reveals stored targets and usernames, not plaintext passwords.
4. Credential enumeration does not prove credential use.
5. Logon Type 2 represents local interactive authentication.
6. Logon Type 10 provides stronger evidence of RDP authentication.
7. Launching `mstsc.exe` does not prove that a session authenticated.
8. Localhost RDP does not demonstrate lateral movement.
9. Pass-the-Hash requires hash-based authentication evidence.
10. T1021.001 should not be counted as validated lateral movement from localhost activity.
11. T1078 requires evidence of adversary abuse, not merely a normal successful logon.
12. Analyst conclusions should distinguish observed, assessed, and unconfirmed findings.
