# Lab 4: Phishing Email Triage

**Date:** 2026-02-12
**Analyst:** Vishva Teja Chikoti
**Environment:** Simulated SOC Analyst Workstation
**Severity:** HIGH
**Ticket:** SOC-4821
**Difficulty:** Intermediate

---

## Objective

Investigate a user-reported suspicious email by analyzing:

* Sender and reply-to information
* SPF, DKIM, and DMARC results
* Domain impersonation
* Encoded URL content
* Attachment naming and file type
* Email campaign scope
* Link-click and attachment-execution evidence

The goal is to determine whether the message represents a phishing attempt, identify the available evidence, assess organizational impact, and recommend proportionate containment actions.

---

## NIST SP 800-61 Rev. 3 Alignment

This lab demonstrates incident detection, analysis, prioritization, evidence preservation, scope assessment, containment planning, and escalation.

**Observed:** The simulated message contained a lookalike sender domain, failed authentication results, an encoded URL, a mismatched reply-to address, and a double-extension executable attachment.

**Assessed:** The combined artifacts are consistent with a phishing email designed to impersonate a trusted organization and encourage credential submission or file execution.

**Not confirmed:** The evidence does not demonstrate that a user clicked the link, submitted credentials, executed the attachment, or that the attachment contained functioning malware.

---

## Lab Scope and Safety

All indicators in this report are simulated and use reserved example infrastructure.

No live third-party domains, IP addresses, credentials, or malware were used.

| Indicator Type   | Safe Simulated Value                     |
| ---------------- | ---------------------------------------- |
| Sender domain    | `paypa1-verify.example`                  |
| Decoded URL      | `https://credential-check.example/steal` |
| Originating IP   | `198.51.100.45`                          |
| Reply-to address | `collect-data@reply.example`             |
| Attachment       | `Account_Verification_Form.pdf.exe`      |

The `.example` domain and `198.51.100.0/24` address range are used for documentation and simulation.

---

## Lab Setup

| Component                  | Detail                                              |
| -------------------------- | --------------------------------------------------- |
| Environment                | Simulated SOC analyst workstation                   |
| Data source                | User-reported suspicious email                      |
| Tools                      | CyberChef, email-header analyzer, Splunk            |
| Primary log sources        | Email gateway, proxy, DNS, Windows Security, Sysmon |
| Optional enrichment        | Sandbox and reputation services                     |
| Sysmon index               | `endpoint`                                          |
| Windows and Defender index | `wineventlog`                                       |

---

## Email Evidence

```text
From: secure-alert@paypa1-verify.example
To: jsmith@company.example
Subject: Urgent: Your Account Has Been Suspended
Date: 2026-02-12 09:14:33 UTC
Originating IP: 198.51.100.45
SPF: FAIL
DKIM: FAIL
DMARC: FAIL
Reply-To: collect-data@reply.example
Attachment: Account_Verification_Form.pdf.exe
```

---

## Analyst Narrative

A user reported an email claiming to represent PayPal account security.

Initial triage identified several suspicious features:

* A lookalike sender domain containing the number `1`
* A reply-to domain different from the sender domain
* SPF, DKIM, and DMARC failures
* An urgency-themed subject
* A Base64-encoded URL value
* An executable attachment using a double extension

No single indicator independently proves maliciousness. However, the combination of brand impersonation, authentication failures, encoded content, reply-to mismatch, and executable masquerading creates a high-confidence phishing assessment within the controlled simulation.

### Analyst Assessment

**Observed:**

* The sender domain visually impersonated a trusted brand.
* The reply-to address used a different domain.
* SPF, DKIM, and DMARC were recorded as failed.
* A Base64 string decoded into a second URL.
* The attachment ended in `.exe` despite containing `.pdf` in its name.
* The user reported the message before opening the attachment.

**Assessed:**

* The message is consistent with phishing and brand impersonation.
* The attachment name was designed to make an executable appear document-like.
* The encoded URL may have been intended to obscure the destination from casual inspection or simple filtering.
* The reply-to mismatch may support collection of victim responses through separate infrastructure.

**Not confirmed:**

* Authentication failures alone do not prove spoofing or malicious intent.
* The decoded path name does not prove that the destination hosted a credential-harvesting page.
* The attachment was not detonated or reverse engineered.
* No credential submission was observed.
* No endpoint execution was observed.
* No organization-wide phishing campaign was confirmed.
* The operator’s sophistication or professionalism cannot be determined from these artifacts alone.

---

## Investigation Steps

### Step 1 — Preserve the Message

* Preserve the original email in `.eml` or `.msg` format.
* Retain complete headers.
* Record the message ID.
* Preserve the original attachment without opening it.
* Document the reporting user and report time.

---

### Step 2 — Header Analysis

Review:

* `From`
* Envelope sender / Return-Path
* `Reply-To`
* `Received` chain
* Message ID
* SPF result
* DKIM result
* DMARC result
* Sending IP
* Timestamp consistency

### Authentication Assessment

| Result     | Meaning                                                      | Limitation                                                                    |
| ---------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| SPF FAIL   | Sending host was not authorized by the evaluated SPF policy  | Forwarding or configuration issues can affect results                         |
| DKIM FAIL  | The evaluated signature did not validate                     | Message modification, broken signatures, or configuration issues are possible |
| DMARC FAIL | The message did not satisfy aligned SPF or DKIM requirements | Must be interpreted with domain policy, alignment, and complete headers       |

**Assessment:** The three failures significantly increase suspicion when combined with domain impersonation, but they should not be described as automatic proof that a message is malicious.

---

### Step 3 — Domain Review

```text
Displayed brand: PayPal
Observed sender: paypa1-verify.example
Expected corporate domain: paypal.com
```

The observed name uses the number `1` in place of a lowercase `l`, creating a visual lookalike.

In a real investigation, validate:

* Registration date
* Registrar
* DNS records
* Hosting provider
* Certificate history
* Passive DNS
* Reputation
* Known internal ownership
* Whether the domain is newly observed in the organization

Do not claim that a domain is newly registered or unaffiliated with a company unless that information was actually verified.

---

### Step 4 — Decode the URL

**Encoded value:**

```text
aHR0cHM6Ly9jcmVkZW50aWFsLWNoZWNrLmV4YW1wbGUvc3RlYWw=
```

**Decoded value:**

```text
https://credential-check.example/steal
```

**Tool:**

```text
CyberChef → From Base64
```

### URL Assessment

**Observed:** Base64 decoding revealed a second destination string.

**Assessed:** Encoding may have been used to reduce readability or obscure the destination.

**Not confirmed:** The destination was not loaded, crawled, or independently verified as a credential-harvesting page.

In a production investigation, submit the URL to an approved sandbox or secure URL-analysis platform rather than opening it directly from an analyst workstation.

---

### Step 5 — Attachment Analysis

**Filename:**

```text
Account_Verification_Form.pdf.exe
```

### Attachment Assessment

* The final extension is `.exe`.
* The filename contains `.pdf` before the executable extension.
* This is consistent with double-extension masquerading.
* The attachment should not be opened directly.
* The file should be hashed and analyzed in an isolated environment.

**Not confirmed:** The filename alone does not prove that the executable contains malware or that it executes silently.

---

### Step 6 — Scope Assessment

Search for:

* Other recipients of the same message
* Matching sender domain
* Matching reply-to address
* Matching subject
* Matching message ID patterns
* Matching attachment name or hash
* Proxy or DNS requests for the observed domains
* Endpoint execution of the attachment
* Defender or EDR detections
* Credential resets or unusual sign-ins following delivery

---

## Artifacts and Indicators

| Type           | Value                                                  | Classification                 |
| -------------- | ------------------------------------------------------ | ------------------------------ |
| Sender domain  | `paypa1-verify.example`                                | Simulated suspicious artifact  |
| Decoded URL    | `https://credential-check.example/steal`               | Simulated suspicious artifact  |
| Originating IP | `198.51.100.45`                                        | Documentation-only IP          |
| Attachment     | `Account_Verification_Form.pdf.exe`                    | Suspicious filename            |
| Reply-to       | `collect-data@reply.example`                           | Simulated suspicious artifact  |
| Encoded token  | `aHR0cHM6Ly9jcmVkZW50aWFsLWNoZWNrLmV4YW1wbGUvc3RlYWw=` | Encoded investigation artifact |
| SHA-256        | Not collected                                          | Requires original attachment   |
| MD5            | Not collected                                          | Requires original attachment   |

These artifacts should not be described as confirmed indicators of compromise unless they are associated with verified malicious activity.

### Hash Collection

```powershell
Get-FileHash `
    -Path ".\Account_Verification_Form.pdf.exe" `
    -Algorithm SHA256

Get-FileHash `
    -Path ".\Account_Verification_Form.pdf.exe" `
    -Algorithm MD5
```

SHA-256 should be the primary hash used for investigation and correlation. MD5 may be retained for compatibility with older threat-intelligence systems but should not be relied upon for integrity assurance.

Do not invent or reuse placeholder hashes. The previously listed values represented empty-file hashes and were not valid evidence for the attachment.

---

## Detection Queries

Field names and indexes may differ by email, proxy, and endpoint platform. These queries represent the expected detection logic and should be adapted to the actual schema.

### Query 1 — Email Campaign Scope

```spl
index=email_logs
(sender_domain="paypa1-verify.example"
 OR reply_to="collect-data@reply.example"
 OR attachment_name="Account_Verification_Form.pdf.exe")
| eval attachment_lower=lower(attachment_name)
| where like(attachment_lower, "%.exe")
    OR like(attachment_lower, "%.pdf.exe")
| stats
    count AS message_count
    values(subject) AS subjects
    values(attachment_name) AS attachments
    values(message_id) AS message_ids
    BY recipient sender_domain reply_to
| sort -message_count
```

This query identifies recipients and messages sharing the simulated sender, reply-to, or attachment indicators.

---

### Query 2 — Suspicious Authentication and Impersonation

```spl
index=email_logs
| eval sender_lower=lower(sender_domain)
| eval subject_lower=lower(subject)
| where
    spf_result="fail"
    AND dkim_result="fail"
    AND dmarc_result="fail"
    AND (
        like(sender_lower, "%paypa1%")
        OR like(subject_lower, "%suspended%")
        OR like(subject_lower, "%verify%")
        OR like(subject_lower, "%urgent%")
        OR like(subject_lower, "%locked%")
    )
| table _time recipient sender sender_domain reply_to subject spf_result dkim_result dmarc_result attachment_name
| sort -_time
```

Authentication failure and urgency wording should contribute to a risk score rather than serving as automatic proof of phishing.

---

### Query 3 — Proxy Click Investigation

```spl
index=proxy_logs
(url="*paypa1-verify.example*"
 OR url="*credential-check.example*")
| table _time user src_ip dest_ip url http_method status user_agent
| sort _time
```

A proxy event establishes that a request was attempted or completed. It does not by itself prove credential submission or endpoint compromise.

---

### Query 4 — DNS Scope Investigation

```spl
index=dns_logs
(query="paypa1-verify.example"
 OR query="credential-check.example")
| stats
    count AS query_count
    earliest(_time) AS first_seen
    latest(_time) AS last_seen
    values(answer) AS answers
    BY src_ip user query
| convert ctime(first_seen) ctime(last_seen)
| sort -query_count
```

---

### Query 5 — Sysmon Attachment Execution Check

Sysmon process-creation telemetry is stored in `index=endpoint`.

```spl
index=endpoint
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
(Image="*\\Account_Verification_Form.pdf.exe"
 OR CommandLine="*Account_Verification_Form.pdf.exe*")
| table _time host User Image ParentImage CommandLine ProcessId ProcessGuid Hashes IntegrityLevel
| sort _time
```

A matching event would support attachment execution. Absence of a match does not prove the file was never executed if telemetry was unavailable, delayed, or incomplete.

---

### Query 6 — Defender Detection Check

Windows Defender events are stored in `index=wineventlog`.

```spl
index=wineventlog
source="WinEventLog:Microsoft-Windows-Windows Defender/Operational"
(EventCode=1116 OR EventCode=1117)
Message="*Account_Verification_Form*"
| table _time host EventCode Message
| sort -_time
```

A Defender detection would provide supporting evidence about the file but should be correlated with the exact path, hash, process, and detection name.

---

## MITRE ATT&CK Mapping

| Technique ID | Technique                           | Evidence                                               | Status                        |
| ------------ | ----------------------------------- | ------------------------------------------------------ | ----------------------------- |
| T1566.001    | Phishing: Spearphishing Attachment  | Executable attachment delivered in the simulated email | Confirmed simulation behavior |
| T1566.002    | Phishing: Spearphishing Link        | Encoded link included in the simulated email           | Confirmed simulation behavior |
| T1036.007    | Masquerading: Double File Extension | `.pdf.exe` attachment name                             | Confirmed                     |
| T1027        | Obfuscated Files or Information     | Base64 used to obscure the destination string          | Assessed                      |

### Excluded Mappings

* **T1071.001 — Web Protocols:** Not demonstrated. A phishing URL does not establish command-and-control communication.
* **T1598 — Phishing for Information:** Not required for this report because T1566.001 and T1566.002 more directly represent the delivered phishing email.
* **T1204.001 — Malicious Link:** Not demonstrated because no user click was confirmed.
* **T1204.002 — Malicious File:** Not demonstrated because no attachment execution was confirmed.
* **Credential Access techniques:** Not demonstrated because no credentials were submitted or collected.

---

## Risk Assessment

### Severity: HIGH

| Factor                          | Assessment                          |
| ------------------------------- | ----------------------------------- |
| Lookalike sender domain         | High                                |
| Double-extension executable     | High                                |
| Encoded secondary URL           | High                                |
| SPF, DKIM, and DMARC failures   | High-confidence supporting evidence |
| Reply-to mismatch               | Suspicious                          |
| Confirmed attachment execution  | Not observed                        |
| Confirmed credential submission | Not observed                        |
| Confirmed additional recipients | Not established                     |
| Confirmed malware behavior      | Not established                     |

Severity should be increased to **CRITICAL** only when evidence shows significant impact, such as:

* Attachment execution
* Malware detection or behavioral confirmation
* Credential submission
* Account takeover
* Multiple affected recipients
* Privileged-user compromise
* Broad campaign delivery
* Follow-on persistence or lateral movement

---

## Verdict

### High-Confidence Phishing Simulation

The combined evidence is consistent with a phishing email containing both a suspicious link and an executable attachment disguised through a double extension.

**Confirmed within the simulation:**

* Brand-lookalike sender domain
* Authentication failures
* Reply-to mismatch
* Encoded secondary URL
* Executable attachment with a double extension

**Not confirmed:**

* Live malicious infrastructure
* Credential-harvesting functionality
* Malware behavior
* Attachment execution
* User click
* Credential submission
* Account compromise
* Organization-wide campaign

The correct production verdict would remain:

```text
Phishing — high confidence
Impact — not yet confirmed
Scope — under investigation
```

---

## Containment and Response Actions

### Immediate Actions

1. Preserve the original message and headers.
2. Quarantine the reported email.
3. Search for matching messages across all mailboxes.
4. Identify all recipients.
5. Search proxy and DNS logs for access to the observed domains.
6. Search Sysmon and EDR telemetry for attachment execution.
7. Calculate the attachment hash.
8. Submit the file and URL to approved analysis platforms.
9. Add confirmed malicious indicators to appropriate controls.
10. Document the evidence and investigation status.

### If a Link Was Clicked

A click alone does not automatically prove compromise.

Perform the following:

1. Review the full URL and redirect chain.
2. Determine whether credentials were submitted.
3. Check browser, proxy, DNS, and endpoint telemetry.
4. Review sign-in logs for anomalous sessions.
5. Reset the user’s password if credential submission is suspected or confirmed.
6. Revoke active sessions and tokens when account compromise is possible.
7. Isolate the endpoint when exploit activity, payload delivery, or malicious execution is supported by evidence.

### If the Attachment Was Executed

1. Isolate the endpoint.
2. Preserve process and network evidence.
3. Collect the file hash and sample.
4. Review the process tree.
5. Search for child processes, persistence, and network connections.
6. Review Defender and EDR detections.
7. Scope the hash and behavior across the environment.
8. Escalate to incident response.

### Blocking Guidance

* Block confirmed malicious domains and URLs at email, DNS, proxy, and endpoint controls.
* Evaluate the business impact before blocking shared hosting infrastructure or broadly used IP addresses.
* Do not publish or block the reserved example indicators used in this report.
* Quarantine matching email messages based on multiple attributes rather than a subject line alone.

---

## Escalation Summary

```text
ESCALATION SUMMARY — Ticket SOC-4821

Classification:
High-confidence phishing simulation

Severity:
HIGH

Analyst:
Vishva Teja Chikoti

Observed Evidence:
- Lookalike sender domain
- SPF, DKIM, and DMARC failures
- Reply-to mismatch
- Base64-encoded secondary URL
- Double-extension executable attachment

Impact:
No user click, credential submission, or attachment execution confirmed

Scope:
One reported recipient; organization-wide scope search required

Recommended Next Actions:
- Preserve the original email
- Search for additional recipients
- Review proxy and DNS activity
- Hash and sandbox the attachment
- Search Sysmon and Defender telemetry
- Block indicators only after validation
```

---

## False Positives and Alternative Explanations

| Scenario                                               | Validation                                                                                       |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| Legitimate sender with authentication misconfiguration | Validate domain ownership, complete headers, vendor communication, and prior message history     |
| Forwarded or modified email                            | Review forwarding path and `Received` headers                                                    |
| Internal phishing simulation                           | Confirm approved security-testing infrastructure and campaign owner                              |
| Legitimate executable attachment                       | Validate sender relationship, code signature, hash, business purpose, and secure delivery method |
| Benign Base64 parameter                                | Decode the value and inspect its function and destination                                        |
| Reply-to mismatch used by legitimate service           | Validate documented vendor mail flow and prior baseline                                          |
| User incorrectly reported marketing email              | Examine all message artifacts rather than relying on urgency wording alone                       |

Do not allowlist an entire domain solely because one prior message was legitimate. Tune using sender infrastructure, DKIM selector, message patterns, expected recipients, attachment type, and business relationship.

---

## Screenshots

> This lab uses simulated infrastructure. No real email was analyzed.
> Screenshots are not applicable. In a production investigation,
> capture: full headers, authentication results, decoded URL,
> CyberChef decode step, gateway scope search results,
> proxy/DNS query results, Sysmon execution search, Defender detection.

---

## Lessons Learned

1. Multiple weak indicators can combine into a strong phishing assessment.
2. SPF, DKIM, and DMARC failures require context and are not automatic proof of maliciousness.
3. A double-extension executable is highly suspicious but does not prove malware behavior.
4. Base64 content should be decoded safely and assessed in context.
5. A decoded URL path does not prove credential harvesting without page or behavioral evidence.
6. A Tor or anonymized source does not establish attacker sophistication.
7. Never use invented hashes as investigation evidence.
8. A link click does not automatically prove endpoint compromise.
9. Attachment execution and credential submission materially increase severity.
10. T1071.001 should not be mapped merely because a phishing URL uses HTTP or HTTPS.
11. Use `index=endpoint` for Sysmon execution telemetry.
12. Use `index=wineventlog` for Windows Defender events.
13. Separate observed evidence, analyst assessment, and unconfirmed conclusions.
14. Use safe reserved infrastructure in public simulations.
