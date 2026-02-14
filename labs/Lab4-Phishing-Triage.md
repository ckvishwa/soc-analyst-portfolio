# Lab 4: Phishing Email Triage

**Date:** 2026-02-12
**Analyst:** Vishva Teja Chikoti
**Severity:** HIGH
**Ticket:** #4821
**Difficulty:** Intermediate

---

## Objective
Investigate a user-reported phishing email. Analyze headers,
URLs, attachments, and authentication failures to determine
malicious intent and take appropriate containment actions.

---
## NIST SP 800-61 Incident Response Phase
> **Phase 2: Detection & Analysis → Phase 3: Containment**
> Phishing email triaged. Malicious attachment (pdf.exe) identified.
> Base64 URL decoded to evil.com/steal. Severity: CRITICAL.
## Lab Setup

| Component | Detail |
|-----------|--------|
| Environment | Simulated SOC analyst workstation |
| Data Source | User-reported suspicious email |
| Tools Used | CyberChef, VirusTotal, Email Header Analyzer |
| Log Sources | Email gateway logs, proxy logs, endpoint logs |

---

## Analyst Narrative

User jsmith@company.com reported a suspicious email claiming
to be from PayPal. Initial review immediately flagged multiple
indicators: typosquatted domain, triple authentication failure
(SPF/DKIM/DMARC), Base64-encoded malicious URL, and a
double-extension executable disguised as PDF.

Key pivot point: Decoding the URL token revealed the actual
destination was https://evil.com/steal — a credential
harvesting site hidden behind an innocent-looking login URL.
This confirmed malicious intent within 2 minutes of investigation.

Second critical finding: The Tor exit node IP (185.220.101.45)
as originating IP combined with a disposable reply-to inbox
indicates professional phishing infrastructure — not a
one-time opportunistic attack.

---

## Email Evidence

```
FROM:    secure-alert@paypa1-verify.com
TO:      jsmith@company.com
SUBJECT: Urgent: Your Account Has Been Suspended
DATE:    2026-02-12 09:14:33 UTC
IP:      185.220.101.45
SPF:     FAIL
DKIM:    FAIL
DMARC:   FAIL
Reply-To: collect-data@temp-mail.org
```

---

## Investigation Steps

### Step 1: Header Analysis (2 min)
- Checked SPF/DKIM/DMARC → all FAIL = spoofed domain
- X-Originating-IP: 185.220.101.45 → Tor exit node
- Reply-To differs from sender → separate collection infrastructure

### Step 2: Domain Analysis (1 min)
- paypa1-verify.com → typosquatted (number 1, not letter l)
- Not registered to PayPal Inc.
- Registered recently (typical phishing domain pattern)

### Step 3: URL Decode (2 min)
- Extracted token: `aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==`
- Identified Base64 encoding (== padding giveaway)
- Decoded via CyberChef → `https://evil.com/steal`
- Confirmed credential harvesting destination

### Step 4: Attachment Analysis (1 min)
- Filename: Account_Verification_Form.pdf.exe
- Double extension identified → executable disguised as PDF
- Did NOT open → submitted hash to VirusTotal

### Step 5: Scope Check (3 min)
- Checked email gateway for same sender domain
- Checked proxy logs for clicks on paypa1-verify.com
- Checked if other users received same email

---

## IOC Analysis

### Red Flag 1: Typosquatted Domain
```
Malicious:  paypa1-verify.com (number 1 not letter l)
Legitimate: paypal.com
```
Classic domain spoofing. Tricks casual readers into trusting the sender.

### Red Flag 2: Base64 Encoded URL
```
Displayed: http://paypa1-verify.com/login?token=aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==
Decoded:   https://evil.com/steal
Tool:      CyberChef → From Base64
```
Attacker hid real destination inside encoded token.
Victim sees fake login page. Credentials sent to evil.com/steal.

### Red Flag 3: Double Extension Attachment
```
Filename: Account_Verification_Form.pdf.exe
Reality:  Executable file (.exe) disguised as PDF
Risk:     Opens → malware executes silently
```
Windows hides known extensions by default.
User sees "Account_Verification_Form.pdf" — opens it thinking it's a form.

### Red Flag 4: Authentication Triple Failure
```
SPF:   FAIL → Not sent from PayPal mail servers
DKIM:  FAIL → Email content not signed by PayPal
DMARC: FAIL → Domain policy violated
```
All 3 failing = email is 100% spoofed. Automatic escalation trigger.

### Red Flag 5: Suspicious Infrastructure
```
X-Originating-IP: 185.220.101.45 (Tor exit node)
Reply-To:         collect-data@temp-mail.org (disposable inbox)
```
Tor IP = attacker hiding true origin.
Separate reply-to = attacker collecting responses on different
infrastructure than sending domain. Professional phishing setup.

---

## Extracted IOCs

| Type | Value | Risk |
|------|-------|------|
| Sender Domain | paypa1-verify.com | CRITICAL |
| Malicious URL | https://evil.com/steal | CRITICAL |
| IP Address | 185.220.101.45 | HIGH |
| Attachment | Account_Verification_Form.pdf.exe | CRITICAL |
| Reply-To | collect-data@temp-mail.org | HIGH |
| Encoded Token | aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA== | HIGH |
| SHA256 | e3b0c44298fc1c149afb4c8996fb924427ae41e4649b934ca495991b7852b855 | CRITICAL |
| MD5 | d41d8cd98f00b204e9800998ecf8427e | CRITICAL |

*Hashes simulated. In real investigation:*
```powershell
Get-FileHash "Account_Verification_Form.pdf.exe" -Algorithm SHA256
Get-FileHash "Account_Verification_Form.pdf.exe" -Algorithm MD5
```

---

## Detection Queries

### Query 1: Email Gateway — Campaign Scope
```splunk
index=email_logs sender_domain="paypa1-verify.com"
| stats count by recipient, subject, attachment_name
| where attachment_name="*.exe" OR attachment_name="*.pdf.exe"
```
*Identifies how many users received this email*

### Query 2: Urgency-Based Phishing Detection
```splunk
index=email_logs
| search subject="*suspended*" OR subject="*verify*" OR subject="*urgent*" OR subject="*locked*"
| stats count by sender_domain, recipient
| where count > 1
```
*Detects urgency-language phishing campaigns across organization*

### Query 3: Proxy Logs — Did Anyone Click?
```splunk
index=proxy_logs
| search url="*paypa1-verify*" OR url="*evil.com/steal*"
| table _time, src_ip, url, user
| sort _time
```
*Identifies users who clicked the malicious link*

### Query 4: Endpoint — Attachment Execution Check
```splunk
index=main EventCode=1
| search CommandLine="*Account_Verification*" OR Image="*Account_Verification*"
| table _time, User, CommandLine, ParentImage
```
*Detects if attachment was opened and executed*

---

## Containment Actions (In Order)

```
1. Block IP 185.220.101.45 at firewall
2. Block domains: paypa1-verify.com, evil.com
3. Pull email from ALL company inboxes immediately
4. Check gateway: how many users received it?
5. Check proxy logs: did anyone click the URL?
6. If clicked → isolate that system immediately
7. Hash attachment → submit to VirusTotal
8. Notify all staff: active phishing campaign
9. Document all IOCs
10. Escalate to L2 with full IOC report
```

---

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|----|-----------|---------|
| T1566.001 | Spearphishing Attachment | pdf.exe attachment |
| T1566.002 | Spearphishing Link | Encoded malicious URL |
| T1027 | Obfuscated Files | Base64 encoded URL token |
| T1036.007 | Double File Extension | pdf.exe masquerading as PDF |
| T1598 | Phishing for Information | Credential harvesting site |
| T1071.001 | Web Protocols | HTTP-based C2/exfil via evil.com |

---

## Risk Rating

**CRITICAL**

| Factor | Assessment |
|--------|-----------|
| Malicious executable attached | CRITICAL |
| Credential harvesting confirmed | CRITICAL |
| Tor-based infrastructure | HIGH |
| Triple auth failure | HIGH |
| Potential for mass compromise | HIGH |

---

## Verdict

**MALICIOUS. CONFIRMED PHISHING ATTACK.**

Not a false positive. Not a misconfiguration.
Active credential harvesting campaign targeting company users
using professional phishing infrastructure (Tor, disposable
inboxes, typosquatted domains).

---

## Escalation to L2

```
ESCALATION SUMMARY - Ticket #4821

Verdict:    MALICIOUS - Confirmed Phishing
Severity:   CRITICAL
Analyst:    Vishva Teja Chikoti
Time:       ~10 min investigation

Key Findings:
- Typosquatted PayPal domain
- Base64 URL decodes to credential harvester
- Double-extension executable attached
- SPF/DKIM/DMARC all fail
- Tor exit node origin

IOCs Extracted: 8
Containment: IP + domain blocked, email pulled from inboxes

L2 Actions Required:
- Sandbox detonation of attachment
- Threat intel on 185.220.101.45
- Scope assessment (click tracking)
- Email gateway rule creation
- User awareness notification
```

---

## False Positives

| Scenario | How to Differentiate |
|----------|---------------------|
| Legitimate urgency email | SPF/DKIM/DMARC would PASS |
| User misidentified spam | Would not have double-extension attachment |
| Internal security test | Would originate from known test infrastructure |

---

## Lessons Learned

1. Base64 in URLs = always decode and inspect
2. Double extensions = never open, always sandbox first
3. SPF/DKIM/DMARC triple fail = auto-escalate, no exceptions
4. One reported phishing = check entire organization immediately
5. Urgency language = automatic suspicion trigger
6. Different Reply-To from sender = professional phishing infrastructure
7. Always extract and hash attachments even if unopened
