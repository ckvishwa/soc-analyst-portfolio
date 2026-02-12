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
```

---

## IOC Analysis

### Red Flag 1: Typosquatted Domain
```
Malicious: paypa1-verify.com (number 1, not letter l)
Legitimate: paypal.com
```
Classic domain spoofing. Tricks casual readers.

### Red Flag 2: Base64 Encoded URL
```
Displayed:  http://paypa1-verify.com/login?token=aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA==
Decoded:    https://evil.com/steal
Tool used:  CyberChef (From Base64)
```
Attacker hid real destination inside encoded token.
Victim sees fake login page. Credentials sent to evil.com.

### Red Flag 3: Double Extension Attachment
```
Filename: Account_Verification_Form.pdf.exe
Reality:  Executable file (.exe) disguised as PDF
Risk:     Opens → malware executes silently
```
Windows hides known extensions by default.
User sees "Account_Verification_Form.pdf" and opens it.

### Red Flag 4: Authentication Triple Failure
```
SPF:   FAIL → Not sent from PayPal mail servers
DKIM:  FAIL → Email content not signed by PayPal
DMARC: FAIL → Domain policy violated
```
All 3 failing = email is 100% spoofed. Not from PayPal.

### Red Flag 5: Suspicious Infrastructure
```
X-Originating-IP: 185.220.101.45 (Tor exit node)
Reply-To: collect-data@temp-mail.org (disposable inbox)
```
Tor IP = attacker hiding origin.
Separate reply-to = attacker collecting responses
from different infrastructure than sending domain.

---

## Extracted IOCs

| Type | Value | Risk |
|------|-------|------|
| Sender Domain | paypa1-verify.com | CRITICAL |
| Malicious URL | evil.com/steal | CRITICAL |
| IP Address | 185.220.101.45 | HIGH |
| File | Account_Verification_Form.pdf.exe | CRITICAL |
| Reply-To | collect-data@temp-mail.org | HIGH |
| Token | aHR0cHM6Ly9ldmlsLmNvbS9zdGVhbA== | HIGH |

---

## Containment Actions (In Order)
```
1. Block IP 185.220.101.45 at firewall
2. Pull email from ALL company inboxes
3. Check gateway: how many users received it?
4. Check proxy logs: did anyone click the URL?
5. If clicked → isolate system immediately
6. Hash attachment → submit to VirusTotal
7. Block domains: paypa1-verify.com, evil.com
8. Document all IOCs
9. Escalate to L2 with full IOC report
```

---

## MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|----|-----------|---------|
| T1566.001 | Spearphishing Attachment | pdf.exe attachment |
| T1566.002 | Spearphishing Link | Encoded malicious URL |
| T1027 | Obfuscated Files | Base64 encoded URL |
| T1036.007 | Double File Extension | pdf.exe masquerading |
| T1598 | Phishing for Information | Credential harvesting |

---

## Risk Rating
**CRITICAL**
- Malicious executable attached
- Credential harvesting URL confirmed
- Tor-based infrastructure
- Triple auth failure = spoofed domain

---

## Verdict
**MALICIOUS. CONFIRMED PHISHING ATTACK.**

Not a false positive. Not a misconfiguration.
Active credential harvesting campaign targeting company users.

---

## What Happens Next (L2 Escalation)
- Forensic analysis of attachment (sandbox detonation)
- Threat intel: Is 185.220.101.45 part of known campaign?
- Scope assessment: How many users received/clicked?
- Email gateway rule: Block future emails from this infrastructure
- User awareness: Notify all staff of active campaign

---

## Lessons Learned
1. Base64 in URLs = always decode and inspect
2. Double extensions = never open, always sandbox
3. SPF/DKIM/DMARC triple fail = auto-escalate
4. One reported phishing = check entire organization
5. Urgency language = automatic suspicion trigger
```
