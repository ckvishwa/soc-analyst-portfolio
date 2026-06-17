# Attack Simulation 02 — Brute Force Login

**Simulation ID:** SIM-002  
**Status:** ✅ Lab Validated  
**Safety Level:** Safe — lab credentials only, isolated network  
**Estimated Time:** 20–25 minutes

---

## Objective

Generate Windows Security Event Log telemetry for repeated failed authentication attempts against an Active Directory account. The goal is to trigger Event ID 4625 (failed logon) at a volume that activates the brute force detection rule and to observe Event ID 4740 (account lockout) when the lockout threshold is reached.

---

## MITRE ATT&CK Technique

| Field | Value |
|-------|-------|
| **Tactic** | Credential Access |
| **Technique ID** | T1110.001 |
| **Technique Name** | Brute Force: Password Guessing |
| **Reference** | https://attack.mitre.org/techniques/T1110/001/ |

---

## Lab-Only Simulation Method

> ⚠️ **SAFETY NOTE:** Only target lab domain accounts you created. Do NOT target real accounts, production systems, or any system outside the lab network. The Kali VM must be on the isolated lab VLAN only.

### Pre-Simulation Checklist
- [ ] Kali VM is on isolated lab network (192.168.10.0/24) — no internet access
- [ ] Lab AD has a test user account created (e.g., `SOCLAB\testuser01`)
- [ ] Account lockout policy is configured on the DC (5 failures in 5 minutes = lockout)
- [ ] Splunk is collecting Windows Security logs from both DC and WIN10-VICTIM
- [ ] Verify Event ID 4625 appears in Splunk baseline (normal login failures exist)

### Setup — Create Test Account on DC

```powershell
# On Windows Server DC (PowerShell as Domain Admin)
New-ADUser -Name "Test User 01" -SamAccountName "testuser01" `
  -AccountPassword (ConvertTo-SecureString "LabPass123!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
```

### Simulation Step 1 — Manual Failed Logons (Windows)

On WIN10-VICTIM, attempt to login as `testuser01` with wrong passwords 10+ times via:
- Windows lock screen (Ctrl+Alt+Del → Switch User)
- Or via Run → `runas /user:SOCLAB\testuser01 cmd.exe` with wrong passwords

This generates Event ID 4625 (Logon Type 2 — interactive) on the DC.

### Simulation Step 2 — Network Brute Force from Kali (SMB)

```bash
# On Kali Linux — targeting lab DC only
# Using hydra with a small wordlist (lab passwords only)
hydra -l testuser01 -P /usr/share/wordlists/rockyou.txt \
  -t 4 -W 3 192.168.10.10 smb

# OR using crackmapexec (safer rate control)
crackmapexec smb 192.168.10.10 -u testuser01 -p /tmp/lab-passlist.txt
```

**Create a small safe test wordlist:**
```bash
cat > /tmp/lab-passlist.txt << 'EOF'
wrongpass1
wrongpass2
wrongpass3
wrongpass4
wrongpass5
wrongpass6
wrongpass7
wrongpass8
wrongpass9
wrongpass10
wrongpass11
LabPass123!
EOF
```

This generates Event ID 4625 (Logon Type 3 — network) on the DC and triggers Event 4740 (lockout) at the threshold.

---

## Expected Windows Event IDs

| Event ID | Log | Description | Key Fields |
|---------|-----|-------------|-----------|
| 4625 | Security | Account failed to log on | `Account_Name`, `IpAddress`, `Logon_Type`, `Failure_Reason`, `Status`, `Sub_Status` |
| 4740 | Security | User account was locked out | `Account_Name`, `CallerComputerName` |
| 4776 | Security | NTLM authentication attempt | `Account_Name`, `Workstation`, `Error_Code` |
| 4771 | Security | Kerberos pre-auth failed | `Account_Name`, `Client_Address`, `Failure_Code` |
| 4624 | Security | Successful logon (after correct password found) | `Account_Name`, `Logon_Type`, `IpAddress` |

---

## Expected Sysmon Event IDs

Sysmon does not directly capture authentication events. Authentication telemetry comes from Windows Security logs. However, Sysmon may capture:

| Event ID | Description | Context |
|---------|-------------|---------|
| 3 | Network Connection | If brute force tool (hydra) makes TCP connections to port 445, Sysmon captures the connection |
| 1 | Process Creation | If brute force attempt is initiated via cmd/PowerShell locally on endpoint |

---

## Detection Logic

```spl
| Detection: Brute Force Login |

index=wineventlog sourcetype="WinEventLog:Security"
EventID=4625
| bucket _time span=5m
| stats count AS failure_count, 
        values(IpAddress) AS source_ips,
        dc(IpAddress) AS unique_source_ips,
        values(Logon_Type) AS logon_types
  BY _time, Account_Name
| where failure_count >= 10
| eval detection="Brute Force Login"
| eval mitre="T1110.001"
| eval severity=case(failure_count >= 50, "Critical", failure_count >= 20, "High", 1=1, "Medium")
| sort -failure_count
```

---

## False Positives

| Scenario | Tuning |
|---------|--------|
| Service accounts with expired passwords | Exclude known service account names from threshold |
| Helpdesk password reset lockouts | Correlate with helpdesk ticket system; exclude known support hours |
| Users locked out after device sync | Review `IpAddress` — repeated failures from same mobile device |

---

## Defensive Takeaway

Account lockout policies are the cheapest brute force mitigation available. Organizations without them are trivially vulnerable to online password guessing. The harder problem is **password spray** — one attempt per account across many accounts — which never trips a single-account lockout threshold. Password spray detection requires a different query: count unique accounts with Event 4625 per source IP, not failures per account.
