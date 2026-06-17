# False Positive Analysis — Enterprise SOC Detection Lab v2

**Purpose:** Document every false positive encountered during detection validation, with tuning recommendations for each.

---

## DET-001 — PowerShell Suspicious Execution

| # | FP Scenario | Trigger Condition | Recommended Exclusion |
|---|------------|-----------------|----------------------|
| 1 | IT automation scripts | Admin accounts running `-ExecutionPolicy Bypass` with signed scripts on a schedule | `NOT (User IN ("domain\\it_svc") AND CommandLine="*-File C:\\Scripts\\Approved\\*")` |
| 2 | SCCM/Intune client | Software deployment invoking PowerShell with hidden window | `NOT ParentImage IN ("*\\ccmexec.exe","*\\ServiceUI.exe")` |
| 3 | Windows Defender updates | Defender update tasks triggering PowerShell | `NOT (User="NT AUTHORITY\\SYSTEM" AND ParentImage="*\\MsMpEng.exe")` |
| 4 | Developer workstations | VS Code terminal sessions using bypass | `NOT ComputerName IN ("DEV-*")` (scope to dev OU) |

---

## DET-002 — Brute Force Login

| # | FP Scenario | Trigger Condition | Recommended Exclusion |
|---|------------|-----------------|----------------------|
| 1 | Stale service account password | Service account authenticating with cached expired password | Exclude specific service account SAMAccountNames from threshold |
| 2 | Post-password-change device sync | Mobile device with cached old credentials retrying multiple times | Correlate IpAddress with MDM inventory — exclude known device IPs |
| 3 | Testing/helpdesk | Support staff testing account lockout | Time-window exclusion during ticketed maintenance window |

---

## DET-004 — Scheduled Task Persistence

| # | FP Scenario | Trigger Condition | Recommended Exclusion |
|---|------------|-----------------|----------------------|
| 1 | Windows Update | WU creates tasks with PowerShell/CMD actions | `NOT SubjectUserName="SYSTEM" NOT TaskName IN ("*WindowsUpdate*","*MicrosoftEdge*","*OneDrive*")` |
| 2 | Software installers | Legitimate apps create tasks at install time | Review task name against installed software inventory; build allowlist |
| 3 | Monitoring agents | IT monitoring tools create scheduled check-in tasks | Exclude known monitoring software task names |

---

## DET-005 — Registry Run Key Persistence

| # | FP Scenario | Trigger Condition | Recommended Exclusion |
|---|------------|-----------------|----------------------|
| 1 | Common consumer apps | Dropbox, OneDrive, Teams, Zoom write Run keys during install/update | `NOT Image IN ("*\\Dropbox*","*\\OneDrive*","*\\Teams*","*\\Zoom*")` |
| 2 | Group Policy | GP applies startup entries via `HKLM\...\Run` | Exclude SYSTEM-context writes from known GP paths |
| 3 | Software updates | Auto-updater rewrites Run key entry | Build a lookup of approved Run key values vs. actual Run key entries |

---

## DET-008 — DNS/HTTP Beacon-like Traffic

| # | FP Scenario | Trigger Condition | Recommended Exclusion |
|---|------------|-----------------|----------------------|
| 1 | Cloud sync clients | OneDrive, Google Drive, Dropbox make periodic check-ins | `NOT Image IN ("*\\OneDrive.exe","*\\Dropbox.exe","*\\googledrivesync.exe")` |
| 2 | AV cloud lookups | Defender/AV making regular cloud reputation queries | Exclude AV process names |
| 3 | Windows telemetry | OS telemetry making regular connections to Microsoft | Exclude known Microsoft IP ranges or use `NOT DestinationHostname="*microsoft.com"` |
| 4 | IT monitoring agents | Monitoring agents with 60s check-in intervals | Exclude known monitoring agent process names and server IPs |

---

## Tuning Philosophy

1. **Never tune blindly.** Every exclusion should be documented with the specific trigger, the process that caused it, and the business justification.
2. **Exclusions should be as narrow as possible.** `NOT User="admin_account"` is better than `NOT User IN ("*")`.
3. **Re-validate after tuning.** After adding an exclusion, manually trigger the simulated attack and confirm the detection still fires.
4. **Track exclusion drift.** Review the exclusion list quarterly. Stale exclusions for removed software or departed staff create blind spots.
5. **Volume is not a reason to suppress.** If a detection is firing too frequently, the answer is a better exclusion — not raising the threshold until it stops alerting.
