# Lesson 6.2: Hands-On Incident Investigation
**Date:** 2026-02-24
**Duration:** ~3 hours
**Platform:** Azure ELK Stack + Python SOC Agent (Claude AI)

---

## Objectives Completed

- [x] Simulated a realistic multi-phase attack on Active Directory environment
- [x] Conducted AI-assisted triage, scoping, and deep analysis
- [x] Built a chronological attack timeline from raw log data
- [x] Identified all IOCs from the incident
- [x] Documented detection gaps discovered during investigation
- [x] Followed NIST IR lifecycle: Detection → Analysis → Containment → Documentation

---

## Attack Simulation

A four-phase attack was executed against WinTarget-VM (soclab.local DC) to generate realistic incident data.

| Phase | Technique | MITRE | Expected Event |
|-------|-----------|-------|----------------|
| 1 | Brute force via PrincipalContext.ValidateCredentials | T1110.001 | Event 4625 |
| 2 | Successful login with known credentials | T1078 | Event 4624/4648 |
| 3 | Post-compromise recon (whoami, net, ipconfig) | T1087/T1016 | Sysmon Event 1 |
| 4 | Persistence via scheduled task | T1053.005 | Event 4698 |

---

## Investigation

### Step 1: Triage - Brute Force Detection

**SOC Agent Prompt:** "Analyze all failed login attempts for svc-backup in the last 1 hour and determine if we're under attack"

**Agent Verdict: HIGH - CONFIRMED BRUTE FORCE ATTACK**

**Evidence Found:**
- 8 failed login attempts in 2 seconds (22:23:18-22:23:20 UTC)
- Source: Internal IP 10.0.1.7
- Target: svc-backup service account
- Method: Automated NTLM authentication via PrincipalContext API
- Rate: 4 attempts/second - clearly automated

**MITRE Mapping:** T1110.001 - Password Guessing

---

### Step 2: Scoping - Post-Compromise Activity

**SOC Agent Prompt:** "Check if svc-backup had any successful logins in the last hour and what activity happened after"

**Agent Verdict: MEDIUM - Credential Exposure + Active Recon**

**Evidence Found:**
- Successful login at 22:10:08 UTC via `net use \\localhost\IPC$ /user:SOCLAB\svc-backup TestPass123!`
- **Critical finding:** Password exposed in plaintext on command line (Sysmon Event 1)
- Recon commands executed at 22:10:19 UTC by azureuser from PowerShell ISE:
  - `whoami /all` - privilege enumeration (T1033)
  - `net user /domain` - domain user discovery (T1087.002)
  - `net localgroup administrators` - local group enumeration (T1069.001)
  - `ipconfig /all` - network configuration discovery (T1016)

---

### Step 3: Process Hunt

**SOC Agent Prompt:** "Search for suspicious process execution on WinTarget-VM in the last 1 hour"

**Result:** 0 events returned

**Root Cause:** The `query_suspicious_processes_elk` function had wrong field name (`process.name` instead of `winlog.event_data.CommandLine`). Fixed during lesson. Also: the recon commands were run under `azureuser` context via PowerShell ISE, not directly under `svc-backup`, so the session correlation was needed.

---

### Step 4: Persistence Check

**SOC Agent Prompt:** "Query for scheduled task creation events (Event ID 4698) on WinTarget-VM in the last 1 hour"

**Result:** 0 events returned

**Root Cause (Detection Gap):** Event ID 4698 requires the "Audit Other Object Access Events" policy to be enabled under Advanced Audit Policy. This is NOT enabled by default on Azure VMs. The scheduled task `WindowsUpdateHelper` was successfully created on the system but generated no log event - a real blind spot in the monitoring configuration.

**Remediation:** Enable via Group Policy:
```
Computer Configuration → Windows Settings → Security Settings →
Advanced Audit Policy Configuration → Object Access →
Audit Other Object Access Events → Success + Failure
```

---

## Attack Timeline

| Time (UTC) | Event ID | Description | MITRE |
|------------|----------|-------------|-------|
| 22:10:08 | 4624/4648 | svc-backup successful network logon from localhost; password in cleartext on cmdline | T1078 |
| 22:10:19 | Sysmon 1 | `whoami /all` - privilege enumeration | T1033 |
| 22:10:19 | Sysmon 1 | `net user /domain` - domain user discovery | T1087.002 |
| 22:10:19 | Sysmon 1 | `net localgroup administrators` - local group enumeration | T1069.001 |
| 22:10:19 | Sysmon 1 | `ipconfig /all` - network config discovery | T1016 |
| 22:23:18-20 | 4625 x8 | Brute force - 8 failed logins in 2 seconds from 10.0.1.7 | T1110.001 |
| N/A | (none) | Scheduled task `WindowsUpdateHelper` created - no log generated (audit gap) | T1053.005 |

---

## Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| Account | svc-backup | Targeted in brute force; credentials exposed in cmdline |
| Internal IP | 10.0.1.7 | Source of brute force authentication attempts |
| Credential exposure | TestPass123! | Found in plaintext in Sysmon Event 1 CommandLine |
| Persistence | WindowsUpdateHelper | Scheduled task created for persistence (unlogged) |
| Technique | NTLM brute force | PrincipalContext.ValidateCredentials at 4 attempts/sec |

---

## Containment Actions (Simulated)

1. Reset svc-backup password immediately
2. Remove scheduled task `WindowsUpdateHelper`
3. Investigate 10.0.1.7 for signs of compromise
4. Review all accounts that authenticated from 10.0.1.7 in the past 30 days
5. Enable "Audit Other Object Access Events" to close the scheduled task blind spot
6. Implement account lockout policy for service accounts (5 failures / 15 min)

---

## Detection Gaps Found

| Gap | Impact | Fix |
|-----|--------|-----|
| Event 4698 not logged | Scheduled task persistence is invisible | Enable Audit Other Object Access Events GPO |
| Service account cmdline logging | Credentials can appear in Sysmon logs | Implement credential guard; avoid net use with inline passwords |
| No lockout on service accounts | Brute force ran to completion | Configure Fine-Grained Password Policy for service accounts |

---

## AI vs. Manual Comparison

The SOC agent correctly:
- Detected the brute force and rated it HIGH
- Found credential exposure in Sysmon CommandLine data
- Correlated the recon commands to the post-compromise window
- Provided MITRE mappings and remediation steps automatically

The SOC agent missed:
- Scheduled task creation (audit policy gap - no data to find)
- Initial correlation between recon user (azureuser) and compromised account (svc-backup) without follow-up prompting

**Conclusion:** AI triage is highly effective for authentication-based attacks with good log coverage. Detection gaps in audit policy are invisible to both AI and manual analysis - the gap must be fixed at the infrastructure level.

---

## Proof

- `Proof/lesson-6.2-brute-force-detected.png` - Agent output: HIGH severity brute force detection
- `Proof/lesson-6.2-post-compromise-recon.png` - Agent output: Successful login + recon activity correlated
