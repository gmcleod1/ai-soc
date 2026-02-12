# Lesson 3.2 Assessment: Atomic Red Team Attack Simulation

## Assignment: Run 3 Attack Simulations, Document Detection Queries

---

## Lab Setup

- **Tool:** Atomic Red Team (invoke-atomicredteam) installed on WinTarget-VM
- **Detection Stack:** Sysmon -> Winlogbeat -> Elasticsearch -> Kibana
- **Data View:** `winlogbeat-*`

### Setup Challenges Encountered

**Windows Defender Blocking Installation:**
The Atomic Red Team atomics folder download was blocked by Windows Defender (virus detection on test payloads). Resolution: Added `C:\AtomicRedTeam` to Defender exclusion paths via `Add-MpPreference -ExclusionPath`.

**T1003.001 LSASS Dump - Blocked by Azure Protections:**
Azure VMs have multiple kernel-level protections (LSA Protection/RunAsPPL, Credential Guard, Virtualization-Based Security) that block LSASS process access even with Administrator privileges and Defender disabled. This is a real-world example of defense-in-depth - the attack was blocked at the OS kernel level, not just by antivirus.

**Atomic Test Definitions Incomplete:**
Due to Defender intercepting the download, the atomics folder was incomplete (`Found 0 atomic tests applicable to windows platform`). Solution: Executed attack commands manually, which is actually closer to real attacker behavior than using a framework.

**Key Takeaway:** These setup challenges mirror real red team operations - attackers constantly deal with endpoint protections blocking their tools.

---

## Simulation 1: T1087.001 - Account Discovery

**Tactic:** Discovery (TA0007)

**What was executed:**
```powershell
net user
net localgroup administrators
whoami /all
systeminfo
```

**What an attacker gains:** A complete picture of the system - who has access, what groups exist, OS version/patch level, network configuration. This is always the first step after initial access.

**Detection Query:**
```
event.code:1 AND winlog.event_data.CommandLine:*net*user*
```

**What Kibana showed:**
- Multiple Sysmon Event ID 1 (Process Creation) events
- Full command lines visible including `net user`, `net localgroup`, `whoami /all`
- Parent process: `powershell.exe` (our admin PowerShell session)
- All commands executed by `azureuser`

**Detection Rule:**
```
Name: Reconnaissance - Account Enumeration
Query: event.code:1 AND winlog.event_data.CommandLine:(*net user* OR *net localgroup* OR *whoami* OR *systeminfo*)
Severity: Medium
MITRE: T1087.001
Note: Filter out IT admin accounts to reduce false positives
```

**Proof:** `Proof/lesson-3.2-t1087-account-discovery.png`

---

## Simulation 2: T1136.001 - Create Local Account

**Tactic:** Persistence (TA0003)

**What was executed:**
```powershell
net user AtomicTestUser Password123! /add
net localgroup administrators AtomicTestUser /add
```

**What an attacker gains:** A backdoor account with admin privileges that survives reboots. The attacker can return via RDP anytime without needing malware.

**Detection Query:**
```
event.code:4720
```

**What Kibana showed:**
- Event 4720 (User Account Created) - `AtomicTestUser` created
- Event 4722 (User Account Enabled)
- Event 4732 (Member Added to Security-Enabled Local Group) - added to Administrators
- Full attack chain visible: create -> enable -> escalate

**Detection Rule:**
```
Name: Backdoor Account - New User Added to Administrators
Query: event.code:(4720 OR 4732)
Severity: High
MITRE: T1136.001
Response: Verify with IT team, disable account if unauthorized
```

**Sysmon-based detection (alternative):**
```
event.code:1 AND winlog.event_data.CommandLine:(*net*user*/add*)
```

**Proof:** `Proof/lesson-3.2-t1136-account-creation.png`

---

## Simulation 3: T1053.005 - Scheduled Task Persistence

**Tactic:** Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004)

**What was executed:**
```powershell
schtasks /create /tn "AtomicTask" /tr "cmd.exe /c whoami" /sc once /st 23:59 /ru SYSTEM
```

**What an attacker gains:** Code execution that survives reboots, runs under SYSTEM context (highest privilege), and can be triggered on schedule or at logon.

**Detection Query:**
```
event.code:1 AND winlog.event_data.CommandLine:*schtasks*
```

**What Kibana showed:**
- Sysmon Event ID 1 captured the full `schtasks /create` command
- Task name "AtomicTask" visible in command line
- `/ru SYSTEM` flag visible - running as SYSTEM is a privilege escalation indicator
- Parent process shows it originated from our PowerShell session

**Detection Rule:**
```
Name: Suspicious Scheduled Task - Potential Persistence
Query: event.code:1 AND winlog.event_data.CommandLine:(*schtasks* AND *create*)
Tuned: event.code:1 AND winlog.event_data.CommandLine:(*schtasks* AND *create*) AND NOT winlog.event_data.CommandLine:(*Microsoft* OR *Windows*)
Severity: Medium-High
MITRE: T1053.005
Response: Review task details, verify legitimacy, delete if malicious
```

**Proof:** `Proof/lesson-3.2-t1053-scheduled-task.png`

---

## Simulation 4: T1059.001 - Encoded PowerShell Execution

**Tactic:** Execution (TA0002)

**What was executed:**
```powershell
$command = "whoami; ipconfig; net user"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell -enc $encoded
```

**What an attacker gains:** Ability to execute arbitrary code while evading signature-based detection. The base64 encoding hides the actual commands from simple string-matching rules.

**Detection Query:**
```
event.code:1 AND winlog.event_data.CommandLine:*-enc*
```

**What Kibana showed:**
- Sysmon Event ID 1 with full command line including the `-enc` flag
- The base64-encoded payload visible in the CommandLine field
- A SOC analyst would decode this to reveal: `whoami; ipconfig; net user`

**How to decode (for investigation):**
```powershell
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("BASE64_STRING_HERE"))
```

**Detection Rule:**
```
Name: PowerShell Obfuscation - Encoded Command
Query: event.code:1 AND winlog.event_data.CommandLine:(*-enc* OR *-EncodedCommand* OR *-ExecutionPolicy Bypass* OR *-WindowStyle Hidden* OR *DownloadString* OR *IEX*)
Severity: High
MITRE: T1059.001
Response: Decode the base64 payload, assess intent, trace parent process
```

**Proof:** `Proof/lesson-3.2-t1059-encoded-powershell.png`

---

## Attack Chain Summary

If these were real attacks (not simulations), the kill chain would look like:

```
1. Initial Access     → Attacker gains RDP access (T1021.001)
2. Discovery          → net user, whoami, systeminfo (T1087.001)
3. Persistence        → Create backdoor account (T1136.001)
4. Privilege Esc.     → Add to Administrators + SYSTEM scheduled task (T1053.005)
5. Execution          → Encoded PowerShell for stealth (T1059.001)
6. Credential Access  → LSASS dump BLOCKED by Azure protections (T1003.001)
```

The attacker was stopped at step 6 by defense-in-depth (LSA Protection). But steps 1-5 all succeeded and were all detectable in our SIEM.

## Detection Matrix

| Technique | ATT&CK ID | Event ID | KQL Query | Severity |
|-----------|-----------|----------|-----------|----------|
| Account Discovery | T1087.001 | Sysmon 1 | `winlog.event_data.CommandLine:*net*user*` | Medium |
| Create Account | T1136.001 | 4720, 4732 | `event.code:(4720 OR 4732)` | High |
| Scheduled Task | T1053.005 | Sysmon 1 | `winlog.event_data.CommandLine:*schtasks*create*` | Medium-High |
| Encoded PowerShell | T1059.001 | Sysmon 1 | `winlog.event_data.CommandLine:*-enc*` | High |
| LSASS Dump | T1003.001 | Sysmon 10 | `winlog.event_data.TargetImage:*lsass.exe` | Critical |

## Cleanup

After the exercise, the following cleanup was performed on WinTarget-VM:
```powershell
# Remove test user
net user AtomicTestUser /delete

# Remove scheduled task
schtasks /delete /tn "AtomicTask" /f

# Re-enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
```

## Key Takeaway

Attack simulation is the only way to **prove** your detections work. Writing a detection rule on paper means nothing until you trigger the actual attack and confirm the alert fires. Atomic Red Team (or manual simulation) closes the loop: Attack -> Detect -> Validate -> Improve.
