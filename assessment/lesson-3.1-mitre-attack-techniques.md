# Lesson 3.1 Assessment: MITRE ATT&CK Technique Documentation

## Assignment: 5 Techniques with Detection Queries

---

### Technique 1: T1003.001 - OS Credential Dumping: LSASS Memory

**Tactic:** Credential Access (TA0006)

**What it does:**
Adversaries dump the memory of the LSASS process to extract plaintext passwords, NTLM hashes, and Kerberos tickets from logged-on users. Common tools include Mimikatz, ProcDump, and comsvcs.dll MiniDump. This is one of the most critical post-compromise techniques because stolen credentials enable lateral movement across the entire network.

**Real-world usage:**
- Sandworm Team (Russian GRU) used Mimikatz against Ukraine's power grid (2016)
- APT28 (Fancy Bear) uses MiniDump for LSASS extraction
- APT3 injected tools directly into lsass.exe

**How to detect it (Event IDs & Log Sources):**
- **Sysmon Event ID 10** (Process Access) - Primary detection
- Look for non-system processes opening handles to lsass.exe
- Key fields: `SourceImage`, `TargetImage`, `GrantedAccess`
- Access mask `0x1F0FFF` (PROCESS_ALL_ACCESS) is highly suspicious

**KQL query to hunt for it:**
```
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:(*svchost.exe OR *csrss.exe OR *wmiprvse.exe OR *MsMpEng.exe)
```

**Severity:** CRITICAL - Immediate investigation required

---

### Technique 2: T1110.003 - Brute Force: Password Spraying

**Tactic:** Credential Access (TA0006)

**What it does:**
Attacker tries a single common password (e.g., "Password1!", "Summer2026!") against many different user accounts. This avoids account lockout policies that trigger after multiple failures on a single account. If even one account uses that password, the attacker gains access.

**Sub-techniques of T1110:**
- T1110.001 - Password Guessing (one user, many passwords)
- T1110.002 - Password Cracking (offline hash cracking)
- T1110.003 - Password Spraying (one password, many users)
- T1110.004 - Credential Stuffing (leaked credential pairs)

**How to detect it (Event IDs & Log Sources):**
- **Event ID 4625** (Failed Logon) - Multiple failures across different usernames
- **Event ID 4624** (Successful Logon) - Success after the spray = compromise
- Key fields: `winlog.event_data.TargetUserName`, `winlog.event_data.IpAddress`, `winlog.event_data.LogonType`
- Pattern: >5 unique usernames failing from the same IP in <5 minutes

**KQL query to hunt for it:**
```
event.code:4625
```
Then aggregate by source IP and check for multiple unique `winlog.event_data.TargetUserName` values. Follow up with:
```
event.code:4624 AND winlog.event_data.IpAddress:"<suspicious-IP>"
```

**Severity:** HIGH - If followed by successful logon, escalate to CRITICAL

---

### Technique 3: T1059.001 - Command and Scripting Interpreter: PowerShell

**Tactic:** Execution (TA0002)

**What it does:**
Attackers abuse PowerShell to execute commands, download payloads, and run code entirely in memory (fileless malware). PowerShell is particularly dangerous because it's a legitimate admin tool (living off the land), has full .NET framework access, and can execute encoded/obfuscated commands to evade signature-based detection.

**Suspicious indicators:**
- `-EncodedCommand` or `-enc` (base64-encoded commands)
- `-WindowStyle Hidden` (hidden execution)
- `-ExecutionPolicy Bypass` (override security policy)
- `Invoke-Expression` / `IEX` (execute strings as code)
- `DownloadString` / `DownloadFile` (fetch remote payloads)
- Unusual parent process (e.g., excel.exe spawning powershell.exe)

**How to detect it (Event IDs & Log Sources):**
- **Sysmon Event ID 1** (Process Creation) - Command line arguments
- **PowerShell Script Block Logging** (Event ID 4104) - Full script content
- Key fields: `winlog.event_data.CommandLine`, `winlog.event_data.ParentImage`

**KQL query to hunt for it:**
```
event.code:1 AND winlog.event_data.Description:"Windows PowerShell" AND winlog.event_data.CommandLine:(*-enc* OR *-ExecutionPolicy Bypass* OR *-WindowStyle Hidden* OR *DownloadString* OR *Invoke-Expression* OR *IEX*)
```

**Severity:** HIGH - Encoded or downloading PowerShell is almost always malicious

---

### Technique 4: T1053.005 - Scheduled Task/Job: Scheduled Task

**Tactic:** Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004)

**What it does:**
Attackers create scheduled tasks to execute malicious code at specific times or intervals, surviving system reboots. Tasks can run under SYSTEM context (privilege escalation) or be triggered by user logon. Advanced attackers delete the Security Descriptor (SD) registry value to hide their tasks from normal enumeration.

**How to detect it (Event IDs & Log Sources):**
- **Event ID 4698** (Scheduled Task Created) - Primary detection
- **Sysmon Event ID 1** - `schtasks.exe` execution with `/create` parameter
- Look for tasks running under SYSTEM context
- Look for tasks executing from unusual directories (Temp, AppData, ProgramData)
- Monitor for `taskeng.exe` or `svchost.exe` spawning suspicious child processes

**KQL query to hunt for it:**
```
event.code:4698
```
And for the schtasks command itself:
```
event.code:1 AND winlog.event_data.CommandLine:(*schtasks* AND *create*)
```
Tuned version (exclude legitimate Windows tasks):
```
event.code:4698 AND NOT winlog.event_data.TaskName:(*Microsoft* OR *Windows*)
```

**Severity:** MEDIUM-HIGH - Depends on task content and execution context

---

### Technique 5: T1136.001 - Create Account: Local Account

**Tactic:** Persistence (TA0003)

**What it does:**
Attackers create new local accounts on compromised systems to maintain access. This provides a backdoor that doesn't require malware - the attacker simply RDPs or logs in with their new account. Often combined with T1098 (Account Manipulation) to add the new account to the Administrators group.

**Attack chain example:**
1. `net user backdoor P@ssw0rd123 /add` (T1136.001 - Create Account)
2. `net localgroup Administrators backdoor /add` (T1098 - Account Manipulation)
3. Attacker now has persistent admin access via RDP

**How to detect it (Event IDs & Log Sources):**
- **Event ID 4720** (User Account Created) - Primary detection
- **Event ID 4732** (Member Added to Security-Enabled Local Group) - Escalation
- **Sysmon Event ID 1** - `net.exe` or `net1.exe` with user creation arguments
- Key fields: `winlog.event_data.TargetUserName`, `winlog.event_data.SubjectUserName`

**KQL query to hunt for it:**
```
event.code:4720
```
Combined detection (creation + admin group add):
```
event.code:(4720 OR 4732)
```
Sysmon-based detection:
```
event.code:1 AND winlog.event_data.CommandLine:(*net* AND *user* AND */add*)
```

**Severity:** HIGH - Any unauthorized account creation requires immediate investigation

---

## Summary: ATT&CK Detection Matrix for This Lab

| Technique | Tactic | Primary Event ID | Severity |
|-----------|--------|-----------------|----------|
| T1003.001 LSASS Dump | Credential Access | Sysmon 10 | CRITICAL |
| T1110.003 Password Spray | Credential Access | 4625 (volume) | HIGH |
| T1059.001 PowerShell | Execution | Sysmon 1 | HIGH |
| T1053.005 Scheduled Task | Persistence | 4698 | MEDIUM-HIGH |
| T1136.001 Create Account | Persistence | 4720 | HIGH |

## Key Takeaway

The MITRE ATT&CK framework transforms raw Event IDs into a threat-intelligence-driven detection strategy. Instead of asking "what does Event 4625 mean?", you ask "am I seeing T1110 brute force behavior, and what does the attacker do NEXT in the kill chain?"

Next step: Lesson 3.2 will use Atomic Red Team to SIMULATE these techniques and detect them in Kibana.
