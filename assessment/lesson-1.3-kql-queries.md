# Lesson 1.3 Assignment: 5 KQL Security Scenario Queries

## 1. Detect Brute Force Attempts (Multiple Failed Logins)
```
event.code:4625 AND winlog.event_data.TargetUserName:*
```
**Scenario:** An attacker is trying to guess passwords by repeatedly attempting logins. Filter for Event ID 4625 and check the `winlog.event_data.TargetUserName` field to see which accounts are being targeted. A high count against a single user in a short timeframe indicates brute force.

**What to look for:** Multiple 4625 events targeting the same account within minutes.

---

## 2. Detect New User Account Creation
```
event.code:4720
```
**Scenario:** An attacker who has gained admin access may create a backdoor account for persistence. Event ID 4720 fires when a new user account is created. This should be rare on a production server -- any unexpected account creation warrants immediate investigation.

**What to look for:** Unexpected accounts created outside of normal admin change windows.

---

## 3. Detect Suspicious Process Execution via Sysmon
```
event.code:1 AND winlog.event_data.Description:("Windows PowerShell" OR "Windows Command Processor")
```
**Scenario:** Attackers commonly use PowerShell and cmd.exe for post-exploitation. Sysmon Event ID 1 captures process creation with full command lines. Filter for shell interpreters to find potentially malicious command execution.

**What to look for:** PowerShell with encoded commands (`-enc`), cmd.exe spawned by unusual parent processes.

---

## 4. Detect RDP Logons from External Sources
```
event.code:4624 AND winlog.event_data.LogonType:10
```
**Scenario:** Logon Type 10 is RemoteInteractive (RDP). After stealing credentials, attackers often RDP into systems. Monitor all RDP logons and correlate the source IP against known admin workstations. Any RDP from an unexpected IP is suspicious.

**What to look for:** RDP logons at unusual hours, from unexpected IPs, or to accounts that don't normally use RDP.

---

## 5. Detect Privilege Escalation via Group Membership Changes
```
event.code:(4732 OR 4728)
```
**Scenario:** Event ID 4732 (member added to local group) and 4728 (member added to domain group) indicate privilege changes. An attacker may add their compromised account to the Administrators group. Any group membership change to privileged groups should trigger an alert.

**What to look for:** Accounts being added to Administrators, Remote Desktop Users, or other privileged groups unexpectedly.

---

## Key Lessons Learned

- **Field names matter:** Winlogbeat uses `winlog.event_data.*` fields, not always ECS fields like `user.name`. Always verify field names in the Discover sidebar before building queries.
- **Not all events are enabled by default:** Event ID 4688 (Process Creation) requires audit policy changes. Sysmon Event ID 1 is a better alternative with richer data.
- **Query broad, then narrow:** Start with `event.code:XXXX` to confirm data exists, then add `AND`/`NOT` filters to drill down.
- **Empty fields:** Some fields like `winlog.event_data.IpAddress` may not be populated for all logon types. Use alternative fields (e.g., LogonType) when needed.
