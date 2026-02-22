# Lesson 4.1 Assessment: Brute Force Attack Detection

## Assignment: Detect and Analyze a Password Spray Attack

---

## Lab Setup

- **Tool:** PowerShell `Start-Process -Credential` on WinTarget-VM
- **Detection Stack:** Winlogbeat -> Elasticsearch -> Kibana
- **Data View:** `winlogbeat-*`
- **Attack Type:** Password spray (T1110.003) - one password against multiple accounts

---

## Attack Simulation

### What Was Executed

```powershell
# Password Spray - 10 fake users, 1 attempt each
$users = 1..10 | ForEach-Object { "testuser$_" }
foreach ($user in $users) {
    $cred = New-Object System.Management.Automation.PSCredential(
        $user,
        (ConvertTo-SecureString "WrongPass123!" -AsPlainText -Force)
    )
    try {
        Start-Process cmd.exe -Credential $cred -ErrorAction Stop
    } catch { }
    Start-Sleep -Seconds 2
}
```

### What an Attacker Gains

Password spraying avoids account lockouts by attempting only 1-2 passwords per account. Attackers use it to find valid credentials across a large user base while staying under lockout thresholds. It is especially effective against organizations with predictable password patterns (e.g., `Company2024!`).

---

## Hunt in Kibana

### Discovery Query

```
event.code:4625
```

**Results:** 21 events in the last hour - 10 from the simulation plus pre-existing noise.

### Key Fields Observed

| Field | Value | Meaning |
|---|---|---|
| `winlog.event_data.TargetUserName` | testuser1-10 | 10 different accounts targeted |
| `winlog.event_data.IpAddress` | `::1` (IPv6 loopback) | Attack ran locally on the VM |
| `winlog.event_data.SubStatus` | `0xc0000064` | User does not exist |
| `winlog.event_data.LogonType` | `2` | Interactive logon attempt |

**SubStatus Reference:**
- `0xC0000064` - Username does not exist
- `0xC000006A` - Wrong password (user exists)
- `0xC0000234` - Account locked out
- `0xC000006F` - Outside allowed logon hours

---

## Visualizations

### Visualization 1 - Failed Login Timeline

**Chart:** Bar, `@timestamp` on X-axis, Count on Y-axis

**Finding:** Massive spike at 19:08 lasting ~18 seconds with near-zero activity before and after. This tight burst pattern is characteristic of automated tooling, not manual attempts.

**Proof:** `Proof/lesson-4.1-vis1-timeline.png`

---

### Visualization 2 - Top Failed Usernames

**Chart:** Bar, Top values of `winlog.event_data.TargetUserName`

**Finding:** All 10 accounts hit exactly twice - perfectly uniform distribution. This is the defining signature of a **password spray** vs a **brute force**:

| Attack Type | Pattern |
|---|---|
| Password Spray | Many accounts, few attempts each (even distribution) |
| Brute Force | One account, many attempts (single spike) |
| Credential Stuffing | Many accounts, matching known username/password pairs |

**Proof:** `Proof/lesson-4.1-vis2-usernames.png`

---

### Visualization 3 - Sub-Status Breakdown

**Chart:** Bar, Top values of `winlog.event_data.SubStatus`

**Finding:** 100% `0xc0000064` - attacker was guessing usernames that do not exist in Active Directory. In a real attack against a known organization, an attacker would first enumerate valid usernames (T1087) before spraying.

**Proof:** `Proof/lesson-4.1-vis3-substatus.png`

---

### Visualization 4 - Failed Logins by LogonType

**Chart:** Bar, Top values of `winlog.event_data.LogonType`

**Finding:** 100% LogonType 2 (interactive). In a network-based attack this would show LogonType 3 (network) or LogonType 10 (RDP). LogonType 2 confirms the attack was executed locally on the machine.

**Proof:** `Proof/lesson-4.1-vis4-logontype.png`

---

## Attack Metrics

| Metric | Value |
|---|---|
| Total failed attempts | 21 |
| Unique usernames targeted | 10 |
| Unique source IPs | 1 (::1 - localhost) |
| Time span of attack | ~18 seconds |
| Average attempts per minute | ~33/min |
| Failure code | 0xc0000064 (user not found) |
| Attack classification | Password spray (T1110.003) |

---

## Detection Rule

```
Name: Brute Force - Password Spray Detected
Query: event.code:4625
Threshold: > 5 unique TargetUserName values from same IpAddress in 5 minutes
Severity: High
MITRE: T1110.003
Action: Alert SOC + block source IP at firewall
```

**Tuned version (reduce noise from service accounts):**
```
event.code:4625 AND NOT winlog.event_data.TargetUserName:(*$ OR ANONYMOUS*)
```

---

## Password Spray vs Brute Force - Key Differences

| Indicator | Password Spray | Brute Force |
|---|---|---|
| Accounts targeted | Many (10+) | One |
| Attempts per account | Few (1-3) | Many (hundreds) |
| Account lockout risk | Low (by design) | High |
| SubStatus pattern | Mix of 0xC0000064 and 0xC000006A | Mostly 0xC000006A |
| Timeline | Steady, spread out | Rapid burst against one account |
| Detection difficulty | Harder (low volume per account) | Easier (high volume threshold) |

---

## Incident Report

**Date:** 2026-02-21
**Time:** 19:08:41 - 19:08:59 UTC
**Severity:** High
**Classification:** Password Spray Attack (T1110.003)

**Summary:**
A password spray attack was detected targeting 10 user accounts on WinTarget-VM over an 18-second window. All authentication attempts failed with SubStatus `0xc0000064`, indicating the targeted usernames do not exist in Active Directory. The attack originated from localhost (::1), suggesting an attacker with existing local access was attempting lateral movement or privilege escalation by guessing additional account credentials.

**Affected Accounts:** testuser1 through testuser10 (nonexistent accounts)

**Source:** ::1 (localhost - attacker already on the machine)

**Recommended Response Actions:**
1. Investigate how the attacker obtained local access to the machine
2. Review other recent authentication events for successful logins
3. Check for new user accounts created (Event 4720)
4. Review process creation logs (Sysmon Event 1) for attacker tooling
5. Isolate the endpoint if active compromise is confirmed
6. Reset all local account passwords
7. Implement an account lockout policy (e.g., 5 failures in 10 minutes)

---

## Key Takeaways

1. **Password spray is designed to evade detection** - low volume per account stays under lockout thresholds
2. **Uniform distribution across accounts = spray** - uneven distribution = focused brute force
3. **SubStatus codes tell you what happened** - distinguish nonexistent users from wrong passwords
4. **LogonType identifies the attack vector** - 2=local, 3=network, 10=RDP
5. **Tight time bursts indicate automation** - 18 seconds for 10 attempts is not human typing speed
