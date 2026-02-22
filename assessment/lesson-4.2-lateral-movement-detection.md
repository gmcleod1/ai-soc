# Lesson 4.2 Assessment: Lateral Movement Detection

## Assignment: Detect and Analyze Lateral Movement Techniques

---

## Lab Setup

- **Tool:** PowerShell `net use`, `cmdkey`, `wmic` on WinTarget-VM
- **Detection Stack:** Sysmon + Winlogbeat -> Elasticsearch -> Kibana
- **Data View:** `winlogbeat-*`
- **Techniques Simulated:** T1078 (Valid Accounts), T1021.002 (SMB/Windows Admin Shares), T1047 (WMI)

---

## What is Lateral Movement?

After gaining initial access to one machine, attackers move to other systems on the network to expand their foothold, reach higher-value targets, or find data to exfiltrate. Lateral movement leaves a trail across multiple event IDs that, when correlated, reveal the attacker's path through the network.

---

## Attack Simulation

### Commands Executed

```powershell
# 1. Explicit credential use (T1078)
cmdkey /add:fake-server /user:admin /pass:Password123!
net use \\fake-server\c$ /user:admin Password123!

# 2. WMI local execution (T1047)
wmic process call create "notepad.exe"

# 3. Network share access (T1021.002)
net use \\127.0.0.1\c$ /user:SOCLAB\azureuser QMrXFPUnqi88UQi1S4kBAa1!
```

---

## Hunt Queries and Results

### Query 1 - Explicit Credential Use (Event 4648)

```
event.code:4648
```

**Results:** 10 hits

**Key Finding:** `azureuser` authenticated explicitly to `localhost` at 19:06 - the attacker testing credentials before using them on a remote target.

**Fields observed:**
- `winlog.event_data.TargetUserName`: azureuser
- `winlog.event_data.TargetServerName`: localhost

**Proof:** `Proof/lesson-4.2-query1-4648.png`

---

### Query 2 - Network Logon (Event 4624 LogonType 3)

```
event.code:4624 AND winlog.event_data.LogonType:3
```

**Results:** 249 hits

**Key Finding:** Majority are `WinTarget-VM$` machine account logons (normal AD background traffic). Attacker's `net use \\127.0.0.1\c$` is present but buried in machine account noise.

**Tuning to reduce noise:**
```
event.code:4624 AND winlog.event_data.LogonType:3 AND NOT winlog.event_data.TargetUserName:*$*
```

**Proof:** `Proof/lesson-4.2-query2-logontype3.png`

---

### Query 3 - WMI Process Execution (Sysmon Event 1)

```
event.code:1 AND winlog.event_data.ParentImage:*WmiPrvSE.exe*
```

**Results:** 1 hit

**Key Finding:** `C:\Windows\System32\wbem\WmiPrvSE.exe` spawned a process at 20:05. This is the exact signature of WMI-based remote execution - an attacker technique that blends into Windows background activity.

**Why this matters:** Legitimate software rarely spawns processes via WmiPrvSE. Any `WmiPrvSE -> cmd.exe` or `WmiPrvSE -> powershell.exe` relationship is highly suspicious.

**Proof:** `Proof/lesson-4.2-query3-wmi.png`

---

### Query 4 - Combined Attack Timeline

```
(event.code:4648 OR (event.code:4624 AND winlog.event_data.LogonType:3) OR (event.code:1 AND winlog.event_data.ParentImage:*WmiPrvSE.exe*)) AND @timestamp > now-2h
```

**Results:** 297 events sorted chronologically

**Attack timeline reconstructed:**

| Time | Event | Actor | Target | Technique |
|---|---|---|---|---|
| 19:01 | 4648 | UMFD/DWM system accounts | localhost | Background (noise) |
| 19:02 | 4624 Type 3 | WinTarget-VM$ | - | AD machine logons (noise) |
| 19:06 | 4648 | azureuser | localhost | Explicit credential test |
| 19:06 | 4624 Type 3 | azureuser | 127.0.0.1 | SMB share access attempt |
| 20:05 | Sysmon 1 | WmiPrvSE.exe | WinTarget-VM | WMI process execution |

**Proof:** `Proof/lesson-4.2-combined-timeline.png`

---

## Lateral Movement Technique Reference

| Technique | MITRE ID | Event IDs | Detection Query | FP Rate |
|---|---|---|---|---|
| Explicit credentials | T1078 | 4648 | `event.code:4648 AND NOT TargetUserName:*$*` | Medium |
| SMB/Admin shares | T1021.002 | 4624 Type 3, 5145 | `event.code:4624 AND LogonType:3` | High (filter machine accounts) |
| WMI execution | T1047 | Sysmon 1 | `ParentImage:*WmiPrvSE.exe*` | Low |
| RDP | T1021.001 | 4624 Type 10 | `event.code:4624 AND LogonType:10` | Medium |
| Pass-the-Hash | T1550.002 | 4624 Type 3 | NTLM auth + no prior password event | High |

---

## Detection Playbook

### Step 1 - Initial Triage
```
# Check for explicit credential use in last hour
event.code:4648 AND NOT winlog.event_data.TargetUserName:*$*

# Look for unusual network logons
event.code:4624 AND winlog.event_data.LogonType:3 AND NOT winlog.event_data.TargetUserName:*$*
```

### Step 2 - Confirm WMI Execution
```
# Any process spawned by WMI provider
event.code:1 AND winlog.event_data.ParentImage:*WmiPrvSE.exe*

# Especially suspicious child processes
event.code:1 AND winlog.event_data.ParentImage:*WmiPrvSE.exe* AND winlog.event_data.Image:(*cmd.exe* OR *powershell.exe* OR *wscript.exe*)
```

### Step 3 - Build Timeline
```
# Correlate all lateral movement indicators
(event.code:4648 OR (event.code:4624 AND winlog.event_data.LogonType:3) OR (event.code:1 AND winlog.event_data.ParentImage:*WmiPrvSE.exe*))
```
Sort ascending by `@timestamp`, filter to the suspect username and timeframe.

### Step 4 - Identify Source and Destination
- Source: `winlog.event_data.IpAddress` on the 4624 event
- Destination: `agent.hostname` (the machine logging the event)
- Actor: `winlog.event_data.TargetUserName`

### Step 5 - Response Actions
1. Isolate affected endpoints (source and destination)
2. Reset compromised account credentials
3. Review all systems the account authenticated to (Event 4624 history)
4. Check for persistence mechanisms on affected systems (scheduled tasks, new accounts, registry run keys)
5. Determine initial access vector - lateral movement means there is already a compromised machine

---

## Key Takeaways

1. **Lateral movement always leaves a trail** - credential use (4648), network logons (4624 Type 3), and remote execution (WmiPrvSE) together tell the full story
2. **Machine account noise is real** - filter `*$*` usernames to surface human attacker activity
3. **WmiPrvSE as parent = red flag** - legitimate software almost never spawns processes this way
4. **Correlation across event IDs is the skill** - no single event proves lateral movement, but together they do
5. **The combined timeline query is your most powerful tool** - it reconstructs the attacker's path through the network in chronological order
