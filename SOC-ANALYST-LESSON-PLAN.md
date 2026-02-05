# SOC Analyst Training - Lesson Plan
**AI-Powered Security Operations Center Training Program**

---

## Overview

**Duration:** 8 weeks (40-50 hours total)
**Level:** Beginner to Intermediate
**Prerequisites:** Basic understanding of Windows, networking concepts
**Tools:** ELK Stack, Winlogbeat, Sysmon, Atomic Red Team, AI SOC Agent

**Learning Objectives:**
By the end of this course, you will be able to:
- Analyze Windows security events to detect threats
- Use the ELK stack for security monitoring
- Recognize MITRE ATT&CK techniques in logs
- Conduct threat hunting investigations
- Leverage AI to accelerate incident analysis
- Write detection rules and queries
- Generate professional incident reports

---

## Week 1: Foundations

### Lesson 1.1: Understanding Your SOC Lab Environment (2 hours)

**Objectives:**
- Understand the architecture of your ELK stack
- Navigate Kibana interface
- Understand log flow: Windows → Winlogbeat → Elasticsearch → Kibana

**Hands-On:**
1. Log into Kibana (http://YOUR-KIBANA-IP:5601)
2. Create your first data view:
   - Name: `filebeat-*`
   - Time field: `@timestamp`
3. Explore the Discover interface
4. Find your Elasticsearch VM's system logs
5. Identify the different log sources

**Success Criteria:**
- [ ] Can navigate Kibana Discover
- [ ] Can create and switch between data views
- [ ] Can filter logs by time range
- [ ] Understand the difference between filebeat and winlogbeat indices

**Assignment:**
- Document the IP addresses and components in your lab
- Screenshot your Kibana Discover showing Elasticsearch logs

---

### Lesson 1.2: Windows Event Logs Basics (3 hours)

**Objectives:**
- Understand Windows Event Log structure
- Learn critical Event IDs for security
- Read and interpret event fields

**Theory:**
- Event Log channels (Security, System, Application)
- Event ID numbering system
- Event levels (Information, Warning, Error, Critical)
- Key fields: Event ID, Source, Task Category, User

**Critical Event IDs Reference:**

| Event ID | Category | Meaning | SOC Importance |
|----------|----------|---------|----------------|
| 4624 | Logon | Successful logon | Baseline normal activity |
| 4625 | Logon | Failed logon | **Brute force detection** |
| 4672 | Privileges | Admin privileges assigned | **Privilege escalation** |
| 4688 | Process | Process creation | Malware execution |
| 4720 | Account | User account created | **Backdoor accounts** |
| 4732 | Group | User added to local group | **Privilege escalation** |
| 4648 | Logon | Explicit credential logon | **Lateral movement** |
| 4697 | Service | Service installed | **Persistence** |

**Hands-On:**
1. RDP into your Windows Target VM
2. Open Event Viewer (eventvwr.msc)
3. Navigate to Security logs
4. Find Event ID 4624 (your own successful logon)
5. Examine all fields in the event details
6. Generate a failed logon:
   ```cmd
   runas /user:fakeuser cmd.exe
   ```
7. Find the resulting Event ID 4625
8. Wait 2 minutes, then find the same event in Kibana

**Success Criteria:**
- [ ] Can locate specific Event IDs in Windows Event Viewer
- [ ] Can correlate Windows events with Kibana logs
- [ ] Understand the timeline delay between event generation and ELK ingestion
- [ ] Can identify key fields: user, source IP, logon type

**Assignment:**
Write a brief description of each critical Event ID and when you'd investigate it.

---

### Lesson 1.3: Kibana Query Language (KQL) Basics (3 hours)

**Objectives:**
- Learn KQL syntax
- Build effective search queries
- Filter and analyze logs

**KQL Fundamentals:**

```
Basic Syntax:
  field:value              → event.code:4625
  field:*partial*          → user.name:*admin*
  field > value            → process.pid > 1000
  field:(value1 OR value2) → event.code:(4624 OR 4625)

Boolean Operators:
  AND  → event.code:4625 AND user.name:admin
  OR   → source.ip:192.168.1.* OR source.ip:10.0.*
  NOT  → event.code:4624 NOT user.name:SYSTEM

Wildcards:
  *    → Matches any characters
  ?    → Matches single character
```

**Hands-On Exercises:**

1. **Find all failed logins:**
   ```
   event.code:4625
   ```

2. **Find failed logins for a specific user:**
   ```
   event.code:4625 AND user.name:"Administrator"
   ```

3. **Find all process creation events:**
   ```
   event.code:4688
   ```

4. **Find PowerShell executions:**
   ```
   event.code:4688 AND process.name:"powershell.exe"
   ```

5. **Find logons from external IPs:**
   ```
   event.code:4624 NOT source.ip:10.0.*
   ```

6. **Find administrative account changes:**
   ```
   event.code:(4720 OR 4722 OR 4724 OR 4732)
   ```

**Practice Scenario:**
Generate test events and find them:

```powershell
# On Windows VM - Generate 10 failed login attempts
for ($i=1; $i -le 10; $i++) {
    runas /user:fakeuser$i cmd.exe 2>$null
    Start-Sleep -Seconds 2
}
```

Then in Kibana:
- Find all 10 failed attempts
- Group by username
- Create a visualization showing failed logins over time

**Success Criteria:**
- [ ] Can write KQL queries without referring to notes
- [ ] Can filter logs to specific event types
- [ ] Can combine multiple conditions with AND/OR/NOT
- [ ] Can use wildcards effectively

**Assignment:**
Create 5 KQL queries for different security scenarios (e.g., detect new user creation, find admin group changes, search for suspicious processes).

---

## Week 2: Sysmon and Advanced Logging

### Lesson 2.1: Understanding Sysmon (3 hours)

**Objectives:**
- Understand what Sysmon provides beyond Windows Event Logs
- Learn Sysmon Event IDs
- Correlate Sysmon with Windows Security events

**Why Sysmon?**
- Windows Security logs: What happened at OS level
- Sysmon logs: HOW it happened (process details, network connections, registry changes)

**Critical Sysmon Event IDs:**

| Event ID | Type | Information Provided |
|----------|------|---------------------|
| 1 | Process Creation | Full command line, parent process, hashes |
| 3 | Network Connection | Source/dest IP, port, process |
| 7 | Image Loaded | DLLs loaded by processes |
| 8 | Create Remote Thread | Process injection detection |
| 10 | Process Access | Process reading another's memory |
| 11 | File Created | File creation with full path |
| 13 | Registry Set Value | Registry modifications |
| 22 | DNS Query | DNS lookups by process |

**Hands-On:**

1. **Deploy Windows VM with Sysmon:**
   ```bash
   ELK_PASSWORD=VpqpwvvtHRnfibtizZm1hvnFv ./deploy-windows-target.sh
   ```

2. **Create winlogbeat data view in Kibana:**
   - Pattern: `winlogbeat-*`
   - Time field: `@timestamp`

3. **Generate test Sysmon events:**
   ```powershell
   # Process creation (Event ID 1)
   notepad.exe

   # Network connection (Event ID 3)
   Test-NetConnection google.com -Port 443

   # DNS query (Event ID 22)
   nslookup microsoft.com
   ```

4. **Search for your events:**
   ```
   event.code:1 AND process.name:notepad.exe
   event.code:3 AND destination.ip:*
   event.code:22 AND dns.question.name:*
   ```

5. **Compare Event ID 4688 vs Sysmon Event ID 1:**
   - Both show process creation
   - Sysmon includes: full command line, parent process, file hash, GUIDs
   - Security log includes: limited info, requires additional audit policy

**Success Criteria:**
- [ ] Can explain the difference between Windows Security and Sysmon logs
- [ ] Can find process creation events in both log sources
- [ ] Understand when to use Sysmon vs Security logs
- [ ] Can identify parent-child process relationships

**Assignment:**
Run `cmd.exe` which launches `ipconfig.exe`. Find both events in Sysmon logs and document the parent-child relationship using ProcessGuid fields.

---

### Lesson 2.2: Command Line Analysis (3 hours)

**Objectives:**
- Recognize suspicious command-line patterns
- Detect obfuscated PowerShell
- Identify living-off-the-land techniques

**Suspicious Command Patterns:**

```powershell
# Credential Dumping
Invoke-Mimikatz
sekurlsa::logonpasswords
procdump -ma lsass.exe

# Reconnaissance
net user /domain
net group "domain admins" /domain
nltest /dclist:

# Lateral Movement
wmic /node:* process call create
psexec \\remote-host cmd.exe

# Persistence
schtasks /create /tn "Update" /tr "powershell.exe -WindowStyle Hidden"
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# Evasion
powershell -enc <base64>
powershell -ExecutionPolicy Bypass -WindowStyle Hidden
```

**Hands-On:**

1. **Generate suspicious PowerShell activity:**
   ```powershell
   # Recon commands
   whoami /all
   net user
   net localgroup administrators
   ipconfig /all

   # Encoded command (harmless)
   $command = "Write-Host 'Test'"
   $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
   $encoded = [Convert]::ToBase64String($bytes)
   powershell -enc $encoded
   ```

2. **Hunt for it in Kibana:**
   ```
   event.code:1 AND process.command_line:*whoami*
   event.code:1 AND process.command_line:*-enc*
   event.code:1 AND process.command_line:*net* AND process.command_line:*user*
   ```

3. **Analyze the parent process:**
   - Who launched these commands?
   - Was it a user-initiated action or scripted?
   - What other processes did the parent spawn?

**Detection Patterns:**

Create saved searches for:
- PowerShell with encoded commands
- Net commands (recon)
- Registry modifications for persistence
- WMI process creation on remote systems

**Success Criteria:**
- [ ] Can identify suspicious command-line patterns
- [ ] Can decode base64 PowerShell commands
- [ ] Understand "living off the land" techniques
- [ ] Can trace command execution back to the source user

**Assignment:**
Create a KQL query that detects ANY of these suspicious patterns in a single search.

---

## Week 3: MITRE ATT&CK Framework

### Lesson 3.1: Introduction to MITRE ATT&CK (2 hours)

**Objectives:**
- Understand the ATT&CK framework structure
- Map Event IDs to ATT&CK techniques
- Use ATT&CK for threat hunting

**Framework Structure:**
```
Tactics (Why?) → Techniques (What?) → Sub-Techniques (How?)

Example:
Tactic: Credential Access (TA0006)
  Technique: OS Credential Dumping (T1003)
    Sub-Technique: LSASS Memory (T1003.001)
```

**Key Tactics for SOC Analysts:**

1. **Initial Access (TA0001)** - How attackers get in
2. **Execution (TA0002)** - Running malicious code
3. **Persistence (TA0003)** - Maintaining access
4. **Privilege Escalation (TA0004)** - Getting higher permissions
5. **Credential Access (TA0006)** - Stealing passwords
6. **Discovery (TA0007)** - Learning about the environment
7. **Lateral Movement (TA0008)** - Moving to other systems
8. **Exfiltration (TA0010)** - Stealing data

**Mapping Event IDs to ATT&CK:**

| Event ID | Technique | Tactic | Detection |
|----------|-----------|--------|-----------|
| 4625 | T1110 - Brute Force | Credential Access | Multiple failures, same source |
| 4720 | T1136 - Create Account | Persistence | New user creation |
| 4648 | T1021 - Remote Services | Lateral Movement | Explicit credentials |
| 4697 | T1543.003 - Windows Service | Persistence | New service creation |

**Hands-On:**

1. Visit MITRE ATT&CK website: https://attack.mitre.org
2. Explore Technique T1003 (Credential Dumping)
3. Read the detection section
4. Map the detection to Event IDs you know

**Assignment:**
Choose 5 techniques and document:
- What the technique does
- How to detect it (Event IDs, log sources)
- KQL query to hunt for it

---

### Lesson 3.2: Atomic Red Team - Your First Attack Simulation (4 hours)

**Objectives:**
- Run controlled attack simulations
- Detect your own simulated attacks
- Build detection rules based on results

**Theory:**
Atomic Red Team provides small, repeatable tests for each MITRE ATT&CK technique.

**Hands-On Exercise: T1003.001 - LSASS Memory Dumping**

**Step 1: Understand the Technique**
- Attackers dump LSASS process memory to extract credentials
- Common tools: Mimikatz, ProcDump, Sysinternals
- Detection: Process access to lsass.exe

**Step 2: Run the Simulation**

```powershell
# RDP into Windows VM
# Open PowerShell as Administrator

Import-Module invoke-atomicredteam

# Show what the test does
Invoke-AtomicTest T1003.001 -ShowDetails

# Run test 2 (safe simulation)
Invoke-AtomicTest T1003.001 -TestNumbers 2
```

**Step 3: Hunt for Evidence in Kibana**

Wait 2-3 minutes for logs, then search:

```
# Sysmon Event 10 - Process Access
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe

# Check what process accessed LSASS
# Look for: SourceImage, GrantedAccess, CallTrace
```

**Step 4: Analyze the Event**

Key fields to examine:
- `SourceImage`: What process tried to access LSASS?
- `TargetImage`: Confirms it was lsass.exe
- `GrantedAccess`: What permissions were requested?
- `CallTrace`: Stack trace showing how it was called

**Step 5: Create Detection Rule**

Create a saved search:
```
Name: Credential Dumping - LSASS Access
Query: event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:*svchost.exe
Description: Detects non-system processes accessing LSASS memory
Severity: High
```

**Step 6: Test with SOC Agent**

```python
# In your local machine
python soc_agent.py

# When prompted, enter:
"Analyze the most recent LSASS process access attempts and determine if they are malicious"
```

The AI agent will:
- Query the ELK stack for Event ID 10 targeting lsass.exe
- Analyze the source process
- Check reputation of the process
- Provide a risk assessment

**Additional Simulations to Try:**

1. **T1087.001 - Account Discovery**
   ```powershell
   Invoke-AtomicTest T1087.001
   # Then search: event.code:4688 AND process.command_line:*net*user*
   ```

2. **T1136.001 - Create Local Account**
   ```powershell
   Invoke-AtomicTest T1136.001 -TestNumbers 1
   # Then search: event.code:4720
   ```

3. **T1053.005 - Scheduled Task**
   ```powershell
   Invoke-AtomicTest T1053.005 -TestNumbers 1
   # Then search: event.code:4698
   ```

**Success Criteria:**
- [ ] Can run Atomic tests without errors
- [ ] Can find resulting events in Kibana within 5 minutes
- [ ] Can identify malicious indicators in the logs
- [ ] Can use SOC agent to analyze the events

**Assignment:**
Run 3 different Atomic tests, document the technique, and create detection queries for each.

---

## Week 4: Threat Hunting

### Lesson 4.1: Brute Force Attack Detection (3 hours)

**Scenario:** Detect and analyze password brute force attempts

**Objectives:**
- Identify brute force patterns
- Calculate failure rates
- Determine source of attacks

**Theory:**
Brute force indicators:
- Multiple failed logons (Event 4625)
- Same source IP or username
- Short time window
- Different usernames (spray attack) or same username (focused attack)

**Hands-On:**

**Step 1: Generate Brute Force Traffic**

```powershell
# On Windows VM
# Simulate password spray attack (10 users, 1 password each)
$users = 1..10 | ForEach-Object { "testuser$_" }
foreach ($user in $users) {
    runas /user:$user "cmd.exe" 2>$null
    Start-Sleep -Seconds 3
}
```

**Step 2: Hunt in Kibana**

```
# Find all failed logins in last 15 minutes
event.code:4625 AND @timestamp > now-15m

# Aggregate by source IP
# Visualize: Terms aggregation on source.ip field
```

**Step 3: Analyze the Attack**

Create visualizations:
1. **Failed Login Timeline**: Line chart showing Event 4625 over time
2. **Top Failed Usernames**: Terms aggregation on user.name
3. **Failed Logins by IP**: Terms aggregation on source.ip
4. **Failure Sub-Status Codes**: Breakdown of why logins failed

**Step 4: Calculate Metrics**

```
# In Kibana, create these metrics:
- Total failed attempts
- Unique usernames targeted
- Unique source IPs
- Time span of attack
- Average attempts per minute
```

**Step 5: Use SOC Agent**

```python
python soc_agent.py

# Query:
"Query failed login attempts from the last hour and identify if this is a brute force attack. Provide statistics on the attack pattern."
```

The agent will:
- Pull Event 4625 logs
- Aggregate by IP and username
- Calculate failure rates
- Assess if it meets brute force thresholds
- Generate incident report

**Detection Rule:**

```
Name: Brute Force - Multiple Failed Logins
Query: event.code:4625
Threshold: > 5 failures from same IP in 5 minutes
Action: Alert + Block IP
```

**Success Criteria:**
- [ ] Can identify brute force in logs
- [ ] Can calculate attack statistics
- [ ] Can differentiate password spray vs credential stuffing
- [ ] Can use aggregations effectively

**Assignment:**
Generate a brute force attack simulation and create a complete incident report including: timeline, affected accounts, source IPs, recommended response actions.

---

### Lesson 4.2: Lateral Movement Detection (3 hours)

**Scenario:** Detect an attacker moving from one system to another

**Objectives:**
- Identify lateral movement techniques
- Track attacker timeline across systems
- Correlate events from multiple sources

**Lateral Movement Indicators:**

| Technique | Event IDs | Detection Pattern |
|-----------|-----------|-------------------|
| RDP | 4624 (Type 10) | Remote logon, unusual source |
| PsExec | 4624, 4688, 5145 | Service creation + process + file share |
| WMI | 4688, 4648 | wmic.exe with remote node parameter |
| Pass-the-Hash | 4624 (Type 3), 4648 | NTLM auth without password change |

**Hands-On:**

**Step 1: Simulate Lateral Movement**

```powershell
# Attempt to access remote share (will fail but generate logs)
net use \\nonexistent-server\c$ /user:admin password123

# WMI to localhost (simulates remote execution)
wmic process call create "notepad.exe"
```

**Step 2: Hunt for Evidence**

```
# Explicit credential use (Event 4648)
event.code:4648

# Network logon (Event 4624 Type 3)
event.code:4624 AND winlog.event_data.LogonType:3

# Process creation via WMI
event.code:4688 AND process.parent.name:WmiPrvSE.exe
```

**Step 3: Build Attack Timeline**

Create a table visualization:
1. Time
2. Event Code
3. User
4. Source IP
5. Process Name
6. Command Line

Sort chronologically to see attack progression.

**Step 4: Correlation Exercise**

Given these events, reconstruct the attack:
1. Event 4648 - User "admin" used explicit credentials
2. Event 4624 Type 3 - Network logon to remote system
3. Event 4688 - cmd.exe created via WmiPrvSE.exe
4. Event 4688 - whoami.exe executed

**Success Criteria:**
- [ ] Can identify different lateral movement techniques
- [ ] Can correlate events across time
- [ ] Can reconstruct attacker timeline
- [ ] Can identify source and target systems

**Assignment:**
Create a lateral movement detection playbook: what to look for, which queries to run, how to respond.

---

## Week 5: AI-Powered Analysis

### Lesson 5.1: Using Your SOC Agent (3 hours)

**Objectives:**
- Understand how the SOC agent works
- Use AI to accelerate investigations
- Interpret AI-generated reports

**Your SOC Agent Architecture:**

```
You → soc_agent.py → Claude AI → SOC Tools → ELK Stack
                         ↓
                   AI Analysis
                         ↓
                 Incident Report
```

**Available Tools:**

1. **query_elk_logs** - Search Elasticsearch
2. **query_failed_logins_elk** - Specialized failed login query
3. **query_suspicious_processes_elk** - Hunt for malicious processes
4. **aggregate_brute_force_attempts** - Brute force analysis
5. **check_ip_reputation** - Query AbuseIPDB
6. **lookup_cve** - Search CVE database
7. **check_file_hash** - VirusTotal lookup

**Hands-On Exercise 1: Basic Investigation**

```bash
# Start the agent
python soc_agent.py

# Enter this prompt:
"Analyze all failed login attempts in the last hour and tell me if we're under attack"
```

**What the AI does:**
1. Uses `query_failed_logins_elk` tool
2. Analyzes patterns in the data
3. Calculates statistics
4. Determines if it's anomalous
5. Provides recommendations

**Hands-On Exercise 2: Suspicious Process Hunt**

```bash
python soc_agent.py

# Prompt:
"Search for any PowerShell processes with encoded commands in the last 24 hours"
```

**What the AI does:**
1. Uses `query_suspicious_processes_elk`
2. Filters for powershell.exe with `-enc` parameter
3. Extracts command lines
4. Attempts to decode base64
5. Assesses maliciousness

**Hands-On Exercise 3: IP Reputation Check**

```bash
python soc_agent.py

# Prompt:
"Check the reputation of the IP address 103.224.182.251"
```

**What the AI does:**
1. Uses `check_ip_reputation` tool
2. Queries AbuseIPDB API
3. Returns abuse confidence score
4. Lists known malicious activities
5. Recommends blocking if high-risk

**Advanced Prompts to Try:**

```
"Find all process creation events where the parent process was cmd.exe and analyze if any are suspicious"

"Query for Event ID 4720 (account creation) and check if the new accounts are legitimate"

"Look for any Sysmon Event 10 where lsass.exe was accessed and determine if it's credential dumping"

"Find all Sysmon Event 3 (network connections) to external IPs and check their reputation"

"Analyze the last 100 process creation events and identify any that match MITRE ATT&CK techniques"
```

**Understanding AI Outputs:**

The agent will provide:
- **Summary** - High-level findings
- **Evidence** - Specific log entries
- **Analysis** - What the data means
- **Risk Assessment** - Severity level
- **Recommendations** - What to do next

**Success Criteria:**
- [ ] Can craft effective prompts for the SOC agent
- [ ] Understand when to use AI vs manual hunting
- [ ] Can validate AI findings against raw logs
- [ ] Can use multiple tools in sequence

**Assignment:**
Use the SOC agent to investigate your Atomic Red Team tests from Week 3. Compare AI analysis vs your manual analysis.

---

### Lesson 5.2: Building Custom Detection Logic (3 hours)

**Objectives:**
- Create custom KQL queries for specific threats
- Build detection rules
- Tune rules to reduce false positives

**Detection Rule Framework:**

```
Rule Components:
1. Name - Clear, descriptive
2. Description - What it detects
3. Query - KQL search
4. Threshold - How many matches = alert
5. Time Window - How long to look back
6. Severity - Critical/High/Medium/Low
7. MITRE Technique - Map to ATT&CK
8. Response - What to do when triggered
```

**Exercise: Create Detection Rules**

**Rule 1: Credential Dumping Detection**

```
Name: LSASS Memory Access - Credential Dumping
Description: Detects processes accessing LSASS memory, potential credential theft
Query: event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:(svchost.exe OR wmiprvse.exe OR csrss.exe)
Threshold: 1 event
Time Window: 1 minute
Severity: Critical
MITRE: T1003.001
Response: Isolate host, investigate process, check for credential theft
```

**Rule 2: Suspicious Scheduled Task**

```
Name: Scheduled Task Creation - Persistence
Description: Detects new scheduled task creation, often used for persistence
Query: event.code:4698
Threshold: 1 event
Time Window: 5 minutes
Severity: Medium
MITRE: T1053.005
Response: Review task details, verify legitimacy, delete if malicious
```

**Rule 3: Administrative Account Creation**

```
Name: New Administrator Account - Potential Backdoor
Description: Detects creation of new accounts added to Administrators group
Query: event.code:4732 AND group.name:"Administrators"
Threshold: 1 event
Time Window: 1 minute
Severity: High
MITRE: T1136.001
Response: Verify with IT team, disable account if unauthorized
```

**Rule 4: Password Spray Detection**

```
Name: Password Spray Attack
Description: Multiple failed logins across different accounts from same source
Query: event.code:4625
Threshold: > 5 unique usernames from same IP
Time Window: 5 minutes
Severity: High
MITRE: T1110.003
Response: Block source IP, reset affected passwords, notify users
```

**Hands-On:**

1. Create these rules as saved searches in Kibana
2. Test each rule by generating the activity
3. Verify the rule triggers correctly
4. Document any false positives

**Tuning Exercise:**

Your Rule 2 (Scheduled Task) is triggering on legitimate Windows tasks.

**Problem:** Too many false positives from system tasks

**Solution:** Add exclusions
```
event.code:4698 AND NOT winlog.event_data.TaskName:(*Microsoft* OR *Windows*)
```

**Success Criteria:**
- [ ] Created at least 5 working detection rules
- [ ] Can test rules with Atomic Red Team
- [ ] Can tune rules to reduce false positives
- [ ] Understand when rules trigger

**Assignment:**
Create 3 custom detection rules for techniques you've tested. Document expected true positives and potential false positives.

---

## Week 6: Incident Investigation

### Lesson 6.1: Incident Response Methodology (2 hours)

**Objectives:**
- Learn structured incident investigation
- Follow NIST Incident Response lifecycle
- Document findings properly

**NIST Incident Response Phases:**

1. **Preparation** - Tools, training, policies ready
2. **Detection & Analysis** - Identify and scope the incident
3. **Containment, Eradication, Recovery** - Stop and remove threat
4. **Post-Incident Activity** - Lessons learned, improve defenses

**Investigation Workflow:**

```
Alert Triggered
    ↓
Initial Triage (5 mins)
    ├─ Is it a true positive?
    ├─ What's the severity?
    └─ Is it still active?
    ↓
Scoping (15 mins)
    ├─ What systems affected?
    ├─ What data at risk?
    └─ Timeline of events
    ↓
Deep Analysis (30-60 mins)
    ├─ Root cause
    ├─ Attack vectors
    ├─ Indicators of Compromise (IOCs)
    └─ Attacker TTPs
    ↓
Containment
    ├─ Isolate affected systems
    ├─ Block malicious IPs/domains
    └─ Reset compromised credentials
    ↓
Documentation
    ├─ Incident report
    ├─ Timeline
    ├─ Evidence preservation
    └─ Lessons learned
```

**Investigation Checklist:**

**Initial Questions:**
- [ ] What triggered the alert?
- [ ] When did it happen?
- [ ] Which system(s) involved?
- [ ] What user account(s)?
- [ ] Is the attack still ongoing?

**Evidence Collection:**
- [ ] Screenshot of initial alert
- [ ] Export relevant logs from Kibana
- [ ] Document all queries run
- [ ] Note any external lookups (IP reputation, etc.)
- [ ] Preserve evidence with timestamps

**Analysis Questions:**
- [ ] What MITRE technique was used?
- [ ] What was the attacker's goal?
- [ ] Was the attack successful?
- [ ] What vulnerabilities were exploited?
- [ ] Are there other victims?

**Success Criteria:**
- [ ] Understand the incident response lifecycle
- [ ] Can follow a structured investigation process
- [ ] Know what to document

---

### Lesson 6.2: Hands-On Incident Investigation (4 hours)

**Scenario: Suspicious Activity Alert**

You receive an alert: "Multiple failed login attempts detected from IP 192.168.1.100"

**Your Mission:** Investigate and determine what happened

**Step 1: Initial Triage (5 minutes)**

```
# Quick check in Kibana
event.code:4625 AND source.ip:192.168.1.100 AND @timestamp > now-1h

Questions to answer:
- How many failed attempts?
- What usernames were targeted?
- When did it start/stop?
- Is it still happening?
```

**Step 2: Scope the Incident (15 minutes)**

```
# Check if any logins succeeded
event.code:4624 AND source.ip:192.168.1.100

# Check what the source IP did after successful login
event.code:(4688 OR 1) AND source.ip:192.168.1.100

# Look for lateral movement
event.code:4648 AND user.name:*compromised-user*
```

**Step 3: Build Timeline (20 minutes)**

Create table in Kibana with columns:
- @timestamp
- event.code
- event.outcome
- user.name
- source.ip
- process.name
- process.command_line

Sort chronologically.

**Example Timeline:**
```
10:15:23 - Event 4625 - Failed login - admin - 192.168.1.100
10:15:45 - Event 4625 - Failed login - administrator - 192.168.1.100
10:16:02 - Event 4625 - Failed login - root - 192.168.1.100
10:16:15 - Event 4625 - Failed login - backup - 192.168.1.100
10:16:30 - Event 4624 - SUCCESS - backup - 192.168.1.100  ← COMPROMISE
10:17:12 - Event 4688 - Process: whoami.exe
10:17:45 - Event 4688 - Process: net.exe user /domain
10:18:30 - Event 4720 - New user created: backdoor123
10:19:15 - Event 4732 - User backdoor123 added to Administrators
```

**Step 4: Deep Analysis**

Use SOC Agent:
```python
python soc_agent.py

"Analyze all activity from IP 192.168.1.100 in the last 2 hours. Focus on the timeline after successful authentication and identify malicious actions."
```

Check IP reputation:
```python
"Check the reputation of IP 192.168.1.100"
```

**Step 5: Identify IOCs**

Indicators of Compromise found:
- Malicious IP: 192.168.1.100
- Compromised account: backup
- Backdoor account: backdoor123
- Attack pattern: Password spray → Recon → Persistence

**Step 6: Containment Actions**

1. Disable compromised account: `backup`
2. Delete backdoor account: `backdoor123`
3. Block IP: 192.168.1.100
4. Force password reset for all accounts
5. Review other systems for similar activity

**Step 7: Create Incident Report**

Use this template:

```
INCIDENT REPORT
===============

Incident ID: INC-2026-001
Date: 2026-02-05
Analyst: [Your Name]
Severity: High

SUMMARY
-------
Brute force password spray attack resulted in account compromise and
backdoor account creation.

TIMELINE
--------
10:15 - Attacker began password spray attack from 192.168.1.100
10:16 - Successfully compromised 'backup' account
10:17 - Conducted reconnaissance (whoami, net user)
10:18 - Created backdoor account 'backdoor123'
10:19 - Added backdoor to Administrators group
10:25 - Attack detected and contained

AFFECTED SYSTEMS
--------------
- Windows-Target-VM (10.0.1.5)

COMPROMISED ACCOUNTS
------------------
- backup (password compromised)
- backdoor123 (attacker-created)

ATTACK TECHNIQUES (MITRE ATT&CK)
------------------------------
- T1110.003 - Password Spray
- T1087 - Account Discovery
- T1136.001 - Create Local Account
- T1078 - Valid Accounts

INDICATORS OF COMPROMISE
-----------------------
- IP: 192.168.1.100
- Username: backdoor123
- Pattern: >10 failed logins in 2 minutes

CONTAINMENT ACTIONS TAKEN
-----------------------
[x] Disabled compromised account 'backup'
[x] Deleted backdoor account 'backdoor123'
[x] Blocked IP 192.168.1.100 in firewall
[x] Forced password reset organization-wide
[x] Verified no lateral movement occurred

ROOT CAUSE
----------
Weak password policy allowed successful password spray attack.
Account 'backup' had a common password.

RECOMMENDATIONS
---------------
1. Implement account lockout policy (5 attempts = 30min lockout)
2. Enforce strong password complexity requirements
3. Deploy multi-factor authentication
4. Create detection rule for password spray patterns
5. Regular security awareness training

EVIDENCE
--------
- Kibana export: incident_001_logs.json
- Screenshots: incident_001_timeline.png
- IP reputation: AbuseIPDB score 85/100

LESSONS LEARNED
---------------
- Detection worked: Alert triggered within 10 minutes
- Response time: 15 minutes from alert to containment
- Improvement: Need automated IP blocking for brute force
```

**Success Criteria:**
- [ ] Can investigate alerts end-to-end
- [ ] Can build accurate timelines
- [ ] Can identify attack techniques
- [ ] Can write professional incident reports
- [ ] Can recommend preventive measures

**Assignment:**
Conduct a full investigation of one of your Atomic Red Team simulations and write a complete incident report.

---

## Week 7: Advanced Threat Hunting

### Lesson 7.1: Hypothesis-Driven Hunting (3 hours)

**Objectives:**
- Develop threat hypotheses
- Hunt proactively for threats
- Use threat intelligence to guide hunting

**Threat Hunting Methodology:**

```
1. Develop Hypothesis
   "Attackers may be using WMI for persistence"

2. Gather Intelligence
   - MITRE T1047 (Windows Management Instrumentation)
   - Event IDs: 4688 (wmic.exe), 5861 (WMI activity)

3. Build Hunt Query
   event.code:4688 AND process.name:wmic.exe

4. Analyze Results
   - Filter out normal activity
   - Identify anomalies
   - Pivot to related events

5. Document Findings
   - True positives → Incident
   - False positives → Tune query
   - Negatives → Hypothesis disproven
```

**Hunting Hypotheses to Test:**

**Hypothesis 1: Living Off The Land**
```
Assumption: Attackers use built-in Windows tools to avoid detection
Hunt for: certutil, bitsadmin, mshta used for downloads
Query: event.code:1 AND process.name:(certutil.exe OR bitsadmin.exe OR mshta.exe) AND process.command_line:*http*
```

**Hypothesis 2: PowerShell Obfuscation**
```
Assumption: Attackers obfuscate PowerShell to evade detection
Hunt for: Encoded commands, hidden windows, execution policy bypass
Query: event.code:1 AND process.name:powershell.exe AND process.command_line:(-enc OR -WindowStyle Hidden OR -ExecutionPolicy Bypass)
```

**Hypothesis 3: Unusual Parent-Child Relationships**
```
Assumption: Malware spawns processes from unusual parents
Hunt for: cmd.exe parent of services.exe, svchost without services parent
Query: event.code:1 AND process.parent.name:cmd.exe AND process.name:(services.exe OR lsass.exe OR winlogon.exe)
```

**Hands-On Hunt Exercise:**

```powershell
# Generate suspicious activity
# Download file using certutil (LOLBin technique)
certutil.exe -urlcache -split -f http://example.com/test.txt C:\temp\test.txt
```

Now hunt for it:
```
event.code:1 AND process.name:certutil.exe AND process.command_line:*urlcache*
```

**Success Criteria:**
- [ ] Can develop testable hypotheses
- [ ] Can translate hypotheses into queries
- [ ] Can identify true vs false positives
- [ ] Can document hunt results

---

### Lesson 7.2: Behavioral Analysis (3 hours)

**Objectives:**
- Identify baseline normal behavior
- Detect anomalies
- Use statistical analysis

**Baseline Normal Activity:**

For 1 week, document:
- Normal process creation patterns
- Typical logon times and users
- Standard network connections
- Regular scheduled tasks

**Anomaly Detection Techniques:**

**1. Time-Based Anomalies**
```
# Logons outside business hours
event.code:4624 AND @timestamp:[22:00 TO 06:00]

# Process execution at odd hours
event.code:1 AND process.name:outlook.exe AND @timestamp:[00:00 TO 05:00]
```

**2. Frequency-Based Anomalies**
```
# Process rarely seen before
event.code:1 AND process.name:psexec.exe

# User account that never logged in before
event.code:4624 AND user.name:NEW_USER
```

**3. Relationship-Based Anomalies**
```
# Unusual parent-child
event.code:1 AND process.parent.name:excel.exe AND process.name:powershell.exe

# Service account logging in interactively
event.code:4624 AND user.name:*svc* AND winlog.event_data.LogonType:2
```

**Hands-On:**

1. Establish baseline (review 24 hours of logs)
2. Note common processes, users, logon patterns
3. Generate anomaly:
   ```powershell
   # At 2 AM, run something unusual
   pse.exe (if you have it) or any tool you don't normally use
   ```
4. Hunt for the anomaly using time/frequency/relationship filters

**Success Criteria:**
- [ ] Can establish behavioral baselines
- [ ] Can identify anomalous activities
- [ ] Can explain why something is anomalous

---

## Week 8: Capstone Project

### Final Assessment: Simulated Cyber Attack Investigation (8 hours)

**Scenario:**

Your organization has been breached. Multiple alerts have fired:
1. Brute force attack detected
2. New user account created
3. Suspicious PowerShell execution
4. Data exfiltration suspected

**Your Task:**

Conduct a full investigation and present findings.

**Phase 1: Generate Attack Sequence (1 hour)**

Run these Atomic tests in sequence:
```powershell
# T1110 - Password Spray
Invoke-AtomicTest T1110.003 -TestNumbers 1

# T1136 - Create Account
Invoke-AtomicTest T1136.001 -TestNumbers 1

# T1059 - PowerShell Execution
Invoke-AtomicTest T1059.001 -TestNumbers 1

# T1083 - File Discovery
Invoke-AtomicTest T1083 -TestNumbers 1
```

**Phase 2: Investigation (3 hours)**

Complete investigation covering:
1. Initial alert triage
2. Full timeline reconstruction
3. Scope assessment
4. Attack technique identification
5. IOC extraction
6. Impact analysis

**Phase 3: Report (2 hours)**

Create comprehensive incident report with:
- Executive summary (non-technical)
- Technical analysis
- Timeline visualization
- MITRE ATT&CK mapping
- Containment actions
- Recommendations

**Phase 4: Presentation (2 hours)**

Prepare 15-minute presentation including:
- Overview of incident
- Attack chain diagram
- Key findings
- Response actions
- Lessons learned

**Deliverables:**

1. Incident report (PDF)
2. Timeline export from Kibana (JSON)
3. Detection rules created (saved searches)
4. SOC agent analysis outputs
5. Presentation slides

**Grading Criteria:**

- **Detection (20%)** - Found all attack phases
- **Analysis (30%)** - Correctly identified techniques and impact
- **Timeline (20%)** - Accurate and complete
- **Report (20%)** - Professional and thorough
- **Recommendations (10%)** - Actionable and relevant

---

## Bonus Week: Advanced Topics

### Optional Lessons

**Bonus 1: Malware Analysis Basics**
- Static analysis of suspicious files
- VirusTotal integration
- Reverse engineering introduction

**Bonus 2: Threat Intelligence**
- OSINT gathering
- Threat feed integration
- Indicators of Compromise (IOCs)

**Bonus 3: SIEM Rule Development**
- Advanced KQL queries
- Correlation rules
- Alert tuning

**Bonus 4: Network Traffic Analysis**
- Sysmon Event ID 3 analysis
- DNS tunneling detection
- C2 communication patterns

---

## Resources

### Recommended Reading
- MITRE ATT&CK Framework: https://attack.mitre.org
- Atomic Red Team Documentation: https://atomicredteam.io
- ELK Stack Documentation: https://elastic.co/guide
- SANS Cyber Defense Reading Room
- Blue Team Handbook

### Practice Platforms
- TryHackMe (SOC Level 1 path)
- CyberDefenders (Blue Team challenges)
- Boss of the SOC (BOTS) datasets

### Communities
- r/blueteam
- SANS Blue Team Summit
- Elastic Security Community

---

## Progress Tracking

### Skills Checklist

**Week 1-2: Foundations**
- [ ] Navigate Kibana effectively
- [ ] Write KQL queries
- [ ] Understand Windows Event Logs
- [ ] Understand Sysmon logs

**Week 3-4: Detection**
- [ ] Map events to MITRE ATT&CK
- [ ] Run Atomic Red Team tests
- [ ] Create detection rules
- [ ] Detect brute force attacks
- [ ] Detect lateral movement

**Week 5-6: Investigation**
- [ ] Use SOC agent for analysis
- [ ] Follow investigation methodology
- [ ] Build incident timelines
- [ ] Write incident reports

**Week 7-8: Advanced**
- [ ] Conduct threat hunts
- [ ] Identify behavioral anomalies
- [ ] Complete capstone investigation
- [ ] Present findings professionally

**Career Ready:**
- [ ] Can analyze Windows security events
- [ ] Can detect common attack techniques
- [ ] Can investigate incidents end-to-end
- [ ] Can use SIEM tools effectively
- [ ] Can leverage AI for security analysis
- [ ] Can communicate findings clearly

---

## Certification Path

After completing this course, consider these certifications:

**Entry Level:**
- CompTIA Security+
- CompTIA CySA+

**Intermediate:**
- GIAC Security Essentials (GSEC)
- GIAC Certified Incident Handler (GCIH)

**Advanced:**
- GIAC Continuous Monitoring Certification (GMON)
- Elastic Certified Analyst

---

**Good luck with your SOC analyst training! 🛡️**

Remember: Every security professional started where you are. The key is consistent practice and curiosity.

Questions? Issues? Document them and use your SOC agent to help investigate! 🎯
