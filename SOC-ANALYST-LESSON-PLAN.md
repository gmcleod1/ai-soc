# SOC Analyst Training - Lesson Plan
**AI-Powered Security Operations Center Training Program**

---

## Overview

**Duration:** 12 weeks (70-80 hours total)
**Level:** Beginner to Intermediate
**Prerequisites:** Basic understanding of Windows, networking concepts
**Tools:** ELK Stack, Winlogbeat, Sysmon, Atomic Red Team, AI SOC Agent, Azure CLI (az), Azure Monitor, Azure Activity Logs, NSG Flow Logs, Azure Entra ID

**Learning Objectives:**
By the end of this course, you will be able to:
- Analyze Windows security events to detect threats
- Use the ELK stack for security monitoring
- Recognize MITRE ATT&CK techniques in logs
- Conduct threat hunting investigations
- Leverage AI to accelerate incident analysis
- Write detection rules and queries
- Generate professional incident reports
- Monitor and analyze Azure cloud infrastructure activity
- Detect cloud-specific misconfigurations and attack techniques
- Apply the MITRE ATT&CK Cloud Matrix to Azure environments
- Conduct cloud incident response and forensics
- Build cloud security monitoring dashboards integrating Azure data with ELK
- Produce a portfolio-ready cloud security assessment

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
   ELK_PASSWORD=your-elk-password-here ./deploy-windows-target.sh
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

## Week 9: Azure Security Fundamentals

### Lesson 9.1: Azure Activity Logs and Azure Monitor (3 hours)

**Objectives:**
- Understand Azure Activity Log categories and their security relevance
- Query Activity Logs using Azure CLI
- Export Activity Logs for centralized analysis
- Detect who performed what action on which resource and when

**Theory:**

Azure Activity Logs record control-plane operations against your subscription. They answer the critical question: **who did what, when, and to which resource?**

**Control Plane vs. Data Plane:**
- **Control plane**: Creating/modifying/deleting Azure resources (Activity Logs capture this)
- **Data plane**: Using the resources themselves (e.g., RDP into a VM, querying Elasticsearch)

**Activity Log Categories:**

| Category | What It Captures | SOC Relevance |
|----------|-----------------|---------------|
| Administrative | Resource create/update/delete | Detect unauthorized changes |
| Security | Defender alerts and notifications | Threat notifications |
| Alert | Azure Monitor alert triggers | Operational awareness |
| Policy | Azure Policy evaluation results | Compliance drift |
| Recommendation | Azure Advisor recommendations | Security posture |

**Key Activity Log Fields:**
- `caller` - Who performed the action (email or service principal)
- `operationName` - What was done (e.g., `Microsoft.Network/networkSecurityGroups/securityRules/write`)
- `resourceId` - Which resource was affected
- `status` - Did it succeed or fail?
- `eventTimestamp` - When it happened

**Retention:** 90 days free in Azure, export to Storage Account for longer retention.

**Certification Mapping:** AZ-500 (Manage security operations), SC-200 (Mitigate threats using Microsoft services)

**Hands-On:**

1. **List all Activity Log entries for your resource group (last 7 days):**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --output table
   ```

2. **Filter for write operations (resource modifications):**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --select caller operationName status eventTimestamp --output table
   ```

3. **Export Activity Logs to JSON for analysis:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --output json > azure-activity-logs.json
   ```

4. **Generate a test event by modifying an NSG rule:**
   ```powershell
   # Create a temporary test rule (generates an Activity Log event)
   az network nsg rule create --resource-group ELK-Security-Lab --nsg-name ELK-NSG --name Test-Rule-DELETE-ME --priority 4000 --source-address-prefixes "1.2.3.4/32" --destination-port-ranges 12345 --access Deny --protocol Tcp --output none

   # Delete the test rule
   az network nsg rule delete --resource-group ELK-Security-Lab --nsg-name ELK-NSG --name Test-Rule-DELETE-ME --output none
   ```

5. **Find those events in Activity Logs:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddMinutes(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --select caller operationName resourceId status eventTimestamp --output table
   ```

6. **Search for specific high-risk operations:**
   ```powershell
   # Find all NSG rule changes
   az monitor activity-log list --resource-group ELK-Security-Lab --output json | python -c "
   import json, sys
   logs = json.load(sys.stdin)
   for log in logs:
       op = log.get('operationName', {}).get('localizedValue', '')
       if 'SecurityRule' in op or 'networkSecurityGroup' in op.lower():
           print(f'{log.get(\"eventTimestamp\")} | {log.get(\"caller\")} | {op} | {log.get(\"status\", {}).get(\"localizedValue\", \"\")}')"
   ```

7. **Use the SOC Agent to analyze exported logs:**
   ```python
   python soc_agent.py

   # Prompt:
   "Parse the file azure-activity-logs.json and identify any suspicious administrative actions such as NSG rule changes, VM deletions, or new deployments by unusual callers"
   ```

**Success Criteria:**
- [ ] Can query Azure Activity Logs via CLI
- [ ] Can filter logs by operation type, caller, and time range
- [ ] Can export Activity Logs to JSON
- [ ] Understand Activity Log categories and their security relevance
- [ ] Can detect resource modifications (NSG changes, VM operations)

**Assignment:**
Export 7 days of Activity Logs. Write a summary of all administrative operations, identify the top callers (users/service principals), and flag any operations that could represent a security risk. Save this as a markdown document in your Proof folder.

---

### Lesson 9.2: NSG Flow Logs and Network Security Analysis (3 hours)

**Objectives:**
- Understand NSG Flow Log format and fields
- Enable NSG Flow Logs on the lab environment
- Analyze network traffic patterns to identify anomalies
- Correlate Azure network data with endpoint data in Kibana

**Theory:**

NSG Flow Logs capture information about IP traffic flowing through your NSG. They show every connection attempt -- allowed or denied.

**Flow Log Tuple Format (Version 2):**
```
1.2.3.4,10.0.1.4,54321,3389,T,I,A,5,300,5,300
```

| Field | Example | Meaning |
|-------|---------|---------|
| Source IP | 1.2.3.4 | Where traffic came from |
| Dest IP | 10.0.1.4 | Where traffic is going |
| Source Port | 54321 | Ephemeral port |
| Dest Port | 3389 | RDP port |
| Protocol | T | T=TCP, U=UDP |
| Direction | I | I=Inbound, O=Outbound |
| Action | A | A=Allowed, D=Denied |
| Packets Src | 5 | Packets from source |
| Bytes Src | 300 | Bytes from source |
| Packets Dst | 5 | Packets from destination |
| Bytes Dst | 300 | Bytes from destination |

**Cost:** Storage Account cost only (~$2-5/month for lab traffic volumes).

**Certification Mapping:** AZ-500 (Configure network security)

**Hands-On:**

1. **Create a Storage Account for flow logs:**
   ```powershell
   $storageName = "elksoclogs$(Get-Random -Minimum 10000 -Maximum 99999)"
   az storage account create --name $storageName --resource-group ELK-Security-Lab --location eastus --sku Standard_LRS --output none
   echo "Storage account: $storageName"
   ```

2. **Get the NSG resource ID:**
   ```powershell
   az network nsg show --resource-group ELK-Security-Lab --name ELK-NSG --query id --output tsv
   ```

3. **Enable NSG Flow Logs:**
   ```powershell
   az network watcher flow-log create --name "ELK-NSG-FlowLog" --resource-group ELK-Security-Lab --nsg ELK-NSG --storage-account $storageName --enabled true --format JSON --log-version 2 --retention 7
   ```

4. **Generate traffic** by browsing to Kibana, RDP-ing to the Windows VM, and running outbound tests from the Windows VM.

5. **Wait 10-15 minutes, then download flow logs:**
   ```powershell
   # List blob containers
   az storage container list --account-name $storageName --output table

   # Download flow log blobs
   mkdir flow-logs
   az storage blob download-batch --destination ./flow-logs --source insights-logs-networksecuritygroupflowevent --account-name $storageName
   ```

6. **Parse flow logs with the Python script:**
   ```powershell
   python parse_flow_logs.py flow-logs/
   ```

   The `parse_flow_logs.py` script (included in this repo) will show:
   - Total allowed/denied flows
   - Top source IPs
   - Top destination ports
   - Denied connection attempts (potential scanning)
   - Outbound connections to external IPs

7. **List current NSG rules and audit them:**
   ```powershell
   az network nsg rule list --resource-group ELK-Security-Lab --nsg-name ELK-NSG --output table
   ```

8. **Correlate with endpoint data:**
   In Kibana, search for the same source IPs that appear in your flow logs:
   ```
   source.ip:<suspicious-ip-from-flow-logs>
   ```

**Success Criteria:**
- [ ] Can enable NSG Flow Logs on an existing NSG
- [ ] Can download and parse flow log JSON
- [ ] Can identify denied vs. allowed traffic
- [ ] Can spot unusual outbound connections
- [ ] Understand the security implications of NSG rule configurations

**Assignment:**
Enable flow logs, collect 1 hour of data, and produce a "Network Security Posture Report" that includes: (1) total allowed/denied flows, (2) top source IPs, (3) top destination ports, (4) any suspicious outbound connections, (5) NSG rule audit with recommendations.

---

## Week 10: Cloud Identity and Access Security

### Lesson 10.1: Azure Entra ID and RBAC Security (3 hours)

**Objectives:**
- Understand Azure Entra ID (formerly Azure AD) and its role in cloud security
- Audit role-based access control (RBAC) assignments in the subscription
- Detect over-privileged accounts and service principals
- Correlate RBAC changes with Activity Log events

**Theory:**

**Azure Entra ID vs. Traditional Active Directory:**
- Traditional AD: On-premises, manages Windows domain resources
- Entra ID: Cloud-based identity service, manages Azure and Microsoft 365 access
- In your SOC lab, Entra ID controls who can modify your Azure infrastructure

**Azure RBAC Model:**
```
Scope (where?) + Role (what?) + Principal (who?) = Assignment
```

Scopes are hierarchical:
```
Management Group
  └── Subscription
       └── Resource Group (ELK-Security-Lab)
            └── Resource (Elasticsearch-VM)
```

**Critical Roles to Monitor:**

| Role | Risk Level | Why |
|------|-----------|-----|
| Owner | CRITICAL | Full access + can assign roles to others |
| User Access Administrator | CRITICAL | Can grant others access |
| Contributor | HIGH | Can create/modify/delete all resources |
| Network Contributor | MEDIUM | Can modify NSG rules, open ports |
| Reader | LOW | Read-only, minimal risk |

**Certification Mapping:** AZ-500 (Manage identity and access), SC-200

**Hands-On:**

1. **List all role assignments in the subscription:**
   ```powershell
   az role assignment list --all --output table
   ```

2. **Find all Owner-level assignments (highest privilege):**
   ```powershell
   az role assignment list --all --role "Owner" --output table
   ```

3. **Find Contributor assignments at the resource group level:**
   ```powershell
   az role assignment list --resource-group ELK-Security-Lab --output table
   ```

4. **List all service principals (app registrations):**
   ```powershell
   az ad sp list --all --query "[].{Name:displayName, AppId:appId, Type:servicePrincipalType}" --output table
   ```

5. **Check for users with multiple high-privilege roles:**
   ```powershell
   az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='User Access Administrator'].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" --output table
   ```

6. **Create a test RBAC assignment and then remove it (generates Activity Log entries):**
   ```powershell
   # Get your own user object ID
   $myObjectId = az ad signed-in-user show --query id --output tsv

   # Assign Reader role at resource group level
   az role assignment create --assignee $myObjectId --role "Reader" --resource-group ELK-Security-Lab --output none

   # Then remove it
   az role assignment delete --assignee $myObjectId --role "Reader" --resource-group ELK-Security-Lab
   ```

7. **Check Activity Logs for the role assignment changes:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddMinutes(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --output table
   ```

8. **Export full RBAC data for audit report:**
   ```powershell
   az role assignment list --all --include-inherited --output json > rbac-audit.json
   ```

**Success Criteria:**
- [ ] Can enumerate all RBAC assignments across the subscription
- [ ] Can identify over-privileged accounts (Owner, User Access Administrator)
- [ ] Can detect service principals and understand their permissions
- [ ] Can correlate RBAC changes with Activity Log events
- [ ] Understand the principle of least privilege in Azure

**Assignment:**
Perform a complete RBAC audit. Document: (1) all role assignments, (2) any over-privileged accounts, (3) service principals and their roles, (4) recommendations for reducing privilege. Format as a professional security assessment document.

---

### Lesson 10.2: Cloud Misconfiguration Hunting (3 hours)

**Objectives:**
- Identify common Azure misconfigurations that lead to breaches
- Check for exposed storage accounts, open NSG rules, and unencrypted resources
- Build a cloud security posture checklist
- Automate misconfiguration detection with the `azure_security_scanner.py` script

**Theory:**

**Top Cloud Misconfigurations (CIS Azure Benchmark):**

| Misconfiguration | Risk | Real-World Impact |
|-----------------|------|-------------------|
| Public blob access on storage accounts | HIGH | Capital One breach (170M records) |
| NSG rules allowing 0.0.0.0/0 on sensitive ports | CRITICAL | Direct attack surface for RDP/SSH brute force |
| Unencrypted VM disks | MEDIUM | Data exposure if disk is accessed |
| Missing diagnostic logging | MEDIUM | Cannot detect or investigate attacks |
| Storage account without HTTPS enforcement | MEDIUM | Data interception in transit |
| Overly permissive RBAC | HIGH | Insider threat / compromised account blast radius |

**Certification Mapping:** AZ-500 (Manage security posture), SC-200, CySA+

**Hands-On:**

1. **Check for NSG rules allowing traffic from any source (0.0.0.0/0):**
   ```powershell
   az network nsg rule list --resource-group ELK-Security-Lab --nsg-name ELK-NSG --query "[?sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet'].{Name:name, Port:destinationPortRange, Source:sourceAddressPrefix, Access:access, Priority:priority}" --output table
   ```

2. **Check if storage accounts have public blob access:**
   ```powershell
   az storage account list --resource-group ELK-Security-Lab --query "[].{Name:name, PublicAccess:allowBlobPublicAccess, HttpsOnly:enableHttpsTrafficOnly, MinTLS:minimumTlsVersion}" --output table
   ```

3. **Check if VM disks are encrypted:**
   ```powershell
   az vm encryption show --resource-group ELK-Security-Lab --name Elasticsearch-VM 2>$null
   az vm encryption show --resource-group ELK-Security-Lab --name WinTarget-VM 2>$null
   ```

4. **Check for VMs with public IPs (attack surface):**
   ```powershell
   az vm list-ip-addresses --resource-group ELK-Security-Lab --output table
   ```

5. **Check for diagnostic settings (is logging enabled?):**
   ```powershell
   $subId = az account show --query id --output tsv
   az monitor diagnostic-settings list --resource "/subscriptions/$subId" --output table
   ```

6. **Check for open management ports (SSH/RDP to internet):**
   ```powershell
   az network nsg rule list --resource-group ELK-Security-Lab --nsg-name ELK-NSG --query "[?(destinationPortRange=='22' || destinationPortRange=='3389') && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')].{Name:name, Port:destinationPortRange, Source:sourceAddressPrefix}" --output table
   ```

7. **Run the automated misconfiguration scanner:**
   ```powershell
   python azure_security_scanner.py
   ```

   The `azure_security_scanner.py` script (included in this repo) automates all of the above checks and produces a formatted security posture report with severity ratings and recommendations.

8. **Use the SOC Agent to analyze findings:**
   ```python
   python soc_agent.py

   # Prompt:
   "Parse the file azure-security-scan-results.json and prioritize the misconfigurations by risk level. For each finding, explain the potential attack scenario and remediation steps."
   ```

**Success Criteria:**
- [ ] Can identify open NSG rules allowing unrestricted traffic
- [ ] Can check for unencrypted VM disks
- [ ] Can find VMs with public IP addresses
- [ ] Can verify storage account security settings
- [ ] Can produce an automated security posture report

**Assignment:**
Run the full misconfiguration scanner against your lab environment. Create a "Cloud Security Posture Report" with: executive summary, findings table (severity, description, recommendation), and remediation priority list. Save the scanner script and report to your GitHub repo as a portfolio piece.

---

## Week 11: Cloud Attack Simulation and Defense

### Lesson 11.1: Cloud MITRE ATT&CK Matrix (3 hours)

**Objectives:**
- Understand the MITRE ATT&CK Cloud Matrix (Azure-specific techniques)
- Map cloud-specific attacks to Azure services
- Simulate cloud attack techniques using Azure CLI
- Detect simulated cloud attacks using Activity Logs

**Theory:**

The MITRE ATT&CK Cloud Matrix covers techniques specific to cloud environments. These are different from endpoint techniques because attackers target the cloud control plane -- APIs, identity, and infrastructure management.

**The Cloud Kill Chain:**
```
Initial Access (stolen credentials)
    ↓
Discovery (enumerate resources, roles, networking)
    ↓
Privilege Escalation (assign Owner/Contributor roles)
    ↓
Persistence (create new cloud accounts, deploy backdoor VMs)
    ↓
Defense Evasion (disable logging, modify NSG rules)
    ↓
Collection (access storage accounts, databases)
    ↓
Exfiltration (copy data to attacker-controlled storage)
```

**Key Cloud ATT&CK Techniques for Azure:**

| Technique ID | Name | Azure Context | Detection |
|-------------|------|---------------|-----------|
| T1078.004 | Cloud Accounts | Compromised Azure credentials | Sign-in logs, unusual locations |
| T1580 | Cloud Infrastructure Discovery | `az vm list`, `az resource list` | Activity Log: read operations spike |
| T1562.008 | Disable Cloud Logs | Deleting diagnostic settings | Activity Log: delete operations |
| T1098.003 | Additional Cloud Roles | Adding Owner/Contributor | Activity Log: role assignment write |
| T1136.003 | Cloud Account | Creating new Entra ID users | Audit Log: user creation |
| T1578.002 | Create Cloud Instance | Deploying rogue VMs | Activity Log: VM creation |
| T1535 | Unused/Unsupported Cloud Regions | Deploy resources in odd regions | Activity Log: unusual location field |
| T1496 | Resource Hijacking | Cryptomining VMs | Unusual VM sizes, cost alerts |

**Certification Mapping:** SC-200, AZ-500

**Hands-On:**

1. **Simulate T1580 - Cloud Infrastructure Discovery:**
   ```powershell
   # Attacker enumerates all resources
   az resource list --resource-group ELK-Security-Lab --output table
   az vm list --resource-group ELK-Security-Lab --show-details --output table
   az network nsg list --resource-group ELK-Security-Lab --output table
   az network public-ip list --resource-group ELK-Security-Lab --output table
   az storage account list --resource-group ELK-Security-Lab --output table
   ```

2. **Detect discovery in Activity Logs:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddMinutes(-15).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --query "[?contains(operationName.localizedValue, 'List') || contains(operationName.localizedValue, 'Read')].{Time:eventTimestamp, Caller:caller, Operation:operationName.localizedValue}" --output table
   ```

3. **Simulate T1098.003 - Additional Cloud Roles (Privilege Escalation):**
   ```powershell
   $myObjectId = az ad signed-in-user show --query id --output tsv

   # Assign Contributor (elevated role)
   az role assignment create --assignee $myObjectId --role "Contributor" --resource-group ELK-Security-Lab --output none

   # Immediately remove it
   az role assignment delete --assignee $myObjectId --role "Contributor" --resource-group ELK-Security-Lab
   ```

4. **Detect role changes in Activity Logs:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddMinutes(-15).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --query "[?contains(operationName.localizedValue, 'role')].{Time:eventTimestamp, Caller:caller, Operation:operationName.localizedValue, Status:status.localizedValue}" --output table
   ```

5. **Simulate T1578.002 - Create Cloud Instance (Rogue VM):**
   ```powershell
   # Create a tiny VM in a DIFFERENT region (this is suspicious!)
   az vm create --resource-group ELK-Security-Lab --name RogueVM-DELETE --location westus2 --image Ubuntu2204 --size Standard_B1s --admin-username testadmin --generate-ssh-keys --no-wait --output none

   # Wait briefly, then delete to avoid cost
   Start-Sleep -Seconds 30
   az vm delete --resource-group ELK-Security-Lab --name RogueVM-DELETE --yes --no-wait
   az network nic delete --resource-group ELK-Security-Lab --name RogueVM-DELETEVMNic --no-wait 2>$null
   az network public-ip delete --resource-group ELK-Security-Lab --name RogueVM-DELETEPublicIP --no-wait 2>$null
   ```

6. **Detect the rogue VM in Activity Logs:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddMinutes(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --query "[?contains(operationName.localizedValue, 'Virtual Machine')].{Time:eventTimestamp, Caller:caller, Operation:operationName.localizedValue, Status:status.localizedValue}" --output table
   ```

7. **Cross-layer correlation (cloud + endpoint):**
   After detecting a cloud-level compromise, check if the attacker also accessed the Windows VM:
   ```
   # In Kibana, search for new RDP sessions from unusual IPs
   event.code:4624 AND winlog.event_data.LogonType:10
   ```

8. **Build cloud detection rules:**

   | Rule | Query Pattern | Severity |
   |------|--------------|----------|
   | Rogue VM Creation | Activity Log: `virtualMachines/write` in unusual region | HIGH |
   | Role Escalation | Activity Log: `roleAssignments/write` with Owner/Contributor | CRITICAL |
   | Mass Discovery | Activity Log: >20 read/list operations in 5 minutes | MEDIUM |
   | Log Deletion | Activity Log: `diagnosticSettings/delete` | CRITICAL |

**Success Criteria:**
- [ ] Can explain at least 6 cloud-specific MITRE ATT&CK techniques
- [ ] Can simulate cloud attacks using Azure CLI
- [ ] Can detect simulated attacks in Azure Activity Logs
- [ ] Can correlate cloud-level and endpoint-level evidence
- [ ] Understand the cloud kill chain concept

**Assignment:**
Choose 3 cloud ATT&CK techniques, simulate each one, detect the evidence in Activity Logs, and write a detection rule for each (query + threshold + severity + response). Document as a "Cloud Threat Detection Playbook."

---

### Lesson 11.2: Azure Incident Response and Cloud Forensics (4 hours)

**Objectives:**
- Apply incident response methodology to cloud-specific incidents
- Collect and preserve cloud forensic evidence
- Perform containment actions in Azure
- Create a cloud incident response playbook

**Theory:**

**How Cloud IR Differs from Traditional IR:**
- No physical access to hardware -- everything is API-based
- Evidence is collected via Azure CLI and APIs, not disk imaging
- Shared responsibility model: Microsoft secures the cloud, you secure what's IN the cloud
- Resources are ephemeral -- an attacker can delete VMs to cover tracks

**Cloud Evidence Sources:**

| Source | What It Contains | How to Collect |
|--------|-----------------|----------------|
| Activity Logs | Control plane operations | `az monitor activity-log list` |
| NSG Flow Logs | Network traffic metadata | Storage Account download |
| Entra ID Sign-In Logs | Authentication events | `az rest` / Graph API |
| VM Disk Snapshots | Full disk contents | `az snapshot create` |
| RBAC State | Who has what access | `az role assignment list` |
| NSG Rules | Network policy state | `az network nsg rule list` |

**Containment Actions in Azure:**

| Action | Command | When to Use |
|--------|---------|------------|
| Lock down NSG | Add Deny-All rule at priority 100 | Active attack, stop all traffic |
| Deallocate VM | `az vm deallocate` | Compromised VM, preserve disk |
| Revoke RBAC | `az role assignment delete` | Compromised credentials |
| Rotate keys | Regenerate storage keys | Exposed storage credentials |
| Snapshot disk | `az snapshot create` | Preserve forensic evidence |

**Certification Mapping:** AZ-500, SC-200, GCIH

**Hands-On Scenario: "Unauthorized VM Deployment and Data Access"**

*You receive an alert that a new VM was created in your resource group by an unknown caller. Investigate, contain, and remediate.*

1. **Detection -- Discover the unauthorized activity:**
   ```powershell
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddHours(-24).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --query "[?contains(operationName.localizedValue, 'Create') && contains(operationName.localizedValue, 'Virtual Machine')].{Time:eventTimestamp, Caller:caller, Operation:operationName.localizedValue, Status:status.localizedValue, Resource:resourceId}" --output table
   ```

2. **Scoping -- Determine what else the caller did:**
   ```powershell
   # Replace SUSPICIOUS-CALLER with the actual caller from step 1
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddHours(-24).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --query "[?caller=='SUSPICIOUS-CALLER'].{Time:eventTimestamp, Operation:operationName.localizedValue, Status:status.localizedValue, Resource:resourceId}" --output table
   ```

3. **Evidence Preservation -- Snapshot a VM disk:**
   ```powershell
   # Create a forensic snapshot of a potentially compromised VM disk
   $diskName = az vm show --resource-group ELK-Security-Lab --name WinTarget-VM --query "storageProfile.osDisk.name" --output tsv
   az snapshot create --resource-group ELK-Security-Lab --name "forensic-snapshot-$(Get-Date -Format 'yyyyMMdd')" --source $diskName --output none
   ```

4. **Containment -- Lock down access:**
   ```powershell
   # Block all external access via NSG emergency rule
   az network nsg rule create --resource-group ELK-Security-Lab --nsg-name ELK-NSG --name Emergency-Block-All --priority 100 --source-address-prefixes "*" --destination-port-ranges "*" --access Deny --protocol "*" --description "Emergency lockdown - incident response" --output none

   # IMPORTANT: Re-allow your own IP after containment
   # az network nsg rule delete --resource-group ELK-Security-Lab --nsg-name ELK-NSG --name Emergency-Block-All
   ```

5. **Revoke compromised credentials:**
   ```powershell
   # List role assignments for the suspicious caller
   az role assignment list --assignee SUSPICIOUS-CALLER --output table

   # Remove their access
   az role assignment delete --assignee SUSPICIOUS-CALLER --role "Contributor" --resource-group ELK-Security-Lab
   ```

6. **Export all evidence for the incident:**
   ```powershell
   mkdir incident-evidence

   # Activity Logs
   az monitor activity-log list --resource-group ELK-Security-Lab --start-time ((Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")) --output json > incident-evidence/activity-logs.json

   # RBAC state
   az role assignment list --all --resource-group ELK-Security-Lab --output json > incident-evidence/rbac.json

   # NSG rules
   az network nsg rule list --resource-group ELK-Security-Lab --nsg-name ELK-NSG --output json > incident-evidence/nsg-rules.json
   ```

7. **Use SOC Agent to generate the cloud incident report:**
   ```python
   python soc_agent.py

   # Prompt:
   "I have evidence of an unauthorized VM deployment in our Azure environment. Parse the file incident-evidence/activity-logs.json and create a cloud incident report. Include timeline, MITRE ATT&CK technique mapping, containment actions taken, and recommendations to prevent recurrence."
   ```

8. **Write the Cloud IR Playbook** with these sections:
   - Preparation checklist (tools, access, contacts)
   - Detection triggers (Activity Log patterns to alert on)
   - Investigation steps (exact CLI commands)
   - Containment actions (NSG lockdown, role revocation, VM deallocation)
   - Eradication steps (remove unauthorized resources)
   - Recovery procedures (restore from snapshots, re-enable access)
   - Lessons learned template

**Success Criteria:**
- [ ] Can collect cloud forensic evidence (Activity Logs, disk snapshots, RBAC state)
- [ ] Can perform containment actions (NSG lockdown, role revocation)
- [ ] Can build a timeline from Azure Activity Logs
- [ ] Can write a cloud incident response playbook
- [ ] Understand the shared responsibility model for incident response

**Assignment:**
Write a complete "Azure Cloud Incident Response Playbook" covering all 6 NIST phases adapted for cloud. Include exact Azure CLI commands for each phase, a decision tree for severity classification, and an evidence collection checklist.

---

## Week 12: Cloud Security Capstone

### Lesson 12.1: Cloud Security Monitoring Dashboard (4 hours)

**Objectives:**
- Ingest Azure Activity Logs into Elasticsearch
- Build a unified cloud + endpoint security dashboard in Kibana
- Create cloud-specific detection rules as saved searches
- Demonstrate real-time cloud security monitoring

**Theory:**

**Why Unified Visibility Matters:**
- Cloud control plane (Activity Logs) tells you WHO modified WHAT infrastructure
- Endpoint data plane (Sysmon/Winlogbeat) tells you WHAT happened ON the systems
- Together, you can trace: credential compromise → cloud privilege escalation → endpoint exploitation

**Dashboard Design for SOC Analysts:**
- Top panels: High-severity alerts and counts
- Middle panels: Timelines and trends
- Bottom panels: Detailed tables and drill-down data

**Certification Mapping:** SC-200, Elastic Certified Analyst

**Hands-On:**

1. **Set up the Azure-to-ELK forwarder:**

   The `azure_to_elk.py` script (included in this repo) polls Azure Activity Logs every 5 minutes and indexes them into Elasticsearch.

   ```powershell
   # Install elasticsearch Python package if needed
   pip install elasticsearch

   # Run the forwarder (uses your .env credentials)
   python azure_to_elk.py
   ```

   This creates an `azure-activity-*` index pattern in Elasticsearch.

2. **Create a Kibana data view for Azure Activity Logs:**
   - Navigate to Kibana > Stack Management > Data Views
   - Create: `azure-activity-*`
   - Time field: `@timestamp`

3. **Build Dashboard Panels:**

   **Panel 1: Azure Operations Timeline** (Line chart)
   - Index: `azure-activity-*`
   - X-axis: `@timestamp` (date histogram, 5-minute intervals)
   - Y-axis: Count
   - Split by: `azure.activity.category`

   **Panel 2: Top Azure Callers** (Horizontal bar chart)
   - Terms aggregation on `azure.activity.caller`
   - Top 10 callers

   **Panel 3: Failed Azure Operations** (Data table)
   - Filter: `azure.activity.status: "Failed"`
   - Columns: timestamp, caller, operation, resource_group

   **Panel 4: NSG Rule Changes** (Saved search)
   - Filter: `azure.activity.operation: *SecurityRule*`

   **Panel 5: VM Operations** (Saved search)
   - Filter: `azure.activity.operation: *virtualMachines*`

   **Panel 6: Role Assignment Changes** (Saved search)
   - Filter: `azure.activity.operation: *roleAssignments*`

   **Panel 7: Endpoint Failed Logins** (from winlogbeat)
   - Index: `winlogbeat-*`
   - Filter: `event.code: 4625`
   - Line chart over time

   **Panel 8: Suspicious Processes** (from winlogbeat)
   - Index: `winlogbeat-*`
   - Filter: `event.code:1 AND process.name:(powershell.exe OR cmd.exe)`
   - Count over time

4. **Create Cloud Detection Rules as Saved Searches:**

   ```
   Rule 1: "Cloud - Unauthorized Resource Creation"
   Query: azure.activity.operation: (*Create* OR *Write*) AND azure.activity.status: "Succeeded"

   Rule 2: "Cloud - Role Escalation"
   Query: azure.activity.operation: *roleAssignments/write* AND azure.activity.status: "Succeeded"

   Rule 3: "Cloud - NSG Modification"
   Query: azure.activity.operation: *securityRules/write* AND azure.activity.status: "Succeeded"

   Rule 4: "Cloud - Diagnostic Setting Deletion (Log Evasion)"
   Query: azure.activity.operation: *diagnosticSettings/delete*
   ```

5. **Export the dashboard:**
   - Kibana > Stack Management > Saved Objects > Export
   - Save the `.ndjson` file to your Git repo under `dashboards/`

6. **Screenshot the dashboard** and add to your Proof folder.

**Success Criteria:**
- [ ] Can ingest Azure Activity Logs into Elasticsearch
- [ ] Can build a multi-panel Kibana dashboard
- [ ] Dashboard shows both cloud and endpoint security data
- [ ] Created at least 4 cloud-specific detection rules
- [ ] Dashboard is exportable and reproducible

**Assignment:**
Build the complete Cloud Security Operations Dashboard. Export it, take screenshots, and write a README documenting: what each panel shows, what detection rules are active, how to set it up from scratch, and what alerts an analyst should prioritize.

---

### Lesson 12.2: Full Cloud Security Assessment and Portfolio Project (4 hours)

**Objectives:**
- Conduct a comprehensive security assessment of the entire Azure lab
- Combine all cloud and endpoint analysis into a professional report
- Create a GitHub portfolio showcasing the complete project
- Prepare LinkedIn-ready presentation of skills

**Theory:**

**What a Professional Cloud Security Assessment Includes:**
1. Executive Summary (1 page, non-technical)
2. Scope and Methodology
3. Risk Rating Framework (Critical/High/Medium/Low)
4. Findings (each with description, evidence, impact, recommendation)
5. Remediation Priority Matrix
6. Appendices (raw data, tool outputs)

**Portfolio Best Practices:**
- Show the PROCESS, not just the results
- Include screenshots as proof of work
- Write clear READMEs with setup instructions
- Demonstrate tools you built, not just tools you used
- Map everything to certifications and frameworks

**Certification Mapping:** AZ-500, SC-200, CySA+, GSEC

**Hands-On: Full Assessment**

1. **Infrastructure Inventory:**
   ```powershell
   mkdir assessment

   # Complete resource inventory
   az resource list --resource-group ELK-Security-Lab --output table > assessment/inventory.txt

   # Network topology
   az network vnet show --resource-group ELK-Security-Lab --name ELK-VNet --output json > assessment/network-topology.json

   # All NSG rules
   az network nsg rule list --resource-group ELK-Security-Lab --nsg-name ELK-NSG --output json > assessment/nsg-rules.json

   # All public IPs
   az network public-ip list --resource-group ELK-Security-Lab --output json > assessment/public-ips.json

   # RBAC assignments
   az role assignment list --resource-group ELK-Security-Lab --output json > assessment/rbac.json
   ```

2. **Security Assessment Checklist:**

   **Identity & Access:**
   - [ ] Reviewed all RBAC assignments
   - [ ] Checked for over-privileged accounts
   - [ ] Verified service principal permissions
   - [ ] Checked for unused accounts

   **Network Security:**
   - [ ] Audited all NSG rules
   - [ ] Checked for overly permissive rules (0.0.0.0/0)
   - [ ] Verified network segmentation
   - [ ] Reviewed public IP assignments

   **Data Protection:**
   - [ ] Checked disk encryption status
   - [ ] Verified storage account security settings
   - [ ] Checked for public blob access

   **Logging & Monitoring:**
   - [ ] Verified Activity Log export
   - [ ] Checked diagnostic settings
   - [ ] Verified endpoint logging (Sysmon, Winlogbeat)
   - [ ] Reviewed dashboard coverage

   **Threat Detection:**
   - [ ] Tested cloud detection rules
   - [ ] Tested endpoint detection rules
   - [ ] Ran attack simulations (cloud + endpoint)
   - [ ] Verified alert effectiveness

3. **Run the full assessment:**
   ```powershell
   # Run the misconfiguration scanner
   python azure_security_scanner.py > assessment/misconfig-report.txt

   # Export Activity Logs
   az monitor activity-log list --resource-group ELK-Security-Lab --output json > assessment/activity-logs.json

   # Run endpoint simulations and detect them
   # (Use Atomic Red Team tests from Week 3)
   ```

4. **Use SOC Agent to compile the report:**
   ```python
   python soc_agent.py

   # Prompt:
   "I need to compile a comprehensive cloud security assessment. Parse the files in the assessment/ folder and create an executive-level security assessment report with risk ratings and prioritized recommendations."
   ```

5. **Organize your GitHub portfolio:**
   ```
   Recommended repository structure:

   ai-soc/
   ├── README.md                      # Project overview
   ├── soc_agent.py                   # AI SOC Agent
   ├── soc_tools.py                   # Security tool definitions
   ├── elk_connector.py               # ELK integration
   ├── azure_security_scanner.py      # Cloud misconfig scanner
   ├── azure_to_elk.py                # Activity Log forwarder
   ├── parse_flow_logs.py             # NSG Flow Log parser
   ├── SOC-ANALYST-LESSON-PLAN.md     # 12-week curriculum
   ├── Proof/                         # Screenshots and evidence
   │   ├── lesson-1.1-columns.png
   │   ├── lesson-1.1-failed-logins.png
   │   └── cloud-dashboard.png
   ├── assessment/                    # Security assessment artifacts
   ├── dashboards/                    # Kibana dashboard exports
   ├── playbooks/                     # IR and detection playbooks
   └── reports/                       # Generated incident reports
   ```

6. **Write your assessment report** following this structure:
   ```
   CLOUD SECURITY ASSESSMENT REPORT
   =================================

   Executive Summary
   -----------------
   [1-paragraph non-technical summary for leadership]

   Scope
   -----
   - Resource Group: ELK-Security-Lab
   - Resources assessed: [count] resources
   - Assessment date: [date]
   - Frameworks: CIS Azure Benchmark, MITRE ATT&CK Cloud

   Findings Summary
   ----------------
   Critical: [count]
   High: [count]
   Medium: [count]
   Low: [count]

   Detailed Findings
   -----------------
   [For each finding: Description, Evidence, Impact, Recommendation]

   Remediation Priority
   --------------------
   [Ordered list with estimated effort and risk reduction]

   Conclusion
   ----------
   [Overall security posture assessment]
   ```

**Success Criteria:**
- [ ] Completed full infrastructure security assessment
- [ ] Produced professional assessment report
- [ ] GitHub repository is organized, documented, and public
- [ ] Dashboard is functional and demonstrates cloud+endpoint monitoring
- [ ] Can articulate findings to both technical and non-technical audiences

**Assignment:**
This is the final capstone. Create the complete GitHub repository with all artifacts from Weeks 9-12. Write a LinkedIn post announcing the completed 12-week cloud security training. Present the assessment as if delivering to a CISO -- 5-minute executive summary + 10-minute technical deep dive.

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

### Cloud Security Resources
- MITRE ATT&CK Cloud Matrix: https://attack.mitre.org/matrices/enterprise/cloud/iaas/
- CIS Azure Foundations Benchmark: https://www.cisecurity.org/benchmark/azure
- Azure Security Documentation: https://learn.microsoft.com/en-us/azure/security/
- Azure CLI Reference: https://learn.microsoft.com/en-us/cli/azure/
- SC-200 Learning Path: https://learn.microsoft.com/en-us/training/paths/sc-200-mitigate-threats-using-microsoft-365-defender/
- AZ-500 Learning Path: https://learn.microsoft.com/en-us/training/paths/manage-identity-access/

### Practice Platforms
- TryHackMe (SOC Level 1 path)
- CyberDefenders (Blue Team challenges)
- Boss of the SOC (BOTS) datasets
- Microsoft Learn Cloud Skills Challenge

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

**Week 9-10: Cloud Security**
- [ ] Query Azure Activity Logs via CLI
- [ ] Analyze NSG Flow Logs
- [ ] Audit Azure RBAC assignments
- [ ] Detect cloud misconfigurations
- [ ] Run automated security scanner

**Week 11-12: Cloud Advanced & Capstone**
- [ ] Map cloud attacks to MITRE ATT&CK Cloud Matrix
- [ ] Simulate and detect cloud attack techniques
- [ ] Perform cloud incident response
- [ ] Build cloud security monitoring dashboard
- [ ] Complete full cloud security assessment
- [ ] Publish portfolio project on GitHub

**Career Ready:**
- [ ] Can analyze Windows security events
- [ ] Can detect common attack techniques
- [ ] Can investigate incidents end-to-end
- [ ] Can use SIEM tools effectively
- [ ] Can leverage AI for security analysis
- [ ] Can communicate findings clearly
- [ ] Can monitor and analyze Azure cloud environments
- [ ] Can detect cloud-specific attack techniques
- [ ] Can perform cloud incident response
- [ ] Can build unified cloud+endpoint security dashboards
- [ ] Can produce professional security assessment reports
- [ ] Has a public GitHub portfolio with cloud security projects

---

## Certification Path

After completing this course, consider these certifications:

**Entry Level:**
- CompTIA Security+
- CompTIA CySA+

**Intermediate:**
- GIAC Security Essentials (GSEC)
- GIAC Certified Incident Handler (GCIH)

**Cloud Security:**
- Microsoft AZ-500 (Azure Security Engineer)
- Microsoft SC-200 (Security Operations Analyst)
- CompTIA Cloud+
- CCSK (Certificate of Cloud Security Knowledge)

**Advanced:**
- GIAC Continuous Monitoring Certification (GMON)
- Elastic Certified Analyst

---

**Good luck with your SOC analyst training! 🛡️**

Remember: Every security professional started where you are. The key is consistent practice and curiosity.

Questions? Issues? Document them and use your SOC agent to help investigate! 🎯
