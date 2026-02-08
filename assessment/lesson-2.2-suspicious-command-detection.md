# Lesson 2.2 Assignment: KQL Query to Detect Suspicious Command Patterns

## Single Detection Query

```kql
event.code:1 AND winlog.event_data.CommandLine:(*whoami* OR *-enc* OR *net user* OR *net localgroup* OR *ipconfig /all* OR *Invoke-Mimikatz* OR *sekurlsa* OR *procdump* OR *lsass* OR *schtasks /create* OR *-ExecutionPolicy Bypass* OR *-WindowStyle Hidden* OR *psexec* OR *wmic /node*)
```

This single query catches ALL of the following attack categories in one search:

## Detection Breakdown

### 1. Reconnaissance
```kql
winlog.event_data.CommandLine:(*whoami* OR *net user* OR *net localgroup* OR *ipconfig /all*)
```
- **MITRE ATT&CK:** T1033 (System Owner/User Discovery), T1087 (Account Discovery)
- **Why suspicious:** Attackers map the environment after initial access
- **Evidence:** 3 `whoami /all` hits and multiple `net user`/`net localgroup` hits from test

### 2. Encoded/Obfuscated PowerShell
```kql
winlog.event_data.CommandLine:(*-enc* OR *-ExecutionPolicy Bypass* OR *-WindowStyle Hidden*)
```
- **MITRE ATT&CK:** T1059.001 (PowerShell), T1027 (Obfuscated Files)
- **Why suspicious:** Encoding hides the actual command from basic log review
- **Evidence:** Captured encoded PowerShell with full base64 string visible in Sysmon logs

### 3. Credential Dumping
```kql
winlog.event_data.CommandLine:(*Invoke-Mimikatz* OR *sekurlsa* OR *procdump* OR *lsass*)
```
- **MITRE ATT&CK:** T1003.001 (LSASS Memory)
- **Why suspicious:** Extracting credentials from memory for lateral movement

### 4. Persistence
```kql
winlog.event_data.CommandLine:(*schtasks /create* OR *reg add*CurrentVersion*Run*)
```
- **MITRE ATT&CK:** T1053.005 (Scheduled Task), T1547.001 (Registry Run Keys)
- **Why suspicious:** Ensures attacker maintains access after reboot

### 5. Lateral Movement
```kql
winlog.event_data.CommandLine:(*psexec* OR *wmic /node*)
```
- **MITRE ATT&CK:** T1021.002 (SMB/Windows Admin Shares), T1047 (WMI)
- **Why suspicious:** Moving from compromised host to other systems

## Key Lessons Learned

- **Sysmon Event ID 1 captures full command lines** — this is why Sysmon is essential. Windows Security Event 4688 doesn't log command lines by default.
- **Parent process matters:** All recon commands shared the same `ParentProcessGuid`, proving they came from one PowerShell session. In a real attack, you'd trace this back to find the initial compromise.
- **Living-off-the-land (LOLBins):** Every command used above (`whoami`, `net`, `ipconfig`, `powershell`) is a legitimate Windows binary. Attackers use built-in tools to avoid detection — you can't just block these executables.
- **Base64 encoding is visible in logs:** Even though the attacker tried to hide the command with `-enc`, Sysmon still captured the full base64 string, which can be decoded for analysis.
