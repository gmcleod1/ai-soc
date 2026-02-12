# KQL Field Reference & Query Cheat Sheet

Quick reference for Kibana queries in this SOC lab. All queries use the `winlogbeat-*` data view unless noted.

---

## Field Name Mapping

Winlogbeat stores Windows event data under `winlog.event_data.*`, NOT the ECS (Elastic Common Schema) fields shown in most tutorials.

| What You Want | WRONG (ECS) | CORRECT (Winlogbeat) | Notes |
|--------------|-------------|---------------------|-------|
| Username | `user.name` | `winlog.event_data.TargetUserName` | For logon events (4624, 4625) |
| Subject user | N/A | `winlog.event_data.SubjectUserName` | Who performed the action |
| Command line | `process.command_line` | `winlog.event_data.CommandLine` | Sysmon Event 1 |
| Source IP | `source.ip` | `winlog.event_data.IpAddress` | Often empty - use LogonType instead |
| Logon type | N/A | `winlog.event_data.LogonType` | 2=Interactive, 3=Network, 10=RDP |
| Parent process | `process.parent.name` | `winlog.event_data.ParentImage` | Full path in Sysmon |
| Process name | `process.name` | `process.name` | Works for Sysmon events |
| Process (Sysmon) | N/A | `winlog.event_data.Image` | Full path of executable |
| PowerShell | `process.name:powershell.exe` | `winlog.event_data.Description:"Windows PowerShell"` | More reliable filter |
| Target process | N/A | `winlog.event_data.TargetImage` | Sysmon Event 10 |
| Source process | N/A | `winlog.event_data.SourceImage` | Sysmon Event 10 |
| Access mask | N/A | `winlog.event_data.GrantedAccess` | Sysmon Event 10 |
| DNS query | `dns.question.name` | `winlog.event_data.QueryName` | Sysmon Event 22 |
| Registry target | N/A | `winlog.event_data.TargetObject` | Sysmon Event 13 |
| File created | N/A | `winlog.event_data.TargetFilename` | Sysmon Event 11 |
| Group name | `group.name` | `winlog.event_data.TargetUserName` | For Event 4732 (group membership) |
| Event ID | `event.code` | `event.code` | Works as-is |
| Timestamp | `@timestamp` | `@timestamp` | Works as-is |

---

## Queries by Event ID

### Windows Security Events

**Event 4624 - Successful Logon**
```
event.code:4624
event.code:4624 AND winlog.event_data.LogonType:10
event.code:4624 AND winlog.event_data.TargetUserName:azureuser
```

**Event 4625 - Failed Logon**
```
event.code:4625
event.code:4625 AND winlog.event_data.TargetUserName:"fakeuser"
event.code:4625 AND winlog.event_data.TargetUserName:*admin*
```

**Event 4648 - Explicit Credentials**
```
event.code:4648
event.code:4648 AND winlog.event_data.TargetUserName:*admin*
```

**Event 4672 - Admin Privileges Assigned**
```
event.code:4672
event.code:4672 AND winlog.event_data.SubjectUserName:azureuser
```

**Event 4697 - Service Installed**
```
event.code:4697
```

**Event 4698 - Scheduled Task Created**
```
event.code:4698
event.code:4698 AND NOT winlog.event_data.TaskName:(*Microsoft* OR *Windows*)
```

**Event 4720 - User Account Created**
```
event.code:4720
```

**Event 4732 - User Added to Group**
```
event.code:4732
event.code:4732 AND winlog.event_data.TargetUserName:"Administrators"
```

### Sysmon Events

**Event 1 - Process Creation**
```
event.code:1
event.code:1 AND winlog.event_data.Description:"Windows PowerShell"
event.code:1 AND winlog.event_data.CommandLine:*whoami*
event.code:1 AND winlog.event_data.CommandLine:*-enc*
event.code:1 AND winlog.event_data.CommandLine:*net* AND winlog.event_data.CommandLine:*user*
event.code:1 AND process.name:cmd.exe
```

**Event 3 - Network Connection**
```
event.code:3
event.code:3 AND winlog.event_data.DestinationPort:443
```

**Event 10 - Process Access (Credential Dumping)**
```
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe
event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:(*svchost* OR *csrss* OR *wmiprvse*)
```

**Event 11 - File Created**
```
event.code:11
event.code:11 AND winlog.event_data.TargetFilename:*Temp*
```

**Event 13 - Registry Value Set**
```
event.code:13
event.code:13 AND winlog.event_data.TargetObject:*CurrentVersion\\Run*
```

**Event 22 - DNS Query**
```
event.code:22
event.code:22 AND winlog.event_data.QueryName:*suspicious-domain*
```

---

## Queries by ATT&CK Technique

| Technique | ID | KQL Query |
|-----------|-----|-----------|
| Brute Force | T1110 | `event.code:4625` (aggregate by TargetUserName) |
| Password Spray | T1110.003 | `event.code:4625` (multiple usernames, same timeframe) |
| LSASS Dump | T1003.001 | `event.code:10 AND winlog.event_data.TargetImage:*lsass.exe AND NOT winlog.event_data.SourceImage:(*svchost* OR *csrss*)` |
| Create Account | T1136.001 | `event.code:4720` |
| Scheduled Task | T1053.005 | `event.code:4698` or `event.code:1 AND winlog.event_data.CommandLine:(*schtasks* AND *create*)` |
| PowerShell Exec | T1059.001 | `event.code:1 AND winlog.event_data.Description:"Windows PowerShell" AND winlog.event_data.CommandLine:(*-enc* OR *DownloadString* OR *IEX*)` |
| Discovery | T1087 | `event.code:1 AND winlog.event_data.CommandLine:(*whoami* OR *net user* OR *net localgroup* OR *ipconfig* OR *systeminfo*)` |
| Lateral Movement (RDP) | T1021.001 | `event.code:4624 AND winlog.event_data.LogonType:10` |
| Lateral Movement (WMI) | T1047 | `event.code:1 AND winlog.event_data.ParentImage:*WmiPrvSE.exe` |
| LOLBin Downloads | T1105 | `event.code:1 AND process.name:(certutil.exe OR bitsadmin.exe) AND winlog.event_data.CommandLine:*http*` |
| Registry Persistence | T1547.001 | `event.code:13 AND winlog.event_data.TargetObject:*CurrentVersion\\Run*` |
| Windows Service | T1543.003 | `event.code:4697` |

---

## Logon Type Reference

| Type | Name | Meaning |
|------|------|---------|
| 2 | Interactive | Console/keyboard logon |
| 3 | Network | SMB, net use, PsExec |
| 4 | Batch | Scheduled task |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached credentials |

---

## Common Gotchas

1. **`winlog.event_data.IpAddress` is often empty** - Use `winlog.event_data.LogonType:10` to filter RDP logons instead
2. **Event ID 4688 may show no results** - Requires "Audit Process Creation" policy enabled. Use Sysmon Event ID 1 instead
3. **`process.name` works for Sysmon** but not for Windows Security events
4. **Wildcards need asterisks on both sides** for partial matches: `*admin*` not `admin`
5. **Field names are case-sensitive** - `CommandLine` not `commandline`
