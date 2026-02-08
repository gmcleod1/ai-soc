# Lesson 2.1 Assignment: Parent-Child Process Relationship

## Task
Run `cmd.exe` which launches `ipconfig.exe`. Find both events in Sysmon logs and document the parent-child relationship using ProcessGuid fields.

## Findings

### cmd.exe (Parent Process)
- **Event ID:** 1 (Process Create)
- **Timestamp:** Feb 8, 2026 @ 18:35:31.309
- **Description:** Windows Command Processor
- **User:** SYSTEM
- **ProcessGuid:** `{606dbbb8-ad38-6988-9904-000000000500}`

### ipconfig.exe (Child Process)
- **Event ID:** 1 (Process Create)
- **Timestamp:** Feb 8, 2026 @ 11:24:27.109
- **Description:** IP Configuration Utility
- **ParentProcessGuid:** `{606dbbb8-b8bb-6988-7408-000000000500}`
- **ProcessGuid:** `{606dbbb8-b8bb-6988-7508-000000000500}`

### Process Chain
```
cmd.exe (parent) --> ipconfig.exe (child)
```

The `ParentProcessGuid` of ipconfig.exe matches the `ProcessGuid` of the cmd.exe process that spawned it, proving the parent-child relationship.

## Why This Matters for SOC Analysts

Parent-child process tracking is critical for detecting attacks:

| Suspicious Chain | What It Indicates |
|-----------------|-------------------|
| outlook.exe > powershell.exe | Phishing email executing malicious code |
| word.exe > cmd.exe > whoami | Macro-based malware doing reconnaissance |
| svchost.exe > cmd.exe > net.exe | Potential lateral movement |
| explorer.exe > powershell.exe -enc | Encoded PowerShell from user interaction |

**Key takeaway:** Sysmon Event ID 1 provides the `ProcessGuid` and `ParentProcessGuid` fields that allow you to reconstruct entire process trees. Windows Security Event 4688 does not include GUIDs, making Sysmon far more valuable for incident response.

## Sysmon vs Windows Security Logs

| Feature | Windows Security (4688) | Sysmon (Event ID 1) |
|---------|------------------------|---------------------|
| Command line | Requires audit policy | Always included |
| Parent process | Limited | Full path + GUID |
| File hash | Not available | MD5/SHA256/IMPHASH |
| Process GUID | Not available | Unique tracking ID |
| Enabled by default | No (audit policy) | Yes (with Sysmon installed) |
