# Lesson 1.2 Assignment: Critical Windows Event IDs

## Event ID Descriptions & Investigation Triggers

### Authentication Events

| Event ID | Name | Description | When to Investigate |
|----------|------|-------------|---------------------|
| **4624** | Successful Logon | An account was successfully logged on. Includes logon type (2=Interactive, 3=Network, 7=Unlock, 10=RDP, 11=Cached). | Logons at unusual hours, from unexpected IPs, or using service accounts interactively. Logon Type 10 from unknown external IPs is a red flag. |
| **4625** | Failed Logon | An account failed to log on. Shows failure reason (bad password, unknown user, account locked). | Multiple failures in short time = brute force. Failures against admin/service accounts. Failures from a single source IP hitting multiple accounts = password spray. |
| **4648** | Explicit Credential Logon | A logon was attempted using explicit credentials (runas, mapping a share with different creds). | Credential usage that doesn't match normal user behavior. Lateral movement often uses explicit credentials to access remote systems. |

### Privilege & Account Events

| Event ID | Name | Description | When to Investigate |
|----------|------|-------------|---------------------|
| **4672** | Special Privileges Assigned | Special privileges (SeDebugPrivilege, SeTakeOwnershipPrivilege, etc.) were assigned to a new logon. | Unexpected admin logons, especially from service accounts or during off-hours. This fires alongside 4624 for admin-level logons. |
| **4720** | User Account Created | A new user account was created. | Unauthorized account creation. Attackers create backdoor accounts for persistence. Always verify new accounts were requested through proper channels. |
| **4732** | Member Added to Security Group | A member was added to a security-enabled local group (e.g., Administrators). | Adding users to Administrators or other privileged groups without change control. Key indicator of privilege escalation. |

### Process & Service Events

| Event ID | Name | Description | When to Investigate |
|----------|------|-------------|---------------------|
| **4688** | Process Creation | A new process was created. Shows the executable path and parent process. | Suspicious parent-child chains (e.g., Word spawning PowerShell), execution from temp directories, encoded command-line arguments, LOLBins (certutil, mshta, regsvr32). |
| **4697** | Service Installed | A new service was installed in the system. | Unexpected services, especially those running as SYSTEM. Malware often installs itself as a service for persistence. |

## Key Logon Types (for Event 4624/4625)

| Type | Name | Meaning |
|------|------|---------|
| 2 | Interactive | Physical keyboard logon or runas |
| 3 | Network | Accessing a shared folder or printer |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP logon |
| 11 | CachedInteractive | Logon using cached domain credentials |

## Hands-On Evidence

- Filtered Event Viewer for 4625: Found 7 failed logon attempts including `fakeuser` test
- Filtered Event Viewer for 4624: Found 173 successful logons including RDP (Type 10) as `azureuser`
- Correlated 4625 events in Kibana using `event.code:4625` on `winlogbeat-*` index
- Confirmed Winlogbeat pipeline is shipping events from WinTarget-VM to Elasticsearch

## SOC Triage Notes

As a SOC analyst, the priority order for investigating these events:
1. **4625 clusters** (brute force) and **4720/4732** (unauthorized changes) are highest priority
2. **4688** with suspicious process chains indicates active compromise
3. **4697** (new services) indicates persistence mechanisms
4. **4624 + 4672** from unexpected sources indicates lateral movement or privilege abuse
5. **4648** helps trace credential-based lateral movement paths
