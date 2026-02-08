I failed 10 logins on purpose yesterday. 😅

Then I hunted for them. 🔍

I'm building an AI-Powered SOC Analyst Training Lab from scratch -- and documenting every step.

Here's what 5 lessons in looks like 👇

I deployed an entire ELK Stack in Azure:
🔹 Elasticsearch
🔹 Kibana
🔹 Winlogbeat
🔹 Sysmon
🔹 Windows target VM generating real attack telemetry

Then I started breaking things. 💥

I ran recon commands like an attacker would:
⚡ whoami /all
⚡ net user
⚡ net localgroup administrators

I encoded PowerShell in base64 to simulate evasion. 🥷

Then I switched hats and hunted for every single event in Kibana. 🎯

The biggest lesson so far?

📖 Documentation lies.

The textbook said search user.name for failed logins.
The real field was winlog.event_data.TargetUserName. 🤦

The lesson plan said Event ID 4688 captures process creation.
It doesn't -- unless you manually enable the audit policy.
Sysmon Event ID 1 does it better out of the box. 💡

You only learn this by getting your hands dirty. 🛠️

5 lessons down. 7 weeks to go. 🚀

What I've covered so far:
✅ Windows Event Log analysis (4624, 4625, 4720, 4732)
✅ KQL threat hunting queries in Kibana
✅ Sysmon parent-child process tracking with ProcessGuid
✅ Command line analysis: encoded PowerShell, LOLBins, recon detection
✅ Built Python tooling for Azure security scanning and log forwarding

Next up: mapping everything to the MITRE ATT&CK framework. 🗺️

If you're trying to break into cybersecurity, stop watching tutorials. 🛑

Build. Break. Hunt. Repeat. 🔁

What's the hardest thing you've learned by doing instead of reading? 👇

#SOCAnalyst #CyberSecurity #ThreatHunting #ELKStack #Sysmon #Azure #BlueTeam #InfoSec #CyberSecurityTraining #HandsOnLearning
