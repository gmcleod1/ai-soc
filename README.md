# AI-Powered SOC Analyst Agent

An intelligent Security Operations Center (SOC) agent powered by Claude AI that automates Level 1 security analyst tasks, analyzes security events from Azure ELK Stack, and provides actionable incident reports.

## Features

### Automated Security Analysis
- Analyzes security events and logs using Claude Sonnet 4
- Extracts indicators (IPs, hashes, CVEs, usernames, timestamps)
- Correlates findings to identify attack patterns
- Assesses severity: CRITICAL, HIGH, MEDIUM, LOW
- Generates detailed incident reports with recommendations

### Security Tools (10 integrated tools)

#### Threat Intelligence
- **IP Reputation**: AbuseIPDB integration for malicious IP detection
- **CVE Lookup**: NIST NVD integration for vulnerability analysis
- **File Hash Analysis**: VirusTotal integration for malware detection

#### ELK Stack Queries
- **Failed Login Detection**: Windows Event 4625 + Linux auth failures
- **Suspicious Process Monitoring**: PowerShell, cmd, scripting engines
- **Network Connection Tracking**: Outbound connection analysis
- **Brute Force Detection**: IP-based aggregation of failed attempts
- **Custom Lucene Queries**: Flexible log querying

#### Log Parsing & Reporting
- Generic log file parsing
- Microsoft Sentinel JSON export parsing
- Automated incident report generation (JSON format)

## Architecture

```
┌─────────────────────────────────────────┐
│  Claude Sonnet 4 (AI Orchestrator)      │
│  Analyzes events & decides tool usage   │
└────────────┬────────────────────────────┘
             │
             v
┌─────────────────────────────────────────┐
│  SOC Tools Layer                        │
│  • Threat Intel APIs                    │
│  • ELK Stack Queries                    │
│  • Log Parsing                          │
│  • Incident Reporting                   │
└──────┬──────────────────────────────┬───┘
       │                              │
       v                              v
┌────────────────┐      ┌─────────────────────┐
│ External APIs  │      │ Azure ELK Stack     │
│ • AbuseIPDB    │      │ • Elasticsearch     │
│ • NIST NVD     │      │ • Filebeat          │
│ • VirusTotal   │      │ • Winlogbeat        │
└────────────────┘      │ • Packetbeat        │
                        └─────────────────────┘
```

## Prerequisites

- Python 3.8+
- Azure ELK Stack (Elasticsearch + Beats)
- API Keys for:
  - Anthropic Claude API
  - AbuseIPDB
  - VirusTotal

## Installation

1. Clone the repository
```bash
git clone https://github.com/yourusername/ai-soc.git
cd ai-soc
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Configure environment variables
```bash
cp .env.example .env
# Edit .env with your API keys and ELK credentials
```

4. Set up your `.env` file with:
   - `ANTHROPIC_API_KEY`: Get from [Anthropic Console](https://console.anthropic.com/)
   - `ABUSEIPDB_API_KEY`: Get from [AbuseIPDB](https://www.abuseipdb.com/)
   - `VIRUSTOTAL_API_KEY`: Get from [VirusTotal](https://www.virustotal.com/)
   - `ELK_HOST`: Your Azure Elasticsearch endpoint
   - `ELK_USERNAME` & `ELK_PASSWORD`: Your ELK credentials

## Usage

### Basic Security Event Analysis

```python
from soc_agent import analyze_security_event

# Analyze a security event
analyze_security_event(
    "Failed login attempt from 45.142.212.61 for user 'admin' at 2024-02-04 10:15:23"
)
```

### Query ELK Stack

```python
from elk_connector import ELKConnector

elk = ELKConnector()

# Query failed logins
failed_logins = elk.query_failed_logins(hours=24, source_ip="192.168.1.100")

# Detect brute force attacks
brute_force = elk.aggregate_by_source_ip(hours=1, top_n=10)

# Query suspicious processes
suspicious = elk.query_suspicious_processes(hostname="WORKSTATION-01", hours=24)
```

### Workflow Example

1. Agent receives security event description
2. Claude analyzes and extracts indicators
3. Agent calls relevant tools:
   - Checks IP reputation
   - Queries ELK for related events
   - Looks up CVE details
   - Checks file hashes
4. Claude correlates findings
5. Generates incident report with:
   - Severity assessment
   - Detailed findings
   - Actionable recommendations
6. Saves report to `reports/INC-YYYYMMDD-HHMMSS.json`

## Expected Index Patterns

Your Azure ELK Stack should have these index patterns:
- `winlogbeat-*` - Windows Event Logs
- `filebeat-*` - General logs (Linux, Syslog, etc.)
- `packetbeat-*` - Network traffic

## Project Structure

```
ai-soc/
├── soc_agent.py          # Main agent orchestration
├── soc_tools.py          # Security tool definitions
├── elk_connector.py      # Elasticsearch integration
├── requirements.txt      # Python dependencies
├── .env.example          # Environment template
├── reports/              # Generated incident reports
└── logs/                 # Log storage
    └── sentinel/         # Microsoft Sentinel exports
```

## Security Considerations

- Never commit `.env` file (contains API keys)
- Incident reports may contain sensitive data
- Use proper RBAC on ELK Stack
- Consider encryption for reports at rest
- Review API rate limits

## Severity Guidelines

- **CRITICAL**: Active breach, data exfiltration, ransomware, critical system compromise
- **HIGH**: Confirmed malicious activity, successful brute force, lateral movement
- **MEDIUM**: Suspicious activity requiring investigation, policy violations
- **LOW**: Informational, likely false positive, minimal risk

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## License

MIT License

## Disclaimer

This tool is for authorized security monitoring only. Ensure you have proper authorization before deploying in any environment.
