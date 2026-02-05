# soc_tools.py
import requests
import json
from datetime import datetime
import os
from elk_connector import ELKConnector

# Initialize ELK connector at module level
elk = ELKConnector()

# ============================================================================
# THREAT INTELLIGENCE TOOLS
# ============================================================================

def check_ip_reputation(ip_address):
    """Check IP reputation using AbuseIPDB API"""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return json.dumps({"error": "AbuseIPDB API key not configured"})
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        if "data" in data:
            return json.dumps({
                "ip": ip_address,
                "abuse_score": data["data"]["abuseConfidenceScore"],
                "total_reports": data["data"]["totalReports"],
                "country": data["data"]["countryCode"],
                "is_public": data["data"]["isPublic"],
                "is_whitelisted": data["data"]["isWhitelisted"]
            })
        return json.dumps({"error": "No data returned"})
    except Exception as e:
        return json.dumps({"error": str(e)})

def lookup_cve(cve_id):
    """Look up CVE from NIST NVD API"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
            vuln = data["vulnerabilities"][0]["cve"]
            
            cvss_score = "N/A"
            severity = "N/A"
            if "metrics" in vuln:
                if "cvssMetricV31" in vuln["metrics"]:
                    cvss_score = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    severity = vuln["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            
            return json.dumps({
                "cve_id": cve_id,
                "description": vuln["descriptions"][0]["value"],
                "cvss_score": cvss_score,
                "severity": severity,
                "published": vuln.get("published", "N/A")
            })
        return json.dumps({"error": "CVE not found"})
    except Exception as e:
        return json.dumps({"error": str(e)})

def check_file_hash(file_hash):
    """Check file hash on VirusTotal"""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return json.dumps({"error": "VirusTotal API key not configured"})
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        data = response.json()
        
        if "data" in data:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return json.dumps({
                "hash": file_hash,
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "undetected": stats["undetected"],
                "harmless": stats["harmless"],
                "total_scans": sum(stats.values())
            })
        return json.dumps({"error": "Hash not found"})
    except Exception as e:
        return json.dumps({"error": str(e)})

# ============================================================================
# ELK STACK TOOLS
# ============================================================================

def query_elk_logs(query, index_pattern="*", time_range_minutes=60):
    """Query ELK stack for security events"""
    return elk.query_logs(index_pattern, query, time_range_minutes)

def query_failed_logins_elk(ip_address=None, username=None, hours=24):
    """Query ELK for failed login attempts"""
    return elk.query_failed_logins(ip_address, username, hours * 60)

def query_suspicious_processes_elk(hostname, hours=1):
    """Query ELK for suspicious process execution"""
    return elk.query_suspicious_processes(hostname, hours * 60)

def aggregate_brute_force_attempts(hours=1):
    """Find top IPs with failed login attempts"""
    return elk.aggregate_by_source_ip(time_range_minutes=hours * 60)

# ============================================================================
# FILE PARSING TOOLS
# ============================================================================

def parse_log_file(file_path):
    """Read and return contents of a log file"""
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

def parse_sentinel_logs(file_path):
    """Parse Sentinel JSON log exports"""
    try:
        with open(file_path, 'r') as f:
            logs = json.load(f)
        
        formatted = []
        for log in logs:
            formatted.append(
                f"Time: {log.get('TimeGenerated', 'N/A')} | "
                f"Computer: {log.get('Computer', 'N/A')} | "
                f"EventID: {log.get('EventID', 'N/A')} | "
                f"Account: {log.get('Account', 'N/A')} | "
                f"IP: {log.get('IpAddress', 'N/A')}"
            )
        
        return "\n".join(formatted)
    except Exception as e:
        return f"Error parsing Sentinel logs: {str(e)}"

# ============================================================================
# REPORTING TOOLS
# ============================================================================

def create_incident_report(title, severity, findings, recommendations):
    """Create incident report and save to disk"""
    os.makedirs("reports", exist_ok=True)
    
    ticket_id = f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    report = {
        "id": ticket_id,
        "title": title,
        "severity": severity,
        "findings": findings,
        "recommendations": recommendations,
        "created": datetime.now().isoformat()
    }
    
    filename = f"reports/{ticket_id}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    
    return f"Report saved: {filename}"

# ============================================================================
# TOOL DEFINITIONS FOR CLAUDE
# ============================================================================

SOC_TOOLS = [
    # Threat Intel
    {
        "name": "check_ip_reputation",
        "description": "Check IP address reputation using AbuseIPDB threat intelligence",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "IP address to check"}
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "lookup_cve",
        "description": "Look up CVE vulnerability details from NIST NVD",
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2024-1234)"}
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "check_file_hash",
        "description": "Check file hash against VirusTotal",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {"type": "string", "description": "MD5, SHA1, or SHA256 hash"}
            },
            "required": ["file_hash"]
        }
    },
    
    # ELK Stack Queries
    {
        "name": "query_elk_logs",
        "description": "Query ELK stack using Lucene query syntax. Searches across all beats (filebeat, winlogbeat, packetbeat)",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Lucene query (e.g., 'source.ip:192.168.1.1 AND event.code:4625')"},
                "index_pattern": {"type": "string", "default": "*", "description": "Index pattern (e.g., 'winlogbeat-*')"},
                "time_range_minutes": {"type": "integer", "default": 60, "description": "How far back to search in minutes"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "query_failed_logins_elk",
        "description": "Search ELK for failed login attempts (Windows Event 4625, Linux auth failures). Use to investigate authentication attacks.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string", "description": "Filter by source IP address"},
                "username": {"type": "string", "description": "Filter by username"},
                "hours": {"type": "integer", "default": 24, "description": "Time range in hours"}
            }
        }
    },
    {
        "name": "query_suspicious_processes_elk",
        "description": "Query ELK for suspicious process execution (PowerShell, cmd, scripting engines) on a specific host",
        "input_schema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Target hostname"},
                "hours": {"type": "integer", "default": 1, "description": "Time range in hours"}
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "aggregate_brute_force_attempts",
        "description": "Find top source IPs with failed login attempts for brute force detection",
        "input_schema": {
            "type": "object",
            "properties": {
                "hours": {"type": "integer", "default": 1, "description": "Time range in hours"}
            }
        }
    },
    
    # File Parsing
    {
        "name": "parse_log_file",
        "description": "Read and analyze a log file from disk",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to log file"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "parse_sentinel_logs",
        "description": "Parse Microsoft Sentinel JSON log exports",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to Sentinel JSON log file"}
            },
            "required": ["file_path"]
        }
    },
    
    # Reporting
    {
        "name": "create_incident_report",
        "description": "Create and save incident report with findings and recommendations",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Incident title"},
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "description": "Severity rating"},
                "findings": {"type": "string", "description": "Detailed findings from analysis"},
                "recommendations": {"type": "string", "description": "Recommended actions"}
            },
            "required": ["title", "severity", "findings", "recommendations"]
        }
    }
]

# Map tool names to functions
SOC_TOOL_FUNCTIONS = {
    "check_ip_reputation": check_ip_reputation,
    "lookup_cve": lookup_cve,
    "check_file_hash": check_file_hash,
    "query_elk_logs": query_elk_logs,
    "query_failed_logins_elk": query_failed_logins_elk,
    "query_suspicious_processes_elk": query_suspicious_processes_elk,
    "aggregate_brute_force_attempts": aggregate_brute_force_attempts,
    "parse_log_file": parse_log_file,
    "parse_sentinel_logs": parse_sentinel_logs,
    "create_incident_report": create_incident_report
}