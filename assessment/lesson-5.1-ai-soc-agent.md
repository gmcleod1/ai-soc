# Lesson 5.1: Using Your SOC Agent
**Date:** 2026-02-23
**Duration:** ~3 hours
**Platform:** Azure ELK Stack + Python SOC Agent (Claude AI)

---

## Objectives Completed

- [x] Understood SOC agent architecture (Python + Claude API + tool use loop)
- [x] Used AI to accelerate security investigations
- [x] Interpreted AI-generated incident reports
- [x] Validated AI findings against raw log data
- [x] Used multiple tools in sequence within a single investigation

---

## SOC Agent Architecture

```
User Prompt
    │
    ▼
soc_agent.py  →  Claude API (claude-sonnet-4-6)
                      │
                      │  tool_use loop (up to 10 iterations)
                      ▼
              soc_tools.py dispatcher
                ├── query_elk_logs          → Elasticsearch (Azure VM)
                ├── query_failed_logins_elk → Elasticsearch (Azure VM)
                ├── aggregate_brute_force   → Elasticsearch (Azure VM)
                ├── check_ip_reputation     → AbuseIPDB API
                ├── lookup_cve              → NIST NVD API
                ├── check_file_hash         → VirusTotal API
                └── create_incident_report  → local JSON report
                      │
                      ▼
              Claude analyzes results → Final Report
```

The agent uses the Anthropic tool use API: Claude receives the prompt plus tool definitions, decides which tools to call, receives results, and iterates until it has enough evidence to write a final analysis.

---

## Exercise 1: Failed Login Analysis

**Prompt:** "Analyze all failed login attempts in the last 24 hours and tell me if we're under attack"

**Tools Used (in order):**
1. `query_failed_logins_elk` (24h) - 1 result (Windows EventSystem suppression, not a real login)
2. `aggregate_brute_force_attempts` (24h) - 0 results
3. `query_elk_logs` with broad auth query - 569 events (all successful logons)
4. `check_ip_reputation` on 10.0.1.7 - 0% abuse score, no reports
5. `create_incident_report` - saved `INC-20260223-155937.json`

**AI Findings:**
- Zero genuine failed authentication events in last 24 hours
- 569 successful logons - all from legitimate sources (DC, localhost, internal network)
- Authentication protocols: Kerberos and NTLM (normal domain operations)
- No brute force patterns, no password spraying

**AI Verdict:** LOW RISK - environment shows normal, healthy authentication activity

**Manual Validation:** Confirmed via Kibana that the single Event ID 4625 was a Windows EventSystem message, not an actual failed login. The AI correctly identified this false positive.

---

## Exercise 2: PowerShell Hunt

**Prompt:** "Search for suspicious PowerShell processes with encoded commands on WinTarget-VM in the last 168 hours"

**Tools Used:**
1. `query_suspicious_processes_elk` (WinTarget-VM, 168h)
2. `query_elk_logs` filtering for `-EncodedCommand` / `-enc` parameters

**AI Findings:**
- Detected Base64-encoded PowerShell commands on WinTarget-VM
- Successfully decoded the commands - retrieved OS version information only
- Parent process: `gc_worker.exe` (Azure Guest Configuration service)
- Execution context: Microsoft Azure legitimate management service

**AI Verdict:** LOW RISK - normal Azure Guest Configuration activity, not malicious

**Key Takeaway:** AI correctly applied context (parent process, execution path) to rule out a false positive that would look suspicious in isolation. This demonstrates the value of AI-assisted triage vs. raw alert-based detection.

---

## AI vs. Manual Analysis Comparison

| Aspect | Manual (KQL) | AI-Assisted |
|--------|-------------|-------------|
| Time to first finding | ~5 min (write query, interpret) | ~30 sec (plain English prompt) |
| False positive handling | Requires analyst knowledge | AI uses context (parent process, source) |
| Multi-source correlation | Multiple separate queries | Single prompt, AI chains tools |
| Report generation | Manual write-up | Auto-generated, structured |
| Confidence score | Analyst judgment | Severity rating with evidence cited |

**When to use AI:** Initial triage, IP enrichment, multi-source correlation, report generation
**When to use manual KQL:** Precise hunting with known field names, custom aggregations, tuning detection rules

---

## Troubleshooting Resolved

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| `TypeError: NoneType` on startup | `ELKConnector()` init at module import before `load_dotenv()` runs | Added `load_dotenv()` to `elk_connector.py` |
| `BadRequestError: Accept version must be 8 or 7, found 9` | `elasticsearch` Python client v9.3.0 incompatible with ES 8.x server | Downgraded to `elasticsearch==8.19.3` |
| `prompt is too long: 203259 tokens` | Results included full `raw` source document per event | Removed `raw` field, capped results at 50, extracted key fields only |

---

## Incident Reports Generated

| Report ID | Title | Severity |
|-----------|-------|----------|
| INC-20260223-155937 | Authentication Activity Analysis - No Active Attack Detected | LOW |

---

## Key Lessons Learned

1. **Tool use loop is the core mechanism** - Claude iterates through tools until it has sufficient evidence, not just one query
2. **Context matters more than raw data** - The AI correctly dismissed encoded PowerShell because it checked the parent process
3. **Token budget management is critical** - Returning full documents from Elasticsearch will exceed LLM context limits; always extract only the fields you need
4. **AI accelerates triage, not replaces judgment** - The analyst still needs to validate AI findings against raw logs

---

## Proof

- `Proof/lesson-5.1-soc-agent-analysis.png` - Terminal output showing tool calls and final LOW RISK analysis
