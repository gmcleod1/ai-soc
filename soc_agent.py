# soc_agent.py
import anthropic
import os
from dotenv import load_dotenv
from soc_tools import SOC_TOOLS, SOC_TOOL_FUNCTIONS
import json

load_dotenv()

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SOC_ANALYST_PROMPT = """You are a Level 1 SOC Analyst analyzing security events.

Your workflow:
1. Analyze the event/log data provided
2. Extract indicators (IPs, hashes, CVEs, usernames, timestamps)
3. Enrich indicators using available tools
4. Correlate findings to identify attack patterns
5. Assess severity based on: threat level, business impact, exploitability
6. Document findings in an incident report
7. Provide clear, actionable recommendations

Severity guidelines:
- CRITICAL: Active breach, data exfil, ransomware, critical system compromise
- HIGH: Confirmed malicious activity, brute force success, lateral movement
- MEDIUM: Suspicious activity requiring investigation, policy violations
- LOW: Informational, false positive likely, minimal risk

Be thorough, cite evidence, explain your reasoning."""

def analyze_security_event(event_description):
    """Analyze a security event"""
    
    messages = [{"role": "user", "content": f"Analyze this security event:\n\n{event_description}"}]
    
    print(f"\n{'='*80}")
    print(f"🔒 SOC ANALYST AGENT")
    print(f"{'='*80}\n")
    
    iteration = 0
    max_iterations = 10
    
    while iteration < max_iterations:
        iteration += 1
        
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            system=SOC_ANALYST_PROMPT,
            tools=SOC_TOOLS,
            messages=messages
        )
        
        if response.stop_reason == "tool_use":
            messages.append({"role": "assistant", "content": response.content})
            
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    tool_name = block.name
                    tool_input = block.input
                    
                    print(f"🔧 [{iteration}] {tool_name}")
                    print(f"   Input: {json.dumps(tool_input, indent=2)}")
                    
                    tool_function = SOC_TOOL_FUNCTIONS[tool_name]
                    result = tool_function(**tool_input)
                    
                    print(f"   Result: {result[:200]}...\n" if len(result) > 200 else f"   Result: {result}\n")
                    
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result)
                    })
            
            messages.append({"role": "user", "content": tool_results})
        
        elif response.stop_reason == "end_turn":
            final_analysis = ""
            for block in response.content:
                if hasattr(block, "text"):
                    final_analysis += block.text
            
            print(f"{'='*80}")
            print(f"ANALYSIS COMPLETE")
            print(f"{'='*80}\n")
            print(final_analysis)
            print(f"\n{'='*80}\n")
            
            return final_analysis
        else:
            break
    
    return "Analysis incomplete"

if __name__ == "__main__":
    
    analyze_security_event(
        "Failed login attempt from 45.142.212.61 for user 'admin' at 2024-02-04 10:15:23"
    )