# parse_flow_logs.py
# NSG Flow Log Parser
# Parses Azure NSG Flow Log JSON files and produces a network security report
# Referenced in SOC Analyst Training - Lesson 9.2

import json
import os
import sys
from collections import Counter
from datetime import datetime


def parse_flow_file(filepath):
    """Parse a single NSG Flow Log JSON file."""
    with open(filepath, "r") as f:
        data = json.load(f)

    flows = []

    for record in data.get("records", []):
        record_time = record.get("time", "")
        nsg = record.get("resourceId", "").split("/")[-1] if record.get("resourceId") else "unknown"

        for flow_group in record.get("properties", {}).get("flows", []):
            rule = flow_group.get("rule", "unknown")

            for flow_set in flow_group.get("flows", []):
                for tuple_str in flow_set.get("flowTuples", []):
                    parts = tuple_str.split(",")
                    if len(parts) < 8:
                        continue

                    flow = {
                        "timestamp": parts[0],
                        "src_ip": parts[1],
                        "dst_ip": parts[2],
                        "src_port": parts[3],
                        "dst_port": parts[4],
                        "protocol": "TCP" if parts[5] == "T" else "UDP",
                        "direction": "Inbound" if parts[6] == "I" else "Outbound",
                        "action": "Allowed" if parts[7] == "A" else "Denied",
                        "rule": rule,
                        "nsg": nsg
                    }

                    # Version 2 has additional fields
                    if len(parts) >= 12:
                        flow["packets_src"] = int(parts[8]) if parts[8] else 0
                        flow["bytes_src"] = int(parts[9]) if parts[9] else 0
                        flow["packets_dst"] = int(parts[10]) if parts[10] else 0
                        flow["bytes_dst"] = int(parts[11]) if parts[11] else 0

                    flows.append(flow)

    return flows


def parse_directory(dirpath):
    """Parse all JSON files in a directory tree."""
    all_flows = []

    for root, dirs, files in os.walk(dirpath):
        for filename in files:
            if filename.endswith(".json"):
                filepath = os.path.join(root, filename)
                try:
                    flows = parse_flow_file(filepath)
                    all_flows.extend(flows)
                except Exception as e:
                    print(f"[WARN] Failed to parse {filepath}: {e}")

    return all_flows


def analyze_flows(flows):
    """Analyze parsed flows and produce a report."""
    if not flows:
        print("\nNo flow data found.")
        return

    allowed = [f for f in flows if f["action"] == "Allowed"]
    denied = [f for f in flows if f["action"] == "Denied"]
    inbound = [f for f in flows if f["direction"] == "Inbound"]
    outbound = [f for f in flows if f["direction"] == "Outbound"]

    print(f"\n{'=' * 60}")
    print(f"NSG FLOW LOG ANALYSIS REPORT")
    print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Flows: {len(flows)}")
    print(f"{'=' * 60}\n")

    # Summary
    print(f"--- SUMMARY ---")
    print(f"  Allowed: {len(allowed)}")
    print(f"  Denied:  {len(denied)}")
    print(f"  Inbound: {len(inbound)}")
    print(f"  Outbound: {len(outbound)}")
    print()

    # Top source IPs (all traffic)
    src_counter = Counter(f["src_ip"] for f in flows)
    print(f"--- TOP SOURCE IPs (all traffic) ---")
    for ip, count in src_counter.most_common(10):
        print(f"  {ip}: {count} flows")
    print()

    # Top destination ports
    port_counter = Counter(f["dst_port"] for f in flows)
    well_known = {"22": "SSH", "80": "HTTP", "443": "HTTPS", "3389": "RDP", "5601": "Kibana", "9200": "Elasticsearch", "445": "SMB"}
    print(f"--- TOP DESTINATION PORTS ---")
    for port, count in port_counter.most_common(10):
        label = well_known.get(port, "")
        suffix = f" ({label})" if label else ""
        print(f"  {port}{suffix}: {count} flows")
    print()

    # Denied flows (potential scanning or unauthorized access)
    if denied:
        print(f"--- DENIED FLOWS ({len(denied)}) ---")
        denied_src = Counter(f["src_ip"] for f in denied)
        print(f"  Top denied source IPs:")
        for ip, count in denied_src.most_common(10):
            print(f"    {ip}: {count} denied attempts")

        denied_ports = Counter(f["dst_port"] for f in denied)
        print(f"\n  Top denied destination ports:")
        for port, count in denied_ports.most_common(10):
            label = well_known.get(port, "")
            suffix = f" ({label})" if label else ""
            print(f"    {port}{suffix}: {count} denied attempts")

        # Show sample denied flows
        print(f"\n  Sample denied flows (first 10):")
        for d in denied[:10]:
            print(f"    {d['src_ip']}:{d['src_port']} -> {d['dst_ip']}:{d['dst_port']} [{d['protocol']}] Rule: {d['rule']}")
        print()

    # Outbound external connections
    external_outbound = [f for f in outbound if f["action"] == "Allowed" and not f["dst_ip"].startswith(("10.", "172.16.", "192.168."))]
    if external_outbound:
        print(f"--- OUTBOUND EXTERNAL CONNECTIONS ({len(external_outbound)}) ---")
        ext_dst = Counter(f["dst_ip"] for f in external_outbound)
        print(f"  Top external destinations:")
        for ip, count in ext_dst.most_common(10):
            print(f"    {ip}: {count} connections")
        print()

    # Rules summary
    rule_counter = Counter(f["rule"] for f in flows)
    print(f"--- NSG RULES HIT ---")
    for rule, count in rule_counter.most_common():
        print(f"  {rule}: {count} flows")
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_flow_logs.py <path-to-flow-logs>")
        print("  <path> can be a single JSON file or a directory of flow log files")
        sys.exit(1)

    path = sys.argv[1]

    if os.path.isfile(path):
        flows = parse_flow_file(path)
    elif os.path.isdir(path):
        flows = parse_directory(path)
    else:
        print(f"Error: '{path}' not found")
        sys.exit(1)

    analyze_flows(flows)

    # Save parsed data to JSON for further analysis
    output_file = "parsed-flow-logs.json"
    with open(output_file, "w") as f:
        json.dump(flows, f, indent=2)
    print(f"Parsed flow data saved to: {output_file}")


if __name__ == "__main__":
    main()
