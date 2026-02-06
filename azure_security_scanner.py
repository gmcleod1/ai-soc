# azure_security_scanner.py
# Azure Security Posture Scanner
# Checks for common misconfigurations in your Azure environment
# Referenced in SOC Analyst Training - Lesson 10.2

import subprocess
import json
import sys
from datetime import datetime


def run_az(cmd):
    """Run an Azure CLI command and return parsed JSON output."""
    result = subprocess.run(
        f"az {cmd} --output json",
        shell=True,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        return None


def check_nsg_rules(resource_group, nsg_name):
    """Check for overly permissive NSG rules."""
    rules = run_az(f"network nsg rule list --resource-group {resource_group} --nsg-name {nsg_name}")
    if not rules:
        return [{"severity": "INFO", "finding": f"Could not retrieve NSG rules for {nsg_name}", "recommendation": "Verify NSG exists and you have access"}]

    findings = []
    sensitive_ports = {"22": "SSH", "3389": "RDP", "445": "SMB", "1433": "SQL Server", "3306": "MySQL", "5432": "PostgreSQL"}

    for rule in rules:
        src = rule.get("sourceAddressPrefix", "")
        access = rule.get("access", "")
        port = rule.get("destinationPortRange", "")
        name = rule.get("name", "")
        priority = rule.get("priority", "")

        if access != "Allow":
            continue

        if src in ["*", "0.0.0.0/0", "Internet"]:
            if port in sensitive_ports:
                findings.append({
                    "severity": "CRITICAL",
                    "finding": f"NSG rule '{name}' (priority {priority}) allows {sensitive_ports[port]} ({port}) from ANY source",
                    "recommendation": f"Restrict {sensitive_ports[port]} access to specific IP ranges"
                })
            elif port == "*":
                findings.append({
                    "severity": "CRITICAL",
                    "finding": f"NSG rule '{name}' (priority {priority}) allows ALL ports from ANY source",
                    "recommendation": "Restrict to specific ports and source IPs"
                })
            else:
                findings.append({
                    "severity": "HIGH",
                    "finding": f"NSG rule '{name}' (priority {priority}) allows port {port} from ANY source",
                    "recommendation": "Restrict source to specific IP ranges"
                })

    return findings


def check_public_ips(resource_group):
    """Check for VMs with public IP addresses."""
    ips = run_az(f"vm list-ip-addresses --resource-group {resource_group}")
    if not ips:
        return []

    findings = []
    for vm in ips:
        vm_name = vm.get("virtualMachine", {}).get("name", "unknown")
        for iface in vm.get("virtualMachine", {}).get("network", {}).get("publicIpAddresses", []):
            ip = iface.get("ipAddress", "N/A")
            findings.append({
                "severity": "MEDIUM",
                "finding": f"VM '{vm_name}' has public IP: {ip}",
                "recommendation": "Consider using Azure Bastion or VPN instead of public IPs for management access"
            })

    return findings


def check_storage_accounts(resource_group):
    """Check storage account security settings."""
    accounts = run_az(f"storage account list --resource-group {resource_group}")
    if not accounts:
        return []

    findings = []
    for acct in accounts:
        name = acct.get("name", "unknown")

        if acct.get("allowBlobPublicAccess", False):
            findings.append({
                "severity": "HIGH",
                "finding": f"Storage account '{name}' allows public blob access",
                "recommendation": "Disable public blob access unless explicitly required"
            })

        if not acct.get("enableHttpsTrafficOnly", True):
            findings.append({
                "severity": "MEDIUM",
                "finding": f"Storage account '{name}' does not enforce HTTPS-only traffic",
                "recommendation": "Enable HTTPS-only traffic to prevent data interception"
            })

        tls = acct.get("minimumTlsVersion", "")
        if tls and tls < "TLS1_2":
            findings.append({
                "severity": "MEDIUM",
                "finding": f"Storage account '{name}' allows TLS version below 1.2 (current: {tls})",
                "recommendation": "Set minimum TLS version to TLS 1.2"
            })

    return findings


def check_disk_encryption(resource_group):
    """Check if VM disks are encrypted."""
    vms = run_az(f"vm list --resource-group {resource_group} --query '[].name'")
    if not vms:
        return []

    findings = []
    for vm_name in vms:
        result = subprocess.run(
            f"az vm encryption show --resource-group {resource_group} --name {vm_name} --output json",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode != 0 or "not enabled" in result.stderr.lower() or not result.stdout.strip():
            findings.append({
                "severity": "MEDIUM",
                "finding": f"VM '{vm_name}' does not have disk encryption enabled",
                "recommendation": "Enable Azure Disk Encryption for data-at-rest protection"
            })

    return findings


def check_rbac(resource_group):
    """Check for over-privileged RBAC assignments."""
    assignments = run_az(f"role assignment list --resource-group {resource_group} --include-inherited")
    if not assignments:
        return []

    findings = []
    high_priv_roles = ["Owner", "Contributor", "User Access Administrator"]

    for assignment in assignments:
        role = assignment.get("roleDefinitionName", "")
        principal = assignment.get("principalName", "unknown")
        scope = assignment.get("scope", "")

        if role in high_priv_roles:
            severity = "HIGH" if role == "Owner" or role == "User Access Administrator" else "MEDIUM"
            findings.append({
                "severity": severity,
                "finding": f"'{principal}' has '{role}' role at scope: {scope}",
                "recommendation": f"Verify this {role} assignment follows least privilege. Consider Reader or a custom role."
            })

    return findings


def main():
    resource_group = "ELK-Security-Lab"
    nsg_name = "ELK-NSG"

    print(f"\n{'=' * 60}")
    print(f"AZURE SECURITY POSTURE ASSESSMENT")
    print(f"Resource Group: {resource_group}")
    print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}\n")

    all_findings = []

    print("[*] Checking NSG rules...")
    all_findings.extend(check_nsg_rules(resource_group, nsg_name))

    print("[*] Checking public IP addresses...")
    all_findings.extend(check_public_ips(resource_group))

    print("[*] Checking storage account security...")
    all_findings.extend(check_storage_accounts(resource_group))

    print("[*] Checking disk encryption...")
    all_findings.extend(check_disk_encryption(resource_group))

    print("[*] Checking RBAC assignments...")
    all_findings.extend(check_rbac(resource_group))

    print(f"\n{'=' * 60}")
    print(f"SCAN RESULTS")
    print(f"{'=' * 60}\n")

    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    print(f"  CRITICAL: {severity_counts['CRITICAL']}")
    print(f"  HIGH:     {severity_counts['HIGH']}")
    print(f"  MEDIUM:   {severity_counts['MEDIUM']}")
    print(f"  LOW:      {severity_counts['LOW']}")
    print(f"  INFO:     {severity_counts['INFO']}")
    print(f"  TOTAL:    {len(all_findings)}\n")

    # Print findings sorted by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    for i, f in enumerate(all_findings, 1):
        print(f"[{f['severity']}] Finding #{i}: {f['finding']}")
        print(f"  Recommendation: {f['recommendation']}\n")

    # Save results to JSON
    output_file = "azure-security-scan-results.json"
    with open(output_file, "w") as fout:
        json.dump({
            "scan_date": datetime.now().isoformat(),
            "resource_group": resource_group,
            "summary": severity_counts,
            "total_findings": len(all_findings),
            "findings": all_findings
        }, fout, indent=2)

    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
