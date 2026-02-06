# azure_to_elk.py
# Azure Activity Log to Elasticsearch Forwarder
# Polls Azure Activity Logs and indexes them into Elasticsearch
# for unified cloud + endpoint security monitoring in Kibana
# Referenced in SOC Analyst Training - Lesson 12.1

import subprocess
import json
import os
import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

load_dotenv()

POLL_INTERVAL_SECONDS = 300  # 5 minutes
LOOKBACK_MINUTES = 15


def get_elk_client():
    """Create Elasticsearch client from environment variables."""
    return Elasticsearch(
        [os.environ.get("ELK_HOST", "http://localhost:9200")],
        basic_auth=(
            os.environ.get("ELK_USERNAME", "elastic"),
            os.environ.get("ELK_PASSWORD", "")
        ),
        verify_certs=False
    )


def fetch_activity_logs(minutes_back=15):
    """Fetch Azure Activity Logs using Azure CLI."""
    start_time = (datetime.utcnow() - timedelta(minutes=minutes_back)).strftime("%Y-%m-%dT%H:%M:%SZ")

    cmd = f"az monitor activity-log list --start-time {start_time} --output json"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[ERROR] Azure CLI failed: {result.stderr}")
        return []

    try:
        return json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        print("[ERROR] Failed to parse Azure CLI output")
        return []


def transform_log(log):
    """Transform an Azure Activity Log entry into an ELK-friendly document."""
    operation = log.get("operationName", {})
    status = log.get("status", {})

    return {
        "@timestamp": log.get("eventTimestamp"),
        "azure.activity.caller": log.get("caller"),
        "azure.activity.operation": operation.get("localizedValue") if isinstance(operation, dict) else str(operation),
        "azure.activity.status": status.get("localizedValue") if isinstance(status, dict) else str(status),
        "azure.activity.resource_group": log.get("resourceGroupName"),
        "azure.activity.resource_id": log.get("resourceId"),
        "azure.activity.category": log.get("category", {}).get("localizedValue", "") if isinstance(log.get("category"), dict) else str(log.get("category", "")),
        "azure.activity.level": log.get("level"),
        "azure.activity.correlation_id": log.get("correlationId"),
        "azure.activity.subscription_id": log.get("subscriptionId"),
        "event.kind": "event",
        "event.category": "configuration",
        "event.type": "change",
        "cloud.provider": "azure"
    }


def index_logs(es, logs):
    """Index transformed logs into Elasticsearch."""
    indexed = 0
    index_name = f"azure-activity-{datetime.utcnow().strftime('%Y.%m.%d')}"

    for log in logs:
        doc = transform_log(log)
        try:
            es.index(index=index_name, document=doc)
            indexed += 1
        except Exception as e:
            print(f"[ERROR] Failed to index document: {e}")

    return indexed


def run_once(es, minutes_back=15):
    """Single poll cycle: fetch and index."""
    logs = fetch_activity_logs(minutes_back)
    if logs:
        count = index_logs(es, logs)
        print(f"[{datetime.utcnow().isoformat()}] Indexed {count}/{len(logs)} Azure Activity Log events")
    else:
        print(f"[{datetime.utcnow().isoformat()}] No new Activity Log events")


def main():
    print("=" * 50)
    print("Azure Activity Log -> Elasticsearch Forwarder")
    print("=" * 50)
    print(f"ELK Host: {os.environ.get('ELK_HOST', 'not set')}")
    print(f"Poll interval: {POLL_INTERVAL_SECONDS}s")
    print(f"Lookback: {LOOKBACK_MINUTES} minutes")
    print()

    es = get_elk_client()

    # Verify ELK connection
    try:
        info = es.info()
        print(f"Connected to Elasticsearch {info['version']['number']}")
    except Exception as e:
        print(f"[ERROR] Cannot connect to Elasticsearch: {e}")
        print("Check your ELK_HOST, ELK_USERNAME, and ELK_PASSWORD in .env")
        return

    # Verify Azure CLI
    result = subprocess.run("az account show --output json", shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print("[ERROR] Azure CLI not authenticated. Run 'az login' first.")
        return
    account = json.loads(result.stdout)
    print(f"Azure subscription: {account.get('name', 'unknown')}")
    print()

    print("Starting continuous polling (Ctrl+C to stop)...\n")
    try:
        while True:
            run_once(es, LOOKBACK_MINUTES)
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nForwarder stopped.")


if __name__ == "__main__":
    main()
