# elk_connector.py
from elasticsearch import Elasticsearch
import json
from datetime import datetime, timedelta
import os

class ELKConnector:
    def __init__(self):
        self.es = Elasticsearch(
            [os.environ.get("ELK_HOST", "https://your-elk-instance.azure.com:9200")],
            basic_auth=(
                os.environ.get("ELK_USERNAME"),
                os.environ.get("ELK_PASSWORD")
            ),
            verify_certs=True,
            ca_certs=os.environ.get("ELK_CA_CERT_PATH")  # If using self-signed certs
        )
    
    def query_logs(self, index_pattern, query, time_range_minutes=60, max_results=100):
        """
        Query ELK using Lucene query syntax
        
        Args:
            index_pattern: e.g., "filebeat-*", "winlogbeat-*"
            query: Lucene query string, e.g., "source.ip:185.220.101.47"
            time_range_minutes: How far back to search
            max_results: Max documents to return
        """
        try:
            # Calculate time range
            now = datetime.utcnow()
            time_from = now - timedelta(minutes=time_range_minutes)
            
            # Build query
            body = {
                "query": {
                    "bool": {
                        "must": [
                            {"query_string": {"query": query}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": time_from.isoformat(),
                                        "lte": now.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": max_results
            }
            
            # Execute search
            response = self.es.search(index=index_pattern, body=body)
            
            # Format results
            hits = response["hits"]["hits"]
            results = []
            for hit in hits:
                source = hit["_source"]
                results.append({
                    "timestamp": source.get("@timestamp"),
                    "host": source.get("host", {}).get("name"),
                    "message": source.get("message"),
                    "source_ip": source.get("source", {}).get("ip"),
                    "event_id": source.get("event", {}).get("code"),
                    "raw": source
                })
            
            return json.dumps({
                "total_hits": response["hits"]["total"]["value"],
                "returned": len(results),
                "results": results
            }, indent=2)
            
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    def query_failed_logins(self, ip_address=None, username=None, time_range_minutes=1440):
        """
        Specialized query for failed login attempts
        Windows Event ID 4625, Linux auth failures
        """
        query_parts = []
        
        # Windows failed logons
        query_parts.append("event.code:4625")
        
        # Linux auth failures
        query_parts.append("message:*Failed*password*")
        
        if ip_address:
            query_parts.append(f"source.ip:{ip_address}")
        
        if username:
            query_parts.append(f"user.name:{username}")
        
        query = " OR ".join([f"({q})" for q in query_parts[:2]])
        if ip_address or username:
            query = f"({query}) AND {' AND '.join(query_parts[2:])}"
        
        return self.query_logs(
            index_pattern="winlogbeat-*,filebeat-*",
            query=query,
            time_range_minutes=time_range_minutes
        )
    
    def query_suspicious_processes(self, hostname, time_range_minutes=60):
        """
        Query for suspicious process execution (Sysmon Event ID 1)
        """
        query = f"host.name:{hostname} AND event.code:1 AND (process.name:(*powershell* OR *cmd* OR *wscript* OR *cscript* OR *mshta*))"
        
        return self.query_logs(
            index_pattern="winlogbeat-*",
            query=query,
            time_range_minutes=time_range_minutes
        )
    
    def query_network_connections(self, ip_address, time_range_minutes=1440):
        """
        Query for network connections to/from an IP
        """
        query = f"source.ip:{ip_address} OR destination.ip:{ip_address}"
        
        return self.query_logs(
            index_pattern="packetbeat-*,filebeat-*",
            query=query,
            time_range_minutes=time_range_minutes
        )
    
    def aggregate_by_source_ip(self, index_pattern="winlogbeat-*", event_code="4625", time_range_minutes=60, top_n=10):
        """
        Aggregate failed logins by source IP (for brute force detection)
        """
        try:
            now = datetime.utcnow()
            time_from = now - timedelta(minutes=time_range_minutes)
            
            body = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"event.code": event_code}},
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": time_from.isoformat(),
                                        "lte": now.isoformat()
                                    }
                                }
                            }
                        ]
                    }
                },
                "aggs": {
                    "ips": {
                        "terms": {
                            "field": "source.ip",
                            "size": top_n
                        }
                    }
                },
                "size": 0
            }
            
            response = self.es.search(index=index_pattern, body=body)
            
            results = []
            for bucket in response["aggregations"]["ips"]["buckets"]:
                results.append({
                    "ip": bucket["key"],
                    "count": bucket["doc_count"]
                })
            
            return json.dumps(results, indent=2)
            
        except Exception as e:
            return json.dumps({"error": str(e)})