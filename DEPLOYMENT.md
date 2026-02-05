# Azure ELK Stack Deployment Guide

Automated deployment script for a security-hardened ELK (Elasticsearch, Logstash, Kibana) stack on Azure, designed for SOC analyst training and security event analysis.

## 🔒 Security Features

This deployment script implements security best practices:

- ✅ **Authentication Required** - Elasticsearch security enabled with auto-generated credentials
- ✅ **IP Whitelisting** - Firewall automatically restricted to your public IP
- ✅ **Network Segmentation** - Elasticsearch API only accessible from internal subnet
- ✅ **No Hardcoded Secrets** - Generates secure random passwords on deployment
- ✅ **Secure SSH** - Uses SSH key authentication, no passwords
- ✅ **Error Handling** - Automatic cleanup on failure (with user confirmation)

⚠️ **Note**: TLS/SSL is disabled for testing purposes. Enable for production use.

## 📋 Prerequisites

### Required Software
- **Azure CLI** - [Installation Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Bash** - Linux/macOS native, Windows users can use Git Bash or WSL
- **Azure Subscription** - [Free trial available](https://azure.microsoft.com/free/)

### Required Credentials
- Azure account with active subscription
- SSH key pair (auto-generated if not found)

## 🚀 Quick Start

### 1. Login to Azure
```bash
az login
```

### 2. Run the Deployment
```bash
chmod +x deploy-elk-azure.sh
./deploy-elk-azure.sh
```

The script will:
1. Verify prerequisites
2. Auto-detect your public IP
3. Generate secure credentials
4. Deploy infrastructure (VMs, networking)
5. Install and configure ELK stack
6. Save credentials to `elk-credentials.txt`

**Deployment time**: ~15 minutes

## ⚙️ Configuration Options

Customize deployment using environment variables:

```bash
# Change Azure region
LOCATION=westus2 ./deploy-elk-azure.sh

# Use larger VMs for production
VM_SIZE=Standard_D4s_v3 ./deploy-elk-azure.sh

# Custom resource group name
RESOURCE_GROUP=MySOC-Lab ./deploy-elk-azure.sh

# Use existing SSH key
SSH_KEY_FILE=/path/to/your/key.pub ./deploy-elk-azure.sh

# Combine multiple options
LOCATION=westus2 VM_SIZE=Standard_D4s_v3 ./deploy-elk-azure.sh
```

### VM Size Options

| Size | vCPUs | RAM | Use Case | Cost/Month* |
|------|-------|-----|----------|-------------|
| Standard_B2s | 2 | 4 GB | Testing only | ~$30 |
| Standard_D2s_v3 | 2 | 8 GB | Default (recommended) | ~$70 |
| Standard_D4s_v3 | 4 | 16 GB | Production | ~$140 |
| Standard_D8s_v3 | 8 | 32 GB | Heavy workloads | ~$280 |

*Approximate costs for East US region

## 📦 What Gets Deployed

### Infrastructure
- **Resource Group**: ELK-Security-Lab
- **Virtual Network**: 10.0.0.0/16 with subnet 10.0.1.0/24
- **Network Security Group**: Firewall rules restricted to your IP
- **2 Virtual Machines**: Ubuntu 22.04 LTS
  - Elasticsearch VM (runs Elasticsearch + Filebeat)
  - Kibana VM (runs Kibana dashboard)

### Software Stack
- **Elasticsearch 8.x** - Search and analytics engine
- **Kibana 8.x** - Visualization and dashboards
- **Filebeat 8.x** - Log shipping and collection

## 🔑 Access Your Deployment

After successful deployment, you'll receive:

```
Kibana Web UI:      http://YOUR-KIBANA-IP:5601
Elasticsearch API:  http://YOUR-ES-IP:9200

Credentials:
  Username: elastic
  Password: [auto-generated]

For SOC Agent (.env):
  ELK_HOST=http://YOUR-ES-IP:9200
  ELK_USERNAME=elastic
  ELK_PASSWORD=[auto-generated]
```

**Credentials are saved to `elk-credentials.txt`** - keep this secure!

## 🧪 Testing Your Deployment

### 1. Access Kibana
Wait 2-3 minutes for services to start, then open Kibana in your browser:
```
http://YOUR-KIBANA-IP:5601
```

Login with the generated credentials.

### 2. Create Data View
1. Navigate to: **Management** → **Stack Management** → **Data Views**
2. Click **Create data view**
3. Name: `filebeat-*`
4. Timestamp field: `@timestamp`
5. Click **Save**

### 3. View Logs
Go to **Analytics** → **Discover** to see system logs being collected.

### 4. Generate Test Security Events
SSH into the Elasticsearch VM and simulate failed login attempts:

```bash
# SSH into Elasticsearch VM (use your credentials from deployment)
ssh -i ~/.ssh/id_rsa azureuser@YOUR-ES-IP

# Generate 20 failed SSH login attempts
for i in {1..20}; do sudo ssh baduser@localhost 2>/dev/null; sleep 1; done

# Exit SSH
exit
```

Check Kibana Discover to see the failed authentication events!

### 5. Test Elasticsearch API
```bash
# Health check
curl -u elastic:YOUR-PASSWORD http://YOUR-ES-IP:9200/_cluster/health

# Query failed logins
curl -u elastic:YOUR-PASSWORD http://YOUR-ES-IP:9200/filebeat-*/_search?q=event.action:ssh_login
```

## 🔗 Integration with SOC Agent

Your AI-powered SOC agent is pre-configured to work with this deployment.

### Update .env File
The script provides the exact configuration needed. Add to your `.env`:

```env
ELK_HOST=http://YOUR-ES-IP:9200
ELK_USERNAME=elastic
ELK_PASSWORD=YOUR-GENERATED-PASSWORD
```

### Run SOC Analysis
```bash
python soc_agent.py
```

The agent can now:
- Query failed login attempts
- Detect brute force attacks
- Analyze suspicious process execution
- Correlate events across logs
- Generate incident reports

## 🛠️ Management Tasks

### Check Service Status
```bash
# SSH into VMs
ssh -i ~/.ssh/id_rsa azureuser@YOUR-ES-IP
ssh -i ~/.ssh/id_rsa azureuser@YOUR-KIBANA-IP

# Check Elasticsearch
sudo systemctl status elasticsearch

# Check Kibana
sudo systemctl status kibana

# Check Filebeat
sudo systemctl status filebeat
```

### View Logs
```bash
# Elasticsearch logs
sudo journalctl -u elasticsearch -f

# Kibana logs
sudo journalctl -u kibana -f

# Filebeat logs
sudo journalctl -u filebeat -f
```

### Stop VMs (Save Costs)
```bash
# Stop both VMs (keeps all data, stops billing for compute)
az vm deallocate --resource-group ELK-Security-Lab --name Elasticsearch-VM
az vm deallocate --resource-group ELK-Security-Lab --name Kibana-VM

# Start VMs again
az vm start --resource-group ELK-Security-Lab --name Elasticsearch-VM
az vm start --resource-group ELK-Security-Lab --name Kibana-VM
```

### Complete Cleanup
```bash
# Delete all resources (WARNING: Permanent!)
az group delete --name ELK-Security-Lab --yes --no-wait
```

## 💰 Cost Management

### Estimated Monthly Costs
- 2x Standard_D2s_v3 VMs: ~$140/month
- 2x Public IPs: ~$7/month
- Storage: ~$5/month
- **Total**: ~$150/month

### Cost Optimization Tips
1. **Deallocate VMs** when not in use (stops compute charges)
2. **Use smaller VM sizes** for testing (Standard_B2s ~$60/month)
3. **Delete when done** - This is a training environment
4. **Set up Azure Budget Alerts** to monitor spending

## 🔐 Security Best Practices

### ✅ Already Implemented
- Authentication required for all services
- Firewall restricted to your IP
- Network segmentation
- Strong random passwords
- SSH key authentication

### ⚠️ For Production Deployments
1. **Enable TLS/SSL**
   - Configure SSL certificates for Elasticsearch and Kibana
   - Update firewall to allow HTTPS (443, 9243)

2. **Use Azure Key Vault**
   - Store credentials securely
   - Rotate passwords regularly

3. **Enable Azure Monitor**
   - Set up logging and alerting
   - Monitor for unauthorized access

4. **Implement Backup Strategy**
   - Configure Elasticsearch snapshots
   - Use Azure Backup for VMs

5. **Use Private Endpoints**
   - Remove public IPs
   - Access via Azure Bastion or VPN

6. **Regular Updates**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

## 🐛 Troubleshooting

### Services Not Starting
```bash
# Check Elasticsearch is listening
sudo netstat -tlnp | grep 9200

# View detailed logs
sudo journalctl -u elasticsearch -n 100 --no-pager
```

### Cannot Access Kibana
- Wait 3-5 minutes after deployment
- Verify your IP hasn't changed: `curl ifconfig.me`
- Update NSG if IP changed:
  ```bash
  az network nsg rule update \
    --resource-group ELK-Security-Lab \
    --nsg-name ELK-NSG \
    --name Allow-Kibana \
    --source-address-prefixes "YOUR-NEW-IP/32"
  ```

### Elasticsearch Health Yellow/Red
```bash
# Check cluster health
curl -u elastic:PASSWORD http://YOUR-ES-IP:9200/_cluster/health?pretty

# Yellow is normal for single-node clusters
# Red indicates a problem - check logs
```

### Filebeat Not Collecting Logs
```bash
# Test Filebeat configuration
sudo filebeat test config
sudo filebeat test output

# Restart Filebeat
sudo systemctl restart filebeat
```

## 📚 Additional Resources

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana Documentation](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Filebeat Documentation](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Azure CLI Reference](https://docs.microsoft.com/en-us/cli/azure/)
- [ELK Stack Tutorial](https://www.elastic.co/guide/en/elastic-stack-get-started/current/get-started-elastic-stack.html)

## 🤝 Contributing

Found a bug or want to improve the deployment script? Contributions welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## ⚠️ Disclaimer

This deployment is designed for **training and testing purposes**. For production environments:
- Enable TLS/SSL encryption
- Implement proper backup strategies
- Follow your organization's security policies
- Consider managed services like Azure Elastic Cloud

## 📄 License

MIT License - See LICENSE file for details

---

**Questions or Issues?** Open an issue on GitHub or contact the maintainer.

**Happy Threat Hunting!** 🛡️
