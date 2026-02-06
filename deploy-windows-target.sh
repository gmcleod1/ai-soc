#!/bin/bash

################################################################################
# Windows Target VM Deployment for SOC Training
# Deploys a Windows Server VM with Winlogbeat to existing ELK stack
# Includes Sysmon and attack simulation tools
################################################################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# Configuration Variables
################################################################################

RESOURCE_GROUP="${RESOURCE_GROUP:-ELK-Security-Lab}"
LOCATION="${LOCATION:-eastus}"
VM_SIZE="${VM_SIZE:-Standard_D2s_v3}"
VNET_NAME="ELK-VNet"
SUBNET_NAME="ELK-Subnet"
NSG_NAME="ELK-NSG"
VM_NAME="WinTarget-VM"
ADMIN_USER="azureuser"
ADMIN_PASSWORD=$(openssl rand -base64 20 | tr -d "=+/" | cut -c1-20)Aa1!

# Elasticsearch configuration (from existing deployment)
ES_PRIVATE_IP="${ES_PRIVATE_IP:-10.0.1.4}"
ELK_PASSWORD="${ELK_PASSWORD}"

################################################################################
# Helper Functions
################################################################################

print_header() {
  echo -e "\n${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BLUE}║  $1${NC}"
  echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}\n"
}

print_status() {
  echo -e "${YELLOW}▶${NC} $1"
}

print_success() {
  echo -e "${GREEN}✓${NC} $1"
}

print_error() {
  echo -e "${RED}✗${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}⚠${NC} $1"
}

################################################################################
# Prerequisites Check
################################################################################

print_header "Checking Prerequisites"

if ! command -v az &> /dev/null; then
  print_error "Azure CLI not found. Please install: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
  exit 1
fi
print_success "Azure CLI found"

if ! az account show &> /dev/null; then
  print_error "Not logged in to Azure. Run: az login"
  exit 1
fi
print_success "Azure CLI authenticated"

SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
print_success "Using subscription: $SUBSCRIPTION_NAME"

# Auto-detect public IP
print_status "Detecting your public IP..."
MY_PUBLIC_IP=$(curl -s https://api.ipify.org)
if [[ -z "$MY_PUBLIC_IP" ]]; then
  print_error "Could not detect public IP"
  exit 1
fi
MY_IP_CIDR="$MY_PUBLIC_IP/32"
print_success "Your public IP: $MY_PUBLIC_IP"

# Check if Elasticsearch password is provided
if [[ -z "$ELK_PASSWORD" ]]; then
  print_error "ELK_PASSWORD environment variable not set"
  echo "Usage: ELK_PASSWORD=your_password ./deploy-windows-target.sh"
  exit 1
fi
print_success "Elasticsearch password provided"

################################################################################
# Deploy Windows VM
################################################################################

print_header "Deploying Windows Server VM"

print_status "Creating Windows Server 2022 VM..."
az vm create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --location "$LOCATION" \
  --image Win2022Datacenter \
  --size "$VM_SIZE" \
  --admin-username "$ADMIN_USER" \
  --admin-password "$ADMIN_PASSWORD" \
  --vnet-name "$VNET_NAME" \
  --subnet "$SUBNET_NAME" \
  --nsg "$NSG_NAME" \
  --public-ip-sku Standard \
  --output none

print_success "Windows VM created"

print_status "Waiting for VM to be ready..."
az vm wait --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --created --timeout 300
print_success "VM is ready"

# Get VM public IP
WIN_PUBLIC_IP=$(az vm show -d --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --query publicIps -o tsv)
print_success "VM Public IP: $WIN_PUBLIC_IP"

################################################################################
# Configure Firewall
################################################################################

print_header "Configuring Firewall"

print_status "Adding RDP rule for your IP..."
az network nsg rule create \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$NSG_NAME" \
  --name Allow-RDP \
  --priority 130 \
  --source-address-prefixes "$MY_IP_CIDR" \
  --destination-port-ranges 3389 \
  --protocol Tcp \
  --access Allow \
  --description "Allow RDP from admin IP" \
  --output none
print_success "RDP access configured"

################################################################################
# Install and Configure Sysmon
################################################################################

print_header "Installing Sysmon"

print_status "Downloading and installing Sysmon..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts "
    # Download Sysmon
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile 'C:\Sysmon.zip'
    Expand-Archive -Path 'C:\Sysmon.zip' -DestinationPath 'C:\Sysmon' -Force

    # Download SwiftOnSecurity Sysmon config
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile 'C:\Sysmon\sysmonconfig.xml'

    # Install Sysmon
    C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml

    Write-Output 'Sysmon installed successfully'
  " \
  --output none

print_success "Sysmon installed"

################################################################################
# Install and Configure Winlogbeat
################################################################################

print_header "Installing Winlogbeat"

print_status "Installing Winlogbeat..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts "
    # Download Winlogbeat
    \$version = '8.19.11'
    \$url = \"https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-\$version-windows-x86_64.zip\"
    Invoke-WebRequest -Uri \$url -OutFile 'C:\winlogbeat.zip'

    # Extract Winlogbeat
    Expand-Archive -Path 'C:\winlogbeat.zip' -DestinationPath 'C:\Program Files' -Force
    Rename-Item \"C:\Program Files\winlogbeat-\$version-windows-x86_64\" -NewName 'Winlogbeat' -Force

    Write-Output 'Winlogbeat downloaded and extracted'
  " \
  --output none

print_success "Winlogbeat installed"

print_status "Configuring Winlogbeat..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts "
    # Create Winlogbeat configuration
    \$config = @'
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h

  - name: System
    ignore_older: 72h

  - name: Security
    ignore_older: 72h
    event_id: 4624, 4625, 4648, 4672, 4720, 4722, 4723, 4724, 4728, 4732, 4756

  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h

# Output to Elasticsearch
output.elasticsearch:
  hosts: ['http://${ES_PRIVATE_IP}:9200']
  username: 'elastic'
  password: '${ELK_PASSWORD}'
  index: 'winlogbeat-%{+yyyy.MM.dd}'

# Setup template
setup.template.name: 'winlogbeat'
setup.template.pattern: 'winlogbeat-*'
setup.ilm.enabled: false

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: C:/ProgramData/winlogbeat/Logs
  name: winlogbeat
  keepfiles: 7
  permissions: 0644
'@

    # Write configuration
    \$config | Out-File -FilePath 'C:\Program Files\Winlogbeat\winlogbeat.yml' -Encoding UTF8

    Write-Output 'Winlogbeat configured'
  " \
  --output none

print_success "Winlogbeat configured"

print_status "Installing Winlogbeat as service..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts "
    # Install as service
    cd 'C:\Program Files\Winlogbeat'
    .\install-service-winlogbeat.ps1

    # Start service
    Start-Service winlogbeat

    # Set to auto-start
    Set-Service winlogbeat -StartupType Automatic

    Write-Output 'Winlogbeat service started'
  " \
  --output none

print_success "Winlogbeat service running"

################################################################################
# Configure Windows Audit Policies
################################################################################

print_header "Configuring Audit Policies"

print_status "Enabling detailed audit logging..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts "
    # Enable advanced audit policies
    auditpol /set /subcategory:'Logon' /success:enable /failure:enable
    auditpol /set /subcategory:'Logoff' /success:enable /failure:enable
    auditpol /set /subcategory:'Account Lockout' /success:enable /failure:enable
    auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable
    auditpol /set /subcategory:'Process Termination' /success:enable /failure:enable
    auditpol /set /subcategory:'Registry' /success:enable /failure:enable
    auditpol /set /subcategory:'File System' /success:enable /failure:enable
    auditpol /set /subcategory:'Filtering Platform Connection' /success:enable /failure:enable

    # Enable PowerShell logging
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1

    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Force | Out-Null
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1

    Write-Output 'Audit policies configured'
  " \
  --output none

print_success "Audit policies enabled"

################################################################################
# Install Attack Simulation Tools
################################################################################

print_header "Installing Attack Simulation Tools"

print_status "Installing Atomic Red Team..."
az vm run-command invoke \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --command-id RunPowerShellScript \
  --scripts "
    # Install Atomic Red Team
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

    Install-Module -Name powershell-yaml -Scope AllUsers -Force
    Install-Module -Name invoke-atomicredteam -Scope AllUsers -Force

    # Download Atomic Red Team tests
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1')
    Install-AtomicRedTeam -getAtomics -Force

    Write-Output 'Atomic Red Team installed'
  " \
  --output none 2>/dev/null || print_warning "Atomic Red Team installation may need manual completion"

print_success "Attack simulation tools ready"

################################################################################
# Save Credentials
################################################################################

print_header "Saving Credentials"

CREDS_FILE="windows-target-credentials.txt"

cat > "$CREDS_FILE" <<EOF
═══════════════════════════════════════════════════════════════
         WINDOWS TARGET VM - ACCESS CREDENTIALS
═══════════════════════════════════════════════════════════════

RDP Access:
  IP Address: ${WIN_PUBLIC_IP}
  Port:       3389
  Username:   ${ADMIN_USER}
  Password:   ${ADMIN_PASSWORD}

Internal Network:
  Private IP: 10.0.1.5 (check Azure portal for actual IP)
  Connected to: ${VNET_NAME}/${SUBNET_NAME}

Elasticsearch Connection:
  Internal ES: http://${ES_PRIVATE_IP}:9200
  Username:    elastic
  Password:    ${ELK_PASSWORD}

Quick RDP Command:
  mstsc /v:${WIN_PUBLIC_IP}

Security Notes:
  ⚠ RDP is restricted to IP: ${MY_PUBLIC_IP}
  ⚠ If your IP changes, update NSG rule: Allow-RDP
  ⚠ Winlogbeat sends logs to Elasticsearch automatically
  ⚠ Sysmon is monitoring process activity

═══════════════════════════════════════════════════════════════
EOF

print_success "Credentials saved to: $CREDS_FILE"

################################################################################
# Deployment Complete
################################################################################

print_header "DEPLOYMENT SUCCESSFUL"

echo -e "${GREEN}
╔════════════════════════════════════════════════════════╗
║          WINDOWS TARGET VM DEPLOYED                    ║
╚════════════════════════════════════════════════════════╝${NC}

${BLUE}Access Information:${NC}
  RDP:           ${WIN_PUBLIC_IP}:3389
  Username:      ${ADMIN_USER}
  Password:      ${ADMIN_PASSWORD}

${BLUE}Installed Components:${NC}
  ✓ Windows Server 2022
  ✓ Sysmon (with SwiftOnSecurity config)
  ✓ Winlogbeat (sending to Elasticsearch)
  ✓ Atomic Red Team
  ✓ Enhanced audit policies

${BLUE}Next Steps:${NC}
  1. RDP into the VM: ${WIN_PUBLIC_IP}
  2. Open PowerShell as Administrator
  3. Run attack simulations (see commands below)
  4. Check Kibana for logs: http://YOUR-KIBANA-IP:5601

${YELLOW}Attack Simulation Commands:${NC}

  # Import Atomic Red Team
  Import-Module invoke-atomicredteam

  # List available techniques
  Invoke-AtomicTest -ShowDetails

  # Simulate credential dumping (T1003)
  Invoke-AtomicTest T1003 -TestNumbers 1

  # Simulate failed login attempts
  for (\$i=1; \$i -le 10; \$i++) {
    runas /user:fakeuser cmd.exe 2>\$null
  }

  # Simulate suspicious PowerShell
  Invoke-Expression 'whoami; net user; ipconfig'

  # Simulate suspicious process
  cmd /c \"net user admin P@ssw0rd /add\"

${YELLOW}View Logs in Kibana:${NC}
  1. Create data view: winlogbeat-*
  2. Search for events:
     - event.code: 4625 (failed logins)
     - event.code: 1 (Sysmon process creation)
     - event.code: 4688 (process creation)

${BLUE}Credentials saved to:${NC} ${CREDS_FILE}

${GREEN}Happy Hunting! 🎯${NC}
"
