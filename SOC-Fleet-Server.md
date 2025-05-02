# Elastic Fleet Server (Ubuntu 24.04)

##  Overview  
Elastic Fleet Server node responsible for managing and enrolling Elastic Agents across Windows/Linux endpoints.


---

## Infrastructure Details
* Location: Toronto, Canada
* Machine Type: Dedicated CPU

* Operating System:Windows 2022 Standard

* Resources Allocated:

### Requirements  
List preconditions before you begin.  
- **OS Base Image:** Ubuntu Server 24.02 LTS  
- **Instance Specs:** ≥2 vCPU, 4 GB RAM, attached to private VLAN  
- **Network Ports:** SSH (22), Elasticsearch (9200), Logstash (5044), Kibana (5601), Fleet (8220)  
- **Access:** SSH key with sudo privileges  

---
  * vCPUs: 1 cores

  * RAM: 4 GB

  * Storage: 30 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication

## Setup Fleet
 * Copy insallation command
  - Click on 3 dot -> Management -> Fleet -> Agent -> Add Fleet Server
  - Copy the linux command(Make sure you copy command from your Fleet)
```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.0.0-linux-x86_64.tar.gz
tar xzvf elastic-agent-9.0.0-linux-x86_64.tar.gz
cd elastic-agent-9.0.0-linux-x86_64
sudo ./elastic-agent install \
  --fleet-server-es=https://149.235.40.59:9200 \
  --fleet-server-service-token=AAEAAWVsYXN0aWMvZmx2ZXQtc2VydmVhL3Rva2VuLTE3fDYyMTA3nDAzMTU6UV85ZFJjZTZRNXFHMXNyVTJqQ2JWUQ \
  --fleet-server-policy=fleet-server-policy \
  --fleet-server-es-ca-trusted-fingerprint=9a078b91ca735f42980606885cf5fe54a0c1ceb6df997e1a45e6bd581bnc2186 \
  --fleet-server-port=8220 \
  --install-servers
```
 * Add Firewall Rule
   | TCP | 1-65535 | Paste-Fleet-ip |
 * Installing agent
  - Paste command it into Fleet Server
 * Allow port 9200 on ELK server
 ```bash
 ufw allow 9200
 ```
## Add Agent
* Create Policy
  **SOC-Windows=Policy** and hit enter

* Copy Command for window
  ```bash
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.0.0-windows-x86_64.zip -OutFile elastic-agent-9.0.0-windows-x86_64.zip 
  Expand-Archive .\elastic-agent-9.0.0-windows-x86_64.zip -DestinationPath .
  cd elastic-agent-9.0.0-windows-x86_64
  .\elastic-agent.exe install --url=https://216.159.148.71:443 --enrollment-token=cTNrTGJwWUJnfThRSEFRYTdW8mw6VWJyNjl6NDJnRmxmMUMwMng3RFplQQ==
  ```
* Allow port 8220
```bash
ufw allow 8220
```
* Edit Fleet Server
 - By heading into Fleet -> setting -> Fleet Server host
 - Change port to 8220
 - also change the port to 8220

 ### Access Window-Server
  - Paste the command 
 ```bash
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.0.0-windows-x86_64.zip -OutFile elastic-agent-9.0.0-windows-x86_64.zip 
  Expand-Archive .\elastic-agent-9.0.0-windows-x86_64.zip -DestinationPath .
  cd elastic-agent-9.0.0-windows-x86_64
  .\elastic-agent.exe install --url=https://216.159.148.71:8220 --enrollment-token=cTNrTGJwWUJnfThRSEFRYTdW8mw6VWJyNjl6NDJnRmxmMUMwMng3RFplQQ==
  ```

### Precautions
 * The ip and token are changed , as these are not real ip and token I used for my SOC lab

    
  
  
