# HomeSOC-Lab 

## Objective
Establish a comprehensive, on-premise SOC lab to simulate real-world adversary tactics and develop end-to-end detection, investigation, and response capabilities. This environment replicates enterprise telemetry pipelines and validation playbooks—empowering you to benchmark and refine SOC processes against validated MyDFIR Challenge workflows.

## Skills Learned
* End-to-end SOC deployment and configuration on Ubuntu Server.

* Ingestion, parsing, and normalization of diverse telemetry sources in the ELK stack.

* Creation and tuning of real-time detection rules and dashboards in Kibana.

* Ticketing system integration (osTicket) for structured incident case management.

* Live-response data collection via Sysmon and Mythic C2 agent.

* Investigation techniques for brute-force, C2, and lateral-movement scenarios.

## Tools Used
* Ubuntu Server 24.02 – Base OS for all virtualized lab components.

* ELK Stack (Elasticsearch, Logstash, Kibana) – Centralized logging, search, and dashboarding.

* Elastic Agent & Fleet – Agent deployment for unified data collection.

* Sysmon – Detailed Windows endpoint telemetry.

* Mythic C2 – Adversary emulation and live-response tool.

* osTicket – Incident ticketing and workflow management.

* Suricata & Zeek – Network traffic inspection and IDS signature tuning.

## Infrastructure Overview: Machine Configurations
### 1. SOC-ELK Server 
* Location: Toronto, Canada
* Machine Type:  Dedicated CPU

* Operating System: Ubuntu Server 24.04 LTS (64-bit)

* Resources Allocated:

  * vCPUs: 4 cores

  * RAM: 16 GB

  * Storage: 100 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication


  * SSH Access: Allowed only from my public IP

* Firewall Rules:

  * SSH (Port 22): Allowed only for my IP

  * Kibana (Port 5601): Temporarily allowed for my IP

### 2. SOC-Window-Server 
* Location: Toronto, Canada
* Machine Type: Shared CPU

* Operating System: Windows Server 2022 Standard

* Resources Allocated:

  * vCPUs: 1 cores

  * RAM: 2 GB

  * Storage: 55 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication

### 3. SOC-Fleet-Server 
* Location: Toronto, Canada
* Machine Type: Dedicated CPU

* Operating System:Windows 2022 Standard

* Resources Allocated:

**Requirements**  
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
 

### 4. SOC-Linux-Server 
* Location: Toronto, Canada
* Machine Type: Shared CPU

* Operating System:Ubuntu Server 24.04 LTS (64-bit)

* Resources Allocated:

  * vCPUs: 1 cores

  * RAM: 1 GB

  * Storage: 25 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication


### 5. SOC-Mythic-Server 
* Location: Toronto, Canada
* Machine Type: Shared CPU

* Operating System:Ubuntu Server 24.04 LTS (64-bit)

* Resources Allocated:

  * vCPUs: 2 cores

  * RAM: 4 GB

  * Storage: 80 GB SSD

### 6. SOC-osTicket-Server 
* Location: Toronto, Canada
* Machine Type: Shared CPU

* Operating System:Windows 2022 Standard

* Resources Allocated:

  * vCPUs: 1 cores

  * RAM: 2 GB

  * Storage: 55 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication
 

##  Project Roadmap

| Phase | Description                              | Status        |
|-------|------------------------------------------|---------------|
| Phase 1 | Provision core infrastructure (6 machines on Vultr, VPC setup, firewall hardening) | ✅ Completed |
| Phase 2 | Install and configure ELK stack (SOC-ELK) | ✅ Completed |
| Phase 3 | Deploy Sysmon & Elastic Agent (SOC-Windows, SOC-Fleet) | ✅ Completed|
| Phase 4 | Integrate Kibana Dashboards & Detections | ✅ Completed |
| Phase 5 | Simulate attacks with Mythic C2          | ✅ Completed |
| Phase 6 | Enable incident tracking with osTicket   | ✅ Completed |
| Phase 7 | Detection fine-tuning, alert triage, and reporting |  🔄 In Progress |

 

##  Tested Attack Scenarios

| Attack Technique         | MITRE Tactic        | Tool/Method Used         | Detection Source     | Status     |
|--------------------------|---------------------|---------------------------|----------------------|------------|
| Brute-force RDP login    | Initial Access      | Hydra                     | Sysmon → ELK         | ✅ Tested  |
| PowerShell C2 beacon     | Command & Control   | Mythic with PoshC2        | Sysmon, Suricata     | ✅ Tested  |
| Lateral movement (psexec)| Lateral Movement    | Impacket psexec.py        | Sysmon + Zeek        | 🔄 Pending |
| Credential dumping       | Credential Access   | Mimikatz                  | Sysmon (Event 10)    | 🔄 Pending |
| Malicious DNS query      | Command & Control   | DNSCat2                   | Zeek + Suricata      | ⏳ Planned |

##  Future Enhancements

- 🔐 **Integrate TheHive + Cortex** for automated incident response workflows and IOC enrichment.
- 🛰️ **MISP (Malware Information Sharing Platform)** for threat intel ingestion and pivot-based investigation.
- 🧬 **Elastic ML Anomaly Detection** for behavior-based threat hunting and rare pattern identification.
- ⚙️ **SOAR Automation** using ElastAlert, Curator, or custom Python scripts.
- ☁️ **SIEM to Cloud Integration** (e.g., ingesting from AWS CloudTrail or Azure logs for hybrid SOC).
- 📦 **Infrastructure-as-Code**: Automate machine provisioning with Terraform + Ansible for repeatability.
- 📊 **Grafana Integration** for advanced visualization beyond Kibana.
- 🔍 **Host forensic triage** with Velociraptor or GRR for incident deep-dive workflows.

## References
- <a href="https://youtube.com/playlist?list=PLG6KGSNK4PuBb0OjyDIdACZnb8AoNBeq6&si=ddBccVKlon1BdScR">MyDFIR SOC Playlist</a>


