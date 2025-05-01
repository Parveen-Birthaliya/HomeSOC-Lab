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

 ## Setup & Configuration Steps
 ### 1. SOC-ELK Server 
* Cloud Provider: Vultr Cloud (Cloud Compute Instance)

* Operating System: Ubuntu Server 24.04 LTS (64-bit)

* Resources Allocated:

  * vCPUs: 4 cores

  * RAM: 16 GB

  * Storage: 100 GB SSD

* Network Configuration:

  * VPC 2.0: Enabled for private/internal network communication

  * Public IP Access: Secured via firewall (ufw)

  * SSH Access: Allowed only from my public IP

* Firewall Rules:

  * SSH (Port 22): Allowed only for my IP

  * Kibana (Port 5601): Temporarily allowed for my IP
 
