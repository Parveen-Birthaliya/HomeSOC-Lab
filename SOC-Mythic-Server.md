
# SOC-Mythic-Server.md

## Overview

The `SOC-Mythic-Server` is a key component of the HomeSOC lab that simulates adversarial behavior through command-and-control (C2) activities. It serves as an emulation tool for detecting and analyzing threat actor tactics using Mythic, which aids in offensive security testing, behavior simulation, and live-response activities.

---

## System Specifications

| Attribute | Configuration           |
| --------- | ----------------------- |
| Hostname  | `soc-mythic-server`     |
| OS        | Ubuntu Server 24.04 LTS |
| vCPU      | 2 Cores                 |
| RAM       | 4 GB                    |
| Storage   | 80 GB SSD               |
| Location  | Toronto, Canada         |
| Network   | VPC 2.0 (Private VLAN)  |

---

## Installed Tools & Agents

| Tool          | Purpose                           | Installation Status |
| ------------- | --------------------------------- | ------------------- |
| Mythic C2     | Adversary emulation and C2 beacon | ✅ Installed         |
| Elastic Agent | Log shipping and detection        | ✅ Installed         |
| Sysmon        | Endpoint telemetry collection     | ✅ Installed         |

---

## Installation & Configuration Steps

### 1. Install Mythic C2

To deploy Mythic C2, you need Docker installed to run the containers.

* Clone Mythic repository:

```bash
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
```

* Set up Mythic environment:

```bash
./setup.sh
```

* Start Mythic C2 services:

```bash
docker-compose up -d
```

* Access the Mythic C2 UI via `http://<your-server-ip>:7443`.

### 2. Install Elastic Agent

1. Download the Elastic Agent package from the Fleet server:

```bash
wget https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-<version>-linux-x86_64.tar.gz
tar -xvzf elastic-agent-<version>-linux-x86_64.tar.gz
cd elastic-agent-<version>
```

2. Install the agent with Fleet server URL and enrollment token:

```bash
sudo ./elastic-agent install --url=http://<fleet-server-ip>:8220 --enrollment-token=<your-token>
```

### 3. Configure Sysmon for Logging

Sysmon will collect additional endpoint telemetry.

* Download and install Sysmon:

```bash
curl -L https://download.sysinternals.com/files/Sysmon.zip -o Sysmon.zip
unzip Sysmon.zip
sysmon -accepteula -c sysmonconfig.xml
```

* Confirm Sysmon installation by checking logs in `C:\Windows\System32\Sysmon` for generated event logs.

---

## Dashboards Utilized

| Dashboard Name           | Source                 | Purpose                                |
| ------------------------ | ---------------------- | -------------------------------------- |
| Mythic C2 Activity       | Mythic C2 Logs         | C2 beacon activity detection           |
| Endpoint Telemetry       | Sysmon + Elastic Agent | Process creation, network connections  |
| Suspicious Command Usage | Sysmon + Elastic Agent | Detection of unusual command execution |

---

## Detection Use Cases

| Detection Name         | Technique         | MITRE ID  | Source                 | Status         |
| ---------------------- | ----------------- | --------- | ---------------------- | -------------- |
| C2 Beacon Detection    | Command & Control | T1071     | Mythic C2              | ✅ Tested       |
| Suspicious PowerShell  | T1059.001         | T1059.001 | Sysmon + Elastic Agent | ✅ Tested       |
| Lateral Movement (WMI) | Lateral Movement  | T1021.002 | Sysmon + Elastic Agent | 🔄 In Progress |

---

## Log Sources

| Source             | Method        | Normalized By             |
| ------------------ | ------------- | ------------------------- |
| Mythic C2 Logs     | Mythic API    | Custom Ingest             |
| Sysmon Logs        | Sysmon Agent  | Logstash Ingest Pipelines |
| Windows Event Logs | Elastic Agent | ECS Field Mapping         |

---

## Future Enhancements

* Automate IOC correlation with external threat intelligence sources.
* Integrate with TheHive for automated incident triage and case management.
* Implement Sigma rules for custom detection scenarios.
* Enable dynamic alerting based on attack patterns detected through Mythic C2.

---

## References

* [Mythic C2 GitHub Repository](https://github.com/its-a-feature/Mythic)
* [Elastic Agent Installation Guide](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html)
* [Sysmon GitHub](https://github.com/Sysinternals/Sysmon)

---

This document is now structured for professional use in your SOC lab setup and ready for integration with other server configurations. Let me know if you need any adjustments or further additions!

