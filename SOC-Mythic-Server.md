# 🧠 SOC-Mythic-Server.md

## Overview

The `SOC-Mythic-Server` serves as the adversary emulation and command-and-control (C2) simulation node within the HomeSOC lab. It leverages the Mythic C2 framework to generate real-world attack traffic, 
test detection logic, and emulate advanced persistent threat (APT) behavior in a controlled environment.

---

## 📌 System Specifications

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

## 🔧 Installation & Configuration Steps

### 1. Prerequisites

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install git docker.io docker-compose -y
```

### 2. Clone Mythic Repository

```bash
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
```

### 3. Launch Mythic C2 Framework

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon
./mythic-cli install github https://github.com/MythicAgents/apfell
./mythic-cli start
```

### 4. Access Mythic Web Interface

* URL: `http://<MYTHIC_IP>:7443`
* Default Credentials:

  * Username: `mythic_adm`
  * Password: `mythic_password`

> 🔐 Update default credentials immediately after first login.

---

## 🧪 Agents & Profiles

| Agent    | Profile    | Use Case                            |
| -------- | ---------- | ----------------------------------- |
| Poseidon | HTTP/HTTPS | Linux lateral movement, beaconing   |
| Apfell   | WebSockets | macOS simulation (optional)         |
| PoshC2   | PowerShell | Windows simulation with obfuscation |

---

## ⚔️ Adversary Simulation Use Cases

| Scenario                     | MITRE Tactic      | Technique ID | Detection Source | Status         |
| ---------------------------- | ----------------- | ------------ | ---------------- | -------------- |
| Beacon Callback via HTTPS    | C2 Channel        | T1071.001    | Zeek + Suricata  | ✅ Tested       |
| PowerShell Command Execution | Execution         | T1059.001    | Sysmon + Kibana  | ✅ Tested       |
| Reverse Shell on Linux       | Execution         | T1059.004    | Zeek + Suricata  | 🔄 In Progress |
| User Enumeration & Dumping   | Credential Access | T1003.001    | Sysmon + ELK     | ⏳ Planned      |

---

## 📊 Monitoring & Detection

* Mythic agent events forwarded via:

  * Sysmon (on Windows targets)
  * Zeek/Suricata (for C2 traffic visibility)
  * Logstash pipelines normalize artifacts into ECS

---

## 🧭 Future Enhancements

* ✅ Integrate Mythic with Atomic Red Team for scripted attack chains
* 🔄 Enable Canary tokens for deception layer
* 🔐 TLS Cert Pinning + HTTPS profile hardening
* 📦 Automate agent deployment via Ansible
* 🎯 Red Team → Blue Team validation loop: detection effectiveness scoring

---

## 📎 References

* [Mythic Framework GitHub](https://github.com/its-a-feature/Mythic)
* [Mythic Documentation](https://docs.mythic-c2.net/)
* [MITRE ATT\&CK Navigator](https://attack.mitre.org/)
