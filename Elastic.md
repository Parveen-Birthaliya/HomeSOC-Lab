# Elastic Stack Web Configuration – [SOC-LAB / PROJECT NAME]

>  This document records all actions taken on the **Elastic Web UI** including Fleet configurations, Kibana visualizations, dashboards, alerts, detection rules, integrations, and data stream management.

---

##  Overview

| Component        | Purpose                                  |
|------------------|-------------------------------------------|
| Kibana           | Visualization and SIEM interface         |
| Fleet            | Agent and integration management         |
| Elastic Defend   | Endpoint Security (EDR)                  |
| Detection Rules  | Threat Detection Logic                   |
| Dashboards       | Operational and Security Visuals         |
| Alerts           | Email, Webhook, and Ticket Notifications |


---

##  Fleet Management

### ➤ Fleet Server

-  Registered via Elastic Agent install command.
- Status: `Healthy`, `Connected`.

### ➤ Agent Policies

| Policy Name           | Modules Enabled                     | Assigned Hosts             |
|-----------------------|-------------------------------------|----------------------------|
| `SOC-Windows-Policy`  | System, Elastic Defend, Sysmon      | `soc-window-server`        |
| `SOC-Linux-Policy`    | System, Suricata                    | `soc-linux-server`         |

---


##  Detection Rules (SIEM)


| Rule Name                                 | Source            | Rule Type    | Trigger Criteria                                                                 | Severity | Action              |
|------------------------------------------|-------------------|--------------|----------------------------------------------------------------------------------|----------|---------------------|
| SSH Brute Force                          | Elastic Agent (Ubuntu) | Threshold     | `event.dataset: system.auth AND event.action: failed-login` > 5 in 5 min         | Medium   | Email, Ticket       |
| Unauthorized SSH Access                  | Elastic Agent (Ubuntu) | KQL           | `event.action: user-login AND user.name != "expected_users"`                     | High     | Email               |
| RDP Brute Force                          | Sysmon (Windows)       | Threshold     | `event.code: 4625 AND logon_type: 10` > 5 in 10 min                              | Medium   | Email, Ticket       |
| Mythic C2 Beacon Detected (HTTP/DNS)     | Logstash → ELK         | ML + KQL      | Repeated outbound to same IP/domain in periodic interval                         | Critical | Ticket, osTicket    |
| PowerShell Obfuscation                   | Sysmon               | KQL           | `process.name: powershell.exe AND script_block_text: "*fromCharCode*"`           | High     | Email, Slack        |
| Suspicious Windows Script Host Usage     | Sysmon               | KQL           | `process.name: wscript.exe OR cscript.exe`                                       | Medium   | Email               |
| Local Admin Group Modified               | Sysmon               | KQL           | `event.code: 4732 AND group.name: "Administrators"`                              | High     | Email, Ticket       |
| Mythic File Transfer Activity            | Mythic Agent          | KQL           | `mythic.event_type: file-upload OR file-download`                                | Critical | Email, Ticket       |
| Mythic Shell Spawn Detected              | Mythic Agent          | KQL           | `command_type: shell OR psh`                                                     | High     | Ticket               |
| osTicket Triggered via Alert             | ELK + osTicket        | Webhook       | Any rule match → Webhook → Ticket generated                                      | —        | Ticket System       |
| Rare Parent-Child Pair (Explorer → Cmd)  | Sysmon               | KQL           | `process.parent.name: explorer.exe AND process.name: cmd.exe`                    | Medium   | Email               |
| LSASS Access Attempt                     | Sysmon               | KQL           | `event.code: 10 AND target.image: lsass.exe`                                     | High     | Email               |
| PowerShell from MS Word                  | Sysmon               | KQL           | `parent_process: WINWORD.EXE AND process.name: powershell.exe`                   | High     | Email               |
| Registry Persistence – Run Key           | Sysmon               | KQL           | `registry.path: "*\\Run\\*" AND event.action: SetValue`                          | High     | Email, Ticket       |
| Suspicious Startup Folder Script         | Sysmon               | KQL           | `file.path: "*\\Startup\\*.vbs OR *.bat"`                                        | Medium   | Email               |
| Cronjob Added (Linux Persistence)        | Elastic Agent (Ubuntu) | File         | `file.path: /etc/cron.d/* AND event.action: created`                             | Medium   | Email               |
| Kernel Module Loaded (Ubuntu)            | Elastic Agent (Ubuntu) | KQL           | `event.dataset: system.syslog AND message: "*insmod*"`                           | Medium   | Email               |
| New User Created (Linux)                 | Elastic Agent (Ubuntu) | KQL           | `event.action: useradd OR usermod`                                               | Medium   | Email               |
| File Execution in Temp Folder            | Sysmon               | KQL           | `file.path: "*\\AppData\\Local\\Temp\\*.exe"`                                    | Medium   | Email               |
| Service Created (Windows)                | Sysmon               | KQL           | `event.code: 7045`                                                               | Medium   | Email               |
| PowerShell with Base64 Payload           | Sysmon               | KQL           | `process.command_line: "*powershell* *-enc*"`                                    | High     | Email               |
| WMI Exec Detected                        | Sysmon               | KQL           | `process.command_line: "*wmic*"`                                                 | Medium   | Email               |
| Psexec Usage                             | Sysmon               | KQL           | `process.name: psexec.exe`                                                       | Medium   | Email               |
| Suspicious DNS Tunneling Volume          | Elastic Agent + Suricata | Threshold     | `dns.question.name: *` > 100 in 10m                                              | High     | Ticket              |
| RDP Enabled via Registry Change          | Sysmon               | KQL           | `registry.path: "*\\fDenyTSConnections"`                                         | Medium   | Email               |
| PowerShell DownloadString Usage          | Sysmon               | KQL           | `powershell.command_line: "*DownloadString*"`                                    | High     | Email               |
| New Inbound Connection on Non-Standard Port | Suricata           | Threshold     | `network.transport: tcp AND destination.port: >1024`                             | Medium   | Email               |
| Suspicious File Extension                | Sysmon               | KQL           | `file.name: *.jpg.exe OR *.doc.exe`                                              | Medium   | Email               |
| Malware Tool Execution (Mimikatz)        | Sysmon               | KQL           | `process.name: mimikatz.exe OR process.hash.md5: known-malicious`               | Critical | Ticket              |
| Startup Modification via Registry        | Sysmon               | KQL           | `registry.path: "*\\Winlogon\\Shell"`                                            | High     | Email               |
| SMBv1 Enabled                            | Sysmon               | Registry      | `registry.path: "*\\SMB1"`                                                       | Medium   | Email               |
| Unexpected Process Spawn from Service    | Sysmon               | KQL           | `process.parent.name: services.exe AND process.name: cmd.exe`                    | Medium   | Email               |
| Suricata Alert: Exploit Signature        | Suricata             | Alert         | `alert.signature: "*Exploit*"`                                                   | Critical | Webhook             |
| Docker Command Executed on Ubuntu        | Elastic Agent (Ubuntu) | KQL           | `process.command_line: "*docker*"`                                               | Medium   | Email               |
| Kernel-Level Process Injection (Mythic)  | Mythic Agent          | Custom        | Process injection or DLL load observed                                           | Critical | Email, Ticket       |
| Logstash Parsing Failure (JSON)          | Logstash              | Alert         | `_grokparsefailure` or `json.parse_error` in logs                                | Low      | Alert Dashboard     |

---



##  Dashboards & Visualizations
| Dashboard Name            | Key Panels Covered                                                          | Data Sources/Modules                         | Host Group(s)              |
| ------------------------- | --------------------------------------------------------------------------- | -------------------------------------------- | -------------------------- |
| `SOC-Suspicious-Activity` | Process trees, LOLBins, registry changes, file drops, persistence artifacts | `Sysmon`, `Elastic Defend`, `Winlogbeat`     | `soc-windows-server`       |
| `SSH-RDP-Auth-Monitor`    | SSH/RDP login attempts, successful/failed auth, source IPs, user tracking   | `         `Sysmon`, `Winlogbeat`             | `soc-windows`, `soc-linux` |

---


##  Testing & Validation

| Test Case                         | Result     |
|----------------------------------|------------|
| New Agent Enrollment             | ✅ Success |
| Detection Rule Trigger           | ✅ Confirmed |
| Alert Ticket Creation via Webhook| ✅ Mapped to osTicket |
| Dashboard Auto-refresh           | ✅ Smooth  |
| Elastic Defend Visibility        | ✅ Process Tree visible |

---

## 📘 References

- [Elastic Fleet Management Docs](https://www.elastic.co/guide/en/fleet/current/fleet-overview.html)
- [SIEM Rule Reference](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [Kibana Dashboard Guide](https://www.elastic.co/guide/en/kibana/current/dashboard.html)

---
