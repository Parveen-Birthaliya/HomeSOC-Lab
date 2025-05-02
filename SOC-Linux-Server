# SOC-Linux-Server

## 🔍 Purpose

This machine is dedicated to collecting, normalizing, and analyzing Linux-based telemetry to simulate adversary activity targeting Unix-like environments. It acts as a critical component in emulating real-world attack chains such as SSH brute-force, privilege escalation, and lateral movement from Linux infrastructure.

##  System Configuration

| Component | Specification                    |
| --------- | -------------------------------- |
| OS        | Ubuntu Server 24.04 LTS (64-bit) |
|Machine Type | Shared CPU                     | 
| CPU       | 1 vCPU                           |
| RAM       | 1 GB                             |
| Storage   | 25 GB SSD                        |
| Location  | Toronto, Canada                  |
| Network   | VPC 2.0 (Internal Only)          |

##  Installed Components

| Tool     | Purpose                                                          |
| -------- | ---------------------------------------------------------------- |
| Filebeat | Log forwarding to Logstash/Elasticsearch                         |
| Auditd   | System call monitoring (privilege escalation, file access, etc.) |
| Syslog   | Basic authentication and system logging                          |
| Suricata | Network-based intrusion detection on Linux segment               |
| Zeek     | Protocol analysis and behavioral network telemetry               |

##  Data Collected

| Log Type        | Source               | Collection Method      | Use Case                                              |
| --------------- | -------------------- | ---------------------- | ----------------------------------------------------- |
| SSH Auth Logs   | `/var/log/auth.log`  | Filebeat               | Detect brute-force attacks, failed logins             |
| Auditd Logs     | `/var/log/audit/`    | Filebeat               | Trace privilege escalations, suspicious binaries      |
| Syslog          | `/var/log/syslog`    | Filebeat               | Monitor daemon/service events                         |
| Suricata Alerts | `/var/log/suricata/` | Suricata Module        | Detect command & control, exploits, and scan behavior |
| Zeek Logs       | `/opt/zeek/logs/`    | Zeek Module (Filebeat) | Analyze DNS, HTTP, SSL, and connection behaviors      |

## 🛡️ Detection Use Cases

| Attack Technique     | MITRE Tactic         | Detection Logic                              | Status         |
| -------------------- | -------------------- | -------------------------------------------- | -------------- |
| SSH brute-force      | Initial Access       | Multiple failed logins from same IP          | ✅ Tested       |
| Privilege escalation | Privilege Escalation | Auditd syscall events for sudo/su attempts   | 🔄 In Progress |
| Data exfiltration    | Exfiltration         | Unusual outbound connections (Zeek+Suricata) | ⏳ Planned      |

##  Validation Workflow

*  Generate failed SSH login attempts via Hydra.
*  Simulate privilege escalation with custom sudo script.
*  Test file exfiltration via SCP and monitor via Zeek.



##  Future Enhancements

* Integrate Osquery for scheduled host state inspection.
* Enable eBPF-based telemetry (via Tracee/Falco).
* Automate log correlation with ElastAlert or custom Python rules.


