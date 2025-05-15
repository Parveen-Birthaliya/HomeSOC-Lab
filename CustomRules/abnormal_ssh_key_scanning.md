# Abnormal SSH Key Scanning

**Detects** unauthorized enumeration of SSH key files (e.g., `authorized_keys`, `id_rsa.pub`) across multiple hosts, which may indicate an adversary searching for valid key-based access or compromised credentials. Such activity often precedes lateral movement or persistent backdoor installation.



## Rules

```yaml
# rules/abnormal_ssh_key_scanning.yml
---
- name: Abnormal SSH Key Scanning
- description: Detects repeated reads of SSH key files (`~/.ssh/authorized_keys`, `~/.ssh/id_*.pub`) on endpoints, indicating scanning for valid SSH credentials or harvesting of public keys.

- references:
  - https://attack.mitre.org/techniques/T1592/002/
  - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
  - https://linux-audit.com/auditd-file-access-auditing/
- tags:
  - T1592.002
  - SSH
  - Credential Access
  - Lateral Movement
  - File Enumeration
- severity: high
- risk_score: 72
- type: threshold
- index:
  - sysmon-*
  - filebeat-*
- language: kuery
- query: >
    event.provider:"Microsoft-Windows-Sysmon"
    AND event.code:11
    AND winlog.event_data.TargetFilename:("*\\.ssh/authorized_keys" OR "*\\.ssh/id_*.pub")
- threshold:
    field: source.ip
    value: 5
    time_window: 10m
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Identify the source host (`source.ip`) and user account (`winlog.event_data.SubjectUserName`) performing the file reads.
- Determine whether the access was part of an approved audit or admin activity.
- Cross-reference with SSH authentication logs (`/var/log/auth.log`, `sshd` logs) for attempted or successful logins.

#### Containment

- Isolate the source host if scanning is confirmed malicious.
- Revoke or rotate SSH keys for accounts accessed during the scanning window.
- Block the source IP at the network perimeter or firewall.

#### Remediation

- Enforce strict file permissions on SSH key directories (e.g., `chmod 700 ~/.ssh`, `chmod 600 ~/.ssh/*`).
- Implement host-based intrusion detection to alert on unauthorized file reads.
- Apply Just-In-Time (JIT) access controls and multi-factor authentication for SSH sessions.

#### Post-Incident Review

- Audit SSH key usage and distribution policies; remove unused or stale keys.
- Update detection thresholds based on normal administrative scanning patterns.
- Incorporate lessons learned into SOC playbooks and train teams on SSH key hygiene.
