# Abnormal File Path Access Patterns

**Detects** unusual access to sensitive, hidden, or system-critical file paths—often indicative of reconnaissance, privilege escalation, malware staging, or data exfiltration. These patterns may involve access to uncommon directories by non-system accounts or unexpected processes interacting with protected areas.



## Rules

```yaml
# rules/abnormal_file_path_access_patterns.yml
---
- name: Abnormal File Path Access Patterns
- description: Detects unexpected or suspicious access to sensitive or hidden file paths (e.g., SYSTEM32, ProgramData, AppData\Roaming) which may indicate privilege escalation, malware staging, or unauthorized reconnaissance.

- references:
  - https://attack.mitre.org/techniques/T1083/
  - https://attack.mitre.org/techniques/T1005/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663
- tags:
  - T1083
  - T1005
  - File System Discovery
  - Suspicious File Access
  - Privilege Escalation
- severity: high
- risk_score: 77
- type: query
- index:
  - winlogbeat-*
  - sysmon-*
- language: kuery
- query: >
    event.code:4663
    AND winlog.event_data.ObjectName:("*\\AppData\\Roaming\\*" OR "*\\ProgramData\\*" OR "*\\System32\\*" OR "*\\Temp\\*" OR "*\\Windows\\Tasks\\*")
    AND NOT winlog.event_data.SubjectUserName:("SYSTEM" OR "Administrator" OR "TrustedInstaller")
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Examine accessed file paths via `winlog.event_data.ObjectName`.
- Identify the process and user performing the access (`process.name`, `winlog.event_data.SubjectUserName`).
- Correlate with process command line, parent-child relationships, and recent execution history.

#### Containment

- Suspend or terminate suspicious processes using `taskkill` or EDR console.
- Isolate host if lateral movement or staging is confirmed.
- Remove unauthorized persistence mechanisms or startup entries.

#### Remediation

- Harden access to sensitive directories using ACLs and GPO.
- Enable file integrity monitoring (FIM) to track changes in critical paths.
- Apply application allowlisting to restrict binary execution in non-standard locations.

#### Post-Incident Review

- Determine if accessed files were altered, exfiltrated, or just enumerated.
- Refine path-based rules to reduce false positives without compromising coverage.
- Update baseline behavior models for file access patterns by user roles.
