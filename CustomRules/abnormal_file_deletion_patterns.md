# Abnormal File Deletion Patterns

**Detects** high-volume or rapid file deletion events, which may indicate ransomware activity, malicious cleanup by an attacker post-exfiltration, or insider threat behavior. This detection helps prevent data loss and enables early incident response before permanent damage occurs.



## Rules

```yaml

- name: Abnormal File Deletion Patterns
- description: Detects sudden spikes in file deletions on endpoints or servers, which may indicate ransomware encryption routines, data wiping, or insider threat activity.

- references:
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1070/004/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4660
- tags:
  - T1485
  - T1070.004
  - File Deletion
  - Ransomware
  - Data Destruction
- severity: critical
- risk_score: 90
- type: threshold
- index:
  - winlogbeat-*
  - sysmon-*
- language: kuery
- query: >
    (event.code:4660 OR event.action:"File deleted")
    AND NOT winlog.event_data.SubjectUserName:("SYSTEM" OR "TrustedInstaller")
- threshold:
    field: host.name
    value: 50
    time_window: 2m
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Identify affected host (`host.name`) and user (`winlog.event_data.SubjectUserName`) from the alert.
- Correlate with process information (`process.name`, `process.command_line`) to detect ransomware or cleanup scripts.
- Check for concurrent encryption or exfiltration events.

#### Containment

- Isolate the affected system from the network immediately.
- Disable account involved in deletion activity if malicious.
- Preserve volatile memory and disk state for forensic review.

#### Remediation

- Restore deleted files from backups after confirming no malicious payload remains.
- Deploy EDR policies to block mass deletions or restrict write/delete access to sensitive directories.
- Enable shadow copies and volume snapshots on critical systems.

#### Post-Incident Review

- Conduct full endpoint triage to assess lateral movement or persistent access.
- Update detection logic to refine thresholds or add behavioral exclusions.
- Improve user behavior analytics (UBA) to detect future insider or compromised account abuse.
