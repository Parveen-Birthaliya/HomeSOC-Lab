# Abnormal Metadata Changes in Digital Files

**Detects** unauthorized modifications to file metadata attributes—such as timestamps, ownership details, or extended attributes—which may indicate malicious preparation for data exfiltration, anti-forensic tampering, or persistence mechanisms. Attackers often alter metadata to evade detection or hide their activity.



## Rules

```yaml
# rules/abnormal_metadata_changes.yml
---
- name: Abnormal Metadata Changes in Digital Files
- description: Detects changes to file metadata (timestamps, attributes, ownership) on endpoints via Sysmon Event ID 11 or Windows Event ID 4663, signaling potential anti-forensic or persistence activity.

- references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon  
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663  
  - https://attack.mitre.org/techniques/T1070/001/  
- tags:
  - T1070.001
  - File Metadata
  - Anti-Forensics
  - Persistence
- severity: high
- risk_score: 70
- type: query
- index:
  - winlogbeat-*
  - sysmon-*
- language: kuery
- query: >
    (event.provider:"Microsoft-Windows-Sysmon" AND event.code:11 AND winlog.event_data.TargetObject:* AND winlog.event_data.ChangeMask:("*FileName*" OR "*Attributes*"))
    OR
    (event.code:4663 AND winlog.event_data.AccessMask:("*WRITE_ATTRIBUTES*" OR "*WRITE_DAC*") AND NOT winlog.event_data.SubjectUserName:("SYSTEM" OR "TrustedInstaller"))
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Identify the file path (`winlog.event_data.TargetObject`) and the specific metadata change (`ChangeMask` or `AccessMask`).
- Determine the initiating account (`winlog.event_data.SubjectUserName`) and source host (`host.name`, `source.ip`).
- Correlate with prior process events (`process.name`, `process.command_line`) to establish context.

#### Containment

- Revert unauthorized metadata changes by restoring from known-good backups or snapshots.
- Quarantine the affected host and suspend the user account if malicious intent is confirmed.
- Block or restrict the process responsible via EDR or application control policies.

#### Remediation

- Enforce file integrity monitoring (FIM) across critical directories to catch metadata tampering.
- Harden permissions with stricter ACLs and remove unnecessary WRITE_ATTRIBUTES/WRITE_DAC privileges.
- Implement periodic baseline comparisons of file metadata to detect drift.

#### Post-Incident Review

- Review forensic timeline to determine scope and intent of metadata tampering.
- Update detection thresholds and exclude legitimate maintenance tools as needed.
- Incorporate findings into incident response playbooks and train teams on anti-forensic indicators.
