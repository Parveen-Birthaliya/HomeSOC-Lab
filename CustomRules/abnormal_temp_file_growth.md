# Abnormal Growth of Temporary Files

**Detects** rapid or excessive creation of files in temporary directories (e.g., `C:\Windows\Temp`, `%USERPROFILE%\AppData\Local\Temp`), which may indicate malicious script execution, data staging for exfiltration, or ransomware encryption processes writing temporary files.



## Rules

```yaml
# rules/abnormal_temp_file_growth.yml
---
- name: Abnormal Growth of Temporary Files
- description: Detects sudden spikes in file creation events within system or user Temp folders, indicating potential malware staging, ransomware activity, or unsanctioned scripts.

- references:
  - https://attack.mitre.org/techniques/T1074/  
  - https://attack.mitre.org/techniques/T1486/  
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663  
- tags:
  - T1074
  - T1486
  - File Creation
  - Ransomware
  - Data Staging
- severity: medium
- risk_score: 65
- type: threshold
- index:
  - winlogbeat-*
  - sysmon-*
- language: kuery
- query: >
    (event.provider:"Microsoft-Windows-Sysmon" AND event.code:11 AND winlog.event_data.TargetFilename:("*\\Temp\\*" OR "*\\AppData\\Local\\Temp\\*"))
    OR
    (event.code:4663 AND winlog.event_data.ObjectName:("*\\Temp\\*" OR "*\\AppData\\Local\\Temp\\*") AND winlog.event_data.AccessMask:"%%4416")
- threshold:
    field: host.name
    value: 100
    time_window: 5m
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Identify the process spawning the temp files (`process.name`, `process.command_line`) and the user account (`winlog.event_data.SubjectUserName`).
- Correlate with parent process lineage and recent script executions.
- Check file contents or extensions for known malicious patterns (e.g., `.tmp` with embedded payload).

#### Containment

- Terminate or isolate the suspicious process via EDR console.
- Quarantine newly created temp files for static/dynamic analysis.
- Block script hosts (e.g., `powershell.exe`, `cmd.exe`) from writing to temp directories via application control policies.

#### Remediation

- Review and harden endpoint script execution policies (e.g., PowerShell Constrained Language Mode).
- Implement least privilege on user profiles and disable write access to temp folders for unnecessary accounts.
- Enable file integrity monitoring (FIM) on critical system paths, including Temp directories.

#### Post-Incident Review

- Audit temp-folder writes over the past 30 days to refine detection thresholds.
- Document the root cause and update your SOC playbooks with identified TTPs.
- Exclude known benign maintenance tasks or patch installers from future alerts.
