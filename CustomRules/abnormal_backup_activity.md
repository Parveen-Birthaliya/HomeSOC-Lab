# Abnormal Patterns in Backup Activity

**Detects** unusual or excessive backup operations—such as a high volume of backup jobs, backups initiated outside of scheduled windows, or backups of sensitive data by non-approved accounts. These anomalies can indicate data staging for exfiltration, unauthorized persistence, or abuse of backup credentials.



## Rules

```yaml
# rules/abnormal_backup_activity.yml
---
- name: Abnormal Patterns in Backup Activity
- description: Detects spikes or off-hours execution of backup jobs across AWS Backup, Azure Recovery Services, or GCP Backup, which may signal misuse of backup processes for malicious purposes.

- references:
  - https://docs.aws.amazon.com/aws-backup/latest/devguide/monitoring-cloudtrail-events.html
  - https://learn.microsoft.com/en-us/azure/backup/backup-monitor-audit-logs
  - https://cloud.google.com/backup-restore/docs/audit-logs
- tags:
  - Backup
  - Data Exfiltration
  - Persistence
  - Cloud
- severity: medium
- risk_score: 55
- type: threshold
- index:
  - aws-cloudtrail-*
  - azure-activity-logs-*
  - gcp-audit-logs-*
- language: kuery
- query: >
    (event.provider:"AWS Backup" AND event.action:"StartBackupJob")
    OR (event.provider:"Microsoft.RecoveryServices" AND event.action:"BackupProtectedItem")
    OR (event.provider:"gcp.backup" AND event.action:"backup.run")
    AND NOT timestamp:[now-1d/d TO now]  # outside normal daily window
- threshold:
    field: event.action
    value: 10
    time_window: 10m
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Identify the backup jobs (`event.action`, `backup.job.id`) and target resources (`resource.name`, `cloud.account.id`).
- Determine initiating identity (`user.name`, `source.ip`) and job timing relative to approved schedule.
- Cross-reference with change-management or ticketing systems to verify authorization.

#### Containment

- Pause or cancel suspicious backup jobs via cloud console or API.
- Revoke or rotate credentials used by the initiating principal.
- Restrict backup service endpoints to approved IP ranges or VPCs.

#### Remediation

- Enforce RBAC policies limiting who can initiate backups and configure schedule windows.
- Implement approval workflows or just-in-time access for backup operations.
- Monitor backup vault usage metrics and integrate alerts with SOAR for automated remediation.

#### Post-Incident Review

- Audit all backup activity over the past 30 days to refine baselines and thresholds.
- Update SOC playbooks with identified tactics and adjust detection logic.
- Conduct a tabletop exercise simulating backup abuse scenarios to validate controls.
