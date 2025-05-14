# Abnormal Cloud Resource Terminations

**Detects** unexpected or high-volume termination of critical cloud resources such as virtual machines, containers, databases, or storage buckets. This may indicate a destructive attack (e.g., ransomware cleanup, insider threat) or an automation script gone rogue. Early detection is crucial to preserve data integrity and operational availability.



## Rules

yaml
# rules/abnormal_cloud_resource_terminations.yml
---
- name: Abnormal Cloud Resource Terminations
- description: Detects deletion or termination of critical cloud resources across AWS, Azure, or GCP, including EC2, VM instances, S3 buckets, and SQL databases, which may indicate malicious activity or misconfigured automation.

- references:
  - https://attack.mitre.org/techniques/T1485/
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/delete-resources
- tags:
  - T1485
  - Resource Termination
  - Data Destruction
  - Insider Threat
  - Cloud
- severity: critical
- risk_score: 91
- type: query
- index:
  - aws-cloudtrail-*
  - azure-activity-logs-*
  - gcp-audit-logs-*
- language: kuery
- query: >
    (event.provider:"ec2.amazonaws.com" AND event.action:("TerminateInstances"))
    OR
    (event.provider:"s3.amazonaws.com" AND event.action:("DeleteBucket"))
    OR
    (event.provider:"rds.amazonaws.com" AND event.action:("DeleteDBInstance"))
    OR
    (event.provider:"Microsoft.Compute" AND event.action:("virtualMachines/delete"))
    OR
    (event.provider:"Microsoft.Sql" AND event.action:("servers/databases/delete"))
    OR
    (event.provider:"gcp.compute" AND event.action:("compute.instances.delete"))
    OR
    (event.provider:"gcp.sqladmin" AND event.action:("cloudsql.instances.delete"))
- schedule:
  - interval: 5m
  - enabled: true


## Remediation
#### Triage

- Identify the user, role, or service that initiated the termination (`user.name`, `cloud.account.id`, `source.ip`).
- Correlate with change tickets or DevOps automation logs to confirm authorization.
- Determine the criticality of the terminated resource (production vs. test environment).

#### Containment

- Immediately disable the user or automation pipeline if malicious behavior is confirmed.
- Restore terminated resources from backups or snapshots if available.
- Block further destructive API calls using SCPs, Azure Locks, or GCP IAM conditions.

#### Remediation

- Implement resource protection controls like AWS Termination Protection, Azure Locks, or GCP Resource Manager Constraints.
- Apply least privilege to all accounts with termination permissions.
- Configure anomaly detection and alerting for destructive operations in your cloud SIEM.

#### Post-Incident Review

- Conduct a full audit of cloud deletion activities over the past 30 days.
- Update CI/CD policies to enforce approval gates on destructive actions.
- Document lessons learned and enhance your incident response runbooks.
