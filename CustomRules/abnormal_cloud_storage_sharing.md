# Abnormal Cloud Storage Sharing Behavior

**Detects** suspicious sharing or permission changes in cloud storage services (e.g., AWS S3, Azure Blob, GCP Cloud Storage), such as making buckets public, granting access to external accounts, or modifying ACLs unexpectedly. These behaviors may indicate data exfiltration attempts, misconfigurations, or insider threats.



## Rules

yaml
# rules/abnormal_cloud_storage_sharing.yml
---
- name: Abnormal Cloud Storage Sharing Behavior
- description: Detects unauthorized sharing, permission changes, or public exposure of cloud storage resources, including S3 buckets, Azure blobs, and GCP buckets. This activity can indicate exfiltration, misconfiguration, or insider threats.

- references:
  - https://attack.mitre.org/techniques/T1537/
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
  - https://cloud.google.com/storage/docs/access-control/iam-permissions
  - https://learn.microsoft.com/en-us/azure/storage/common/storage-security-guide
- tags:
  - T1537
  - Cloud Storage
  - Data Exposure
  - Misconfiguration
  - Insider Threat
- severity: high
- risk_score: 78
- type: query
- index:
  - aws-cloudtrail-*
  - azure-activity-logs-*
  - gcp-audit-logs-*
- language: kuery
- query: >
    (event.action:("PutBucketAcl" OR "PutBucketPolicy") AND event.provider:"s3.amazonaws.com" AND event.outcome:success)
    OR 
    (event.action:("SetIamPolicy" OR "storage.setIamPermissions") AND event.provider:"gcp.storage" AND event.outcome:success)
    OR 
    (event.action:("SetBlobContainerACLs" OR "SetContainerPermissions") AND event.provider:"Microsoft.Storage" AND event.outcome:success)
    AND NOT user.name:("backup_service" OR "infra_admin")
- schedule:
  - interval: 5m
  - enabled: true


## Remediation
#### Triage

- Identify the storage object (bucket/container) and review the changes in ACL or IAM policy.
- Correlate with `user.name`, `source.ip`, and `cloud.region` to verify legitimacy.
- Confirm whether the object was made public or shared externally.

#### Containment

- Immediately revoke public or external access by restoring original permissions.
- Isolate affected storage resources until full investigation is complete.
- Disable the responsible IAM principal if the activity is malicious.

#### Remediation

- Implement preventive controls like AWS Block Public Access, GCP Organization Policies, or Azure Private Endpoints.
- Apply least privilege IAM roles for all cloud storage operations.
- Set up automated compliance scans to detect misconfigurations in real-time.

#### Post-Incident Review

- Audit all storage permission changes over the past 30 days.
- Document findings and update your detection logic and exclusions list.
- Train engineering teams on secure storage sharing practices.
