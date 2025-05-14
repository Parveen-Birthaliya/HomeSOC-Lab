# Abnormal Growth in Cloud Storage Usage

**Detects** sudden or sustained spikes in cloud storage volume or object counts within a short time frame, which may indicate bulk data uploads for exfiltration, backup abuse, or misconfigured processes. Early detection of unusual storage growth can help prevent data leaks and control costs.



## Rules

```yaml
# rules/abnormal_cloud_storage_growth.yml
---
- name: Abnormal Growth in Cloud Storage Usage
- description: Detects significant increases in storage usage or object counts in cloud buckets (e.g., S3, Azure Blob, GCP Storage) that exceed baseline thresholds, indicating potential exfiltration, backup misconfigurations, or cryptomining dumps.

- references:
  - https://attack.mitre.org/techniques/T1531/  
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-dimensions.html  
  - https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-metrics  
- tags:
  - T1531
  - Cloud Storage
  - Data Exfiltration
  - Anomaly Detection
- severity: high
- risk_score: 82
- type: threshold
- index:
  - aws-cloudtrail-*
  - azure-activity-logs-*
  - gcp-audit-logs-*
- language: kuery
- query: >
    (event.provider:"s3.amazonaws.com" AND event.action:"PutObject")
    OR (event.provider:"Microsoft.Storage" AND event.action:"PutBlob")
    OR (event.provider:"gcp.storage" AND event.action:"storage.objects.create")
- threshold:
    field: cloud.storage.object.size
    # triggers when total bytes uploaded exceed 10 GB within 10 minutes
    value: 10737418240
    time_window: 10m
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Identify the target bucket/container and uploader identity (`user.name`, `cloud.account.id`, `source.ip`).
- Correlate upload volume metrics (`cloud.storage.object.size`, `cloud.storage.object.count`) against baseline activity.
- Cross-check with application logs or data classification labels to determine if the upload is expected.

#### Containment

- Temporarily suspend write permissions on the affected storage resource.
- Block the source IP or IAM principal if unauthorized bulk uploads are confirmed.
- Quarantine newly uploaded objects for malware or sensitive data inspection.

#### Remediation

- Enforce service quotas or bucket-level limits to throttle large uploads.
- Implement data exfiltration prevention controls (e.g., DLP policies on cloud storage).
- Apply lifecycle policies to auto-archive or delete outdated objects.

#### Post-Incident Review

- Perform a 30-day review of storage growth trends and refine thresholds.
- Update alerting rules to include object count anomalies as well as volume.
- Document root cause, update runbooks, and train operations teams on storage anomaly detection.
