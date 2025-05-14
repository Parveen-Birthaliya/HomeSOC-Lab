# Abnormal Cloud Service Usage

**Detects** unusual or unauthorized usage patterns of cloud services, such as sudden spikes in resource provisioning, unexpected regions, or services never previously used in the environment. These anomalies may indicate resource hijacking, cryptojacking, reconnaissance, or the early stages of a broader compromise.



## Rules

yaml

---
- name: Abnormal Cloud Service Usage
- description: Detects unexpected use of cloud services, including activation of new services, usage in unapproved regions, or provisioning of excessive resources, which may indicate cryptojacking, enumeration, or initial access activity.

- references:
  - https://attack.mitre.org/techniques/T1583/008/
  - https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
  - https://docs.aws.amazon.com/service-authorization/latest/reference/reference_policies_actions-resources-contextkeys.html
- tags:
  - T1583.008
  - Cloud Enumeration
  - Cryptojacking
  - Resource Abuse
  - Reconnaissance
- severity: medium
- risk_score: 59
- type: query
- index:
  - aws-cloudtrail-*
  - azure-activity-logs-*
  - gcp-audit-logs-*
- language: kuery
- query: >
    (event.provider:* AND event.action:(RunInstances OR StartInstances OR CreateFunction OR CreateCluster OR StartJobRun))
    AND NOT cloud.region:("us-east-1" OR "eastus" OR "us-central1") 
    AND NOT user.name:("automation_user" OR "devops_bot")
- schedule:
  - interval: 5m
  - enabled: true


## Remediation
#### Triage

- Examine the identity (`user.name`, `cloud.account.id`) and IP (`source.ip`) responsible for the service usage.
- Review whether the region, service, and timing align with expected behavior.
- Investigate if the usage volume suggests resource abuse (e.g., for crypto mining).

#### Containment

- Disable or suspend suspicious users, roles, or tokens.
- Terminate active workloads related to cryptojacking or unauthorized compute activity.
- Set budget alerts or enforce service quota limits to prevent excessive usage.

#### Remediation

- Use SCPs (AWS), Azure Policies, or GCP Organization Policies to restrict service and region usage.
- Enable billing anomaly alerts and usage pattern baselines for early detection.
- Apply identity-based controls and MFA across all accounts and projects.

#### Post-Incident Review

- Review recent API activity for related enumeration or exploitation.
- Validate infrastructure-as-code (IaC) pipelines and CI/CD systems for misuse.
- Update detection logic and playbooks with context from this incident.
