# Abnormal Cloud API Calls

**Detects** suspicious or unauthorized cloud API calls that are uncommon, sensitive, or privilege-altering. These behaviors may suggest account compromise, unauthorized automation, or malicious reconnaissance, often preceding privilege escalation or data exfiltration in cloud environments.



## Rules

yaml

---
- name: Abnormal Cloud API Calls
- description: Detects rare or sensitive cloud API calls, such as IAM privilege changes, key deletions, or role assumptions, which may indicate account compromise or malicious automation.

- references:
  - https://attack.mitre.org/techniques/T1529/
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/change-roles
- tags:
  - T1529
  - Cloud
  - API Abuse
  - Privilege Escalation
  - Initial Access
- severity: high
- risk_score: 75
- type: query
- index:
  - aws-cloudtrail-*
  - azure-activity-logs-*
  - gcp-audit-logs-*
- language: kuery
- query: >
    (event.provider:"AWS IAM" AND event.action:("DeleteAccessKey" OR "UpdateAssumeRolePolicy" OR "CreatePolicyVersion"))
    OR
    (event.provider:"Microsoft.Authorization" AND event.action:("roleAssignments/write" OR "elevateAccess"))
    OR
    (event.provider:"gcp.iam" AND event.action:("google.iam.admin.v1.DeleteServiceAccountKey" OR "SetIamPolicy"))
- schedule:
  - interval: 5m
  - enabled: true


## Remediation
#### Triage

- Review the identity (`user.name`, `cloud.account.id`) and session context (`source.ip`, `user_agent.original`) associated with the API call.
- Cross-reference with preceding login attempts or failed authentications.
- Verify whether the API call aligns with expected role or user behavior.

#### Containment

- Revoke affected user credentials or API tokens immediately.
- Suspend the involved user or service principal if unauthorized behavior is confirmed.
- Rotate access keys, secrets, and invalidate any long-lived tokens.

#### Remediation

- Apply Just-In-Time (JIT) access policies for privileged operations.
- Enforce MFA and strict least privilege on cloud IAM roles and users.
- Enable and monitor native cloud threat detection (e.g., AWS GuardDuty, Azure Defender).

#### Post-Incident Review

- Conduct a 30-day retrospective on cloud API usage.
- Add benign automation identities to allowlist or exclusion filters.
- Document learnings and update cloud detection and response playbooks.
