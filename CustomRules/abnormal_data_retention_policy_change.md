# Abnormal Changes in Data Retention Policies

**Detects** unauthorized or suspicious modifications to data retention configurations, which may indicate an attempt to cover malicious activity, exfiltrate data, or hinder future forensic investigations. This includes policy changes in services like Microsoft 365, Exchange, or any logs retention systems, often exploited during post-compromise cleanup stages.



## Rules

yaml

---
- name: Abnormal Changes in Data Retention Policies
- description: Detects changes to data retention policies (e.g., Exchange Retention Policies, Microsoft 365 Compliance Center) that could indicate attempts to tamper with audit logs or cover malicious actions.
- author: PK
- references:
  - https://learn.microsoft.com/en-us/purview/audit-retention :contentReference[oaicite:1]{index=1}
  - https://attack.mitre.org/techniques/T1562/006/ :contentReference[oaicite:2]{index=2}
  - https://learn.microsoft.com/en-us/microsoft-365/compliance/retention-policies :contentReference[oaicite:3]{index=3}
- tags:
  - T1562.006
  - Log Tampering
  - Policy Modification
  - Insider Threat
- severity: high
- risk_score: 73
- type: query
- index:
  - o365-audit-*
  - azure-activity-logs-*
l- anguage: kuery
- query: >
  (event.provider:"Microsoft.Exchange" AND event.category:"Policy" AND event.action:"Set-RetentionPolicy")
  OR
  (event.provider:"Microsoft.OperationalInsights" AND event.action:"UpdateRetentionPolicy")
  OR
  (event.provider:"Microsoft.SecurityComplianceCenter" AND event.action:"Set-RetentionCompliancePolicy")
s- chedule:
   -  interval: 5m
  - enabled: true


## Remediation
#### Triage

- Review the modified policy details (event.action, winlog.event_data).
- Identify the actor account (user.name), originating IP (source.ip), and application (process.name).
- Correlate with recent alerts or anomalies involving the same user or host.

#### Containment

- Immediately disable the user account responsible for the policy change, if unauthorized.
- Revert to the previous known-good retention policy configuration.
- Apply audit log immutability features (e.g., Azure Immutable Blob Storage, M365 Audit Retention Lock).

#### Remediation

- Implement role-based access control (RBAC) and limit who can modify retention policies.
- Enforce just-in-time (JIT) access with approval for sensitive policy changes.
- Enable continuous backup and shadow copies of logs to prevent loss due to policy tampering.

#### Post-Incident Review

- Perform a forensic investigation to determine intent and scope.
- Document and update your security baseline and auditing rules.
- Ensure automated alerting and anomaly detection are applied to all sensitive configuration changes.
