# Abnormal Account Lockout Frequency

**Detects** when a Windows user account is locked out **three or more times** within **five minutes**, indicating a possible brute-force or password-spraying attack. Excessive lockouts often precede credential-based intrusions and, if undetected, can lead to unauthorized access, lateral movement, and compliance breaches .



## Rules

```yaml
# rules/abnormal_account_lockout_frequency.yml
---
name: Abnormal Account Lockout Frequency
description: Detects ≥3 account lockouts of the same Windows user within 5 minutes (Event ID 4740), excluding service/sync accounts.
author: PK
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740 :contentReference[oaicite:1]{index=1}
  - https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-range-query.html :contentReference[oaicite:2]{index=2}
tags:
  - T1110
  - Account Lockout
  - Brute Force
severity: medium
risk_score: 47
type: threshold
index:
  - winlogbeat-*
language: kuery
query: >
  event.code:4740
  AND NOT winlog.event_data.TargetUserName:("svc_*" OR "AD_sync" OR "krbtgt")
threshold:
  field: winlog.event_data.TargetUserName
  value: 3
  time_window: 5m
schedule:
  interval: 1m
enabled: true
```

## Remediation
#### Triage

Extract source IP and host name from the alert metadata (source.ip, host.name) and correlate with preceding Event ID 4625 failures to confirm brute-force behavior 
Netwrix
.

#### Containment

- Unlock the affected account via PowerShell:

powershell
```bash
Unlock-ADAccount -Identity testuser
```
- Block the malicious IP at your perimeter firewall or Windows Defender Firewall.

#### Remediation

- Review and strengthen your AD lockout policy (e.g., set Account lockout threshold to at least 10 attempts, Reset account lockout counter after 15 minutes) per Microsoft baseline recommendations 
Microsoft Learn

- Enforce multifactor authentication (MFA) for all privileged and remote accounts to mitigate password-based attacks 
Microsoft Learn


#### Post-Incident Review

- Update rule exclusions and thresholds based on incident findings.

- Document root cause and adjust your SOC playbook accordingly.
