# Abnormal Email Reply Patterns

**Detects** unusual or potentially malicious email reply behavior such as automatic replies to external domains, sudden spikes in replies to unknown recipients, or reply chains indicative of compromised accounts. This may signal phishing, business email compromise (BEC), or lateral movement using hijacked email sessions.



## Rules

```yaml

- name: Abnormal Email Reply Patterns
- description: Detects anomalous email reply activity, such as sudden reply spikes to external addresses or auto-responses to suspicious domains, potentially indicating BEC, phishing, or account compromise.

- references:
  - https://attack.mitre.org/techniques/T1114/
  - https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-threats?view=o365-worldwide
  - https://learn.microsoft.com/en-us/security/compass/incident-response-playbook-email-account-compromise
- tags:
  - T1114
  - Business Email Compromise
  - Phishing
  - Suspicious Email Behavior
  - Account Compromise
- severity: high
- risk_score: 81
- type: threshold
- index:
  - o365-management-activity-*
  - email-security-logs-*
- language: kuery
- query: >
    event.action:"Send" 
    AND email.direction:"outbound"
    AND email.to.domain:!("<your_company_domain>.com")
    AND NOT email.from.address:("noreply@<your_company>.com" OR "alerts@<your_company>.com")
- threshold:
    field: email.from.address
    value: 10
    time_window: 5m
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Review sender (`email.from.address`) and recipients (`email.to.address`, `email.to.domain`) involved in the suspicious reply pattern.
- Correlate with user login events (e.g., `SigninLogs`) to identify anomalies in access behavior.
- Check message content for phishing or malicious intent.

#### Containment

- Suspend affected mailbox and force sign-out of all sessions.
- Revoke tokens and reset credentials for the impacted account.
- Block outbound mail flow temporarily if multiple accounts show similar behavior.

#### Remediation

- Enable outbound DLP policies to detect exfiltration or anomalous communications.
- Enforce MFA across all users, especially those handling sensitive communications.
- Implement anti-phishing policies and external recipient tagging.

#### Post-Incident Review

- Search historical emails for prior signs of compromise or suspicious threads.
- Notify internal teams of BEC indicators and update awareness materials.
- Refine detection thresholds and add known services or use cases to the allowlist.
