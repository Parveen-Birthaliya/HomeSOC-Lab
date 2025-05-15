# Abnormal SSL Certificate Usage

**Detects** suspicious SSL/TLS certificate usage patterns, such as self-signed certificates, expired certificates in use, or certificates issued by unauthorized or untrusted CAs. Adversaries often leverage custom or misconfigured certificates to facilitate man-in-the-middle attacks, C2 channels, or data exfiltration tunnels.



## Rules

```yaml
# rules/abnormal_ssl_certificate_usage.yml
---
- name: Abnormal SSL Certificate Usage
- description: Detects use of self-signed, expired, or unauthorized SSL/TLS certificates in network traffic or endpoint logs, indicating potential malicious interception or covert channel activity.

- references:
  - https://attack.mitre.org/techniques/T1573/
  - https://tools.ietf.org/html/rfc5280
  - https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration
- tags:
  - T1573
  - SSL/TLS
  - Certificate
  - Man-in-the-Middle
  - C2 Communication
- severity: medium
- risk_score: 62
- type: query
- index:
  - packetbeat-*
  - winlogbeat-*
  - ssl-logs-*
- language: kuery
- query: >
    (tls.server_certificate_not_valid_before:* OR tls.server_certificate_not_valid_after:* OR tls.server_certificate_issuer:*)
    AND (
      tls.server_certificate_not_valid_before < now()
      OR tls.server_certificate_not_valid_after < now()
      OR NOT tls.server_certificate_issuer:("DigiCert, Inc." OR "Let's Encrypt Authority X3" OR "GlobalSign")
    )
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Identify certificate details (`tls.server_certificate_subject`, `tls.server_certificate_issuer`, `tls.server_certificate_not_valid_after`) and associated endpoints (`host.ip`, `host.name`).  
- Validate the certificate chain against your organization’s approved CA allowlist and certificate transparency logs.  
- Correlate with application/process logs to determine the context of certificate usage.

#### Containment

- Block or redirect traffic presenting unauthorized or expired certificates at the perimeter proxy or firewall.  
- Remove self-signed or unapproved certificates from host trust stores.  
- Quarantine affected endpoints until a valid certificate is provisioned.

#### Remediation

- Enforce certificate pinning or maintain a strict CA allowlist for all critical services.  
- Implement automated certificate monitoring and renewal workflows (e.g., ACME protocol).  
- Deploy TLS inspection and validation on all ingress/egress traffic.

#### Post-Incident Review

- Audit corporate certificate inventories and update trust stores.  
- Analyze historical TLS flows for covert or anomalous patterns.  
- Update SOC playbooks and detection logic to incorporate lessons learned and refine thresholds.  
