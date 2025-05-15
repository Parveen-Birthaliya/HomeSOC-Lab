# Abnormal SSL Certificate Validity Changes

**Detects** unexpected modifications to SSL/TLS certificate validity periods—such as changes to `notBefore` or `notAfter` dates—that may indicate malicious replacement of certificates for man-in-the-middle (MitM) attacks, covert C2 channels, or anti-forensic tampering.



## Rules

```yaml
# rules/abnormal_ssl_certificate_validity_changes.yml
---
- name: Abnormal SSL Certificate Validity Changes
- description: Detects changes to SSL/TLS certificate validity dates (notBefore/notAfter) in network or endpoint logs, indicating possible certificate swapping or tampering.

- references:
  - https://tools.ietf.org/html/rfc5280
  - https://attack.mitre.org/techniques/T1573/
  - https://learn.microsoft.com/en-us/windows/win32/secauthn/certificate-chain-validation
- tags:
  - T1573
  - SSL/TLS
  - Certificate
  - Man‐in‐the‐Middle
  - Anti‐Forensics
- severity: high
- risk_score: 70
- type: query
- index:
  - packetbeat-*
  - ssl-logs-*
  - winlogbeat-*
- language: kuery
- query: >
    (tls.server_certificate_not_valid_before:* AND tls.server_certificate_not_valid_after:*)
    AND (
      tls.server_certificate_not_valid_before > tls.previous_certificate_not_valid_before
      OR tls.server_certificate_not_valid_after < tls.previous_certificate_not_valid_after
    )
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Extract certificate fields (`tls.server_certificate_subject`, `tls.server_certificate_issuer`, `tls.server_certificate_not_valid_before`, `tls.server_certificate_not_valid_after`) and compare against known-good values.  
- Identify source and destination endpoints (`source.ip`, `destination.ip`, `host.name`).  
- Correlate with recent configuration changes, deployments, or patch management activity.

#### Containment

- Block or tunnel traffic presenting the suspect certificate at the network perimeter or proxy.  
- Remove or replace the unauthorized certificate on affected hosts or services.  
- Temporarily disable the impacted service until a valid certificate is restored.

#### Remediation

- Enforce automated certificate management (e.g., ACME/Let’s Encrypt) with strict renewal pipelines.  
- Maintain a certificate inventory and use certificate-pinning or allowlists.  
- Enable continuous monitoring of certificate validity and integrity (e.g., Certificate Transparency logs).

#### Post-Incident Review

- Audit certificate change events over the past 30 days to identify patterns.  
- Update SOC playbooks and detection logic to include new legitimate certificate authorities or services.  
- Train operations teams on secure certificate handling and best practices.  
