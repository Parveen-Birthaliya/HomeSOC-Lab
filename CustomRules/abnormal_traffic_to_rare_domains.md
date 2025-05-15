# Abnormal Traffic to Rare Domains

**Detects** outbound DNS or web requests to domains that are not seen in the historical baseline or fall below a rarity threshold, which may indicate suspicious command-and-control callbacks, data exfiltration channels, or reconnaissance activity.



## Rules

```yaml
# rules/abnormal_traffic_to_rare_domains.yml
---
- name: Abnormal Traffic to Rare Domains
- description: Detects DNS queries or HTTP(S) requests to domains with low historical frequency (below threshold) for each host, highlighting potential C2 activity or data exfiltration over uncommon domains.

- references:
  - https://attack.mitre.org/techniques/T1071/001/
  - https://www.elastic.co/guide/en/elasticsearch/reference/current/ml-detect-rare-terms.html
  - https://www.owasp.org/index.php/Command_and_Control_C2
- tags:
  - T1071.001
  - DNS
  - C2
  - Data Exfiltration
  - Anomaly Detection
- severity: high
- risk_score: 78
- type: anomaly
- index:
  - packetbeat-*
  - filebeat-*
  - http-logs-*
- language: kuery
- query: |
    anomaly("dns.question.name", window=30m, threshold=5)
    OR
    anomaly("url.domain", window=30m, threshold=5)
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- Identify the host (`host.name`, `host.ip`) and user context (`user.name`) generating the rare-domain request.
- Extract domain details (`dns.question.name` or `url.domain`) and count of occurrences (`total_count`).
- Cross-reference with threat intelligence feeds or passive DNS data to assess malicious reputation.

#### Containment

- Block resolution or HTTP(S) requests to the suspicious domain at DNS or proxy layers.
- Quarantine the affected endpoint to prevent further callbacks.
- Suspend the user account or API key if automated tooling is implicated.

#### Remediation

- Enrich rare-domain detections with threat intelligence and automated reputation scoring.
- Implement DNS filtering or allowlists for approved domains.
- Deploy egress filtering and SSL/TLS inspection to catch encrypted exfiltration attempts.

#### Post-Incident Review

- Review passive DNS logs and HTTP archives to map historical domain usage.
- Update ML baselines to include newly validated benign domains.
- Incorporate findings into SOC playbooks and refine detection thresholds for future tuning.
