# Abnormal Packet Size in Network Traffic

**Detects** unusually large or small network packets that deviate from baseline MTU or typical application payload sizes. Such anomalies can indicate data exfiltration using oversized packets, tunneling techniques, or malformed packets used in evasion or DoS attacks.



## Rules

```yaml
# rules/abnormal_packet_size.yml
---
- name: Abnormal Packet Size in Network Traffic
- description: Detects network packets with sizes outside of normal operational thresholds (e.g., < 64 bytes or > 1500 bytes) which may indicate data exfiltration, tunneling, or malformed-packet attacks.

- references:
  - https://tools.ietf.org/html/rfc791
  - https://attack.mitre.org/techniques/T1572/
  - https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13684-12.html
- tags:
  - T1572
  - Network Anomaly
  - Packet Size
  - Data Exfiltration
  - Evasion
- severity: medium
- risk_score: 58
- type: query
- index:
  - packetbeat-*
  - zeek-*
  - firewall-logs-*
- language: kuery
- query: >
    (network.bytes < 64 OR network.bytes > 1500)
    AND NOT (network.protocol:icmp AND icmp.type:(0 OR 8))
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Identify source and destination (`source.ip`, `destination.ip`) and determine packet sizes (`network.bytes`).
- Verify whether large packets belong to legitimate jumbo-frame environments or fragmentation.
- Correlate with session context (`network.transport`, `network.protocol`) and historical baselines.

#### Containment

- Block or throttle offending flows at perimeter or internal firewalls.
- Drop malformed or oversized packets using NDR/IDS rules.
- Isolate affected hosts if exfiltration or tunneling is suspected.

#### Remediation

- Enforce MTU consistency and jumbo-frame policies where applicable.
- Deploy deep-packet inspection to detect tunneling protocols or encapsulated data.
- Implement network segmentation to limit high-volume transfers to untrusted segments.

#### Post-Incident Review

- Review network baselines and adjust size thresholds to reduce false positives.
- Document any legitimate use cases (e.g., storage replication) to update allowlists.
- Enhance detection logic with payload inspection and flow anomaly detection.  
