# Abnormal Traffic Spikes from a Single Host

**Detects** sudden or sustained spikes in network traffic volume originating from a single host, which may indicate data exfiltration, DDoS participation, cryptojacking payloads sending heartbeat data, or compromised systems performing large-scale scanning.



## Rules

```yaml
# rules/abnormal_traffic_spikes_single_host.yml
---
- name: Abnormal Traffic Spikes from a Single Host
- description: Detects when a single host generates traffic volumes significantly above its baseline (e.g., >1 GB in 5 minutes), signaling possible exfiltration, DDoS amplification, or unauthorized mass-scanning.

- references:
  - https://attack.mitre.org/techniques/T1041/
  - https://www.cisco.com/c/en/us/td/docs/security/firepower/630/fpmc/administration/guide/fpmc-admin-guide.pdf
  - https://www.ietf.org/rfc/rfc2236.txt
- tags:
  - T1041
  - Data Exfiltration
  - DDoS
  - Network Anomaly
  - Baseline Deviation
- severity: high
- risk_score: 85
- type: threshold
- index:
  - packetbeat-*
  - zeek-*
  - firewall-logs-*
- language: kuery
- query: >
    NOT network.community_id:()
    AND host.name:*
    | stats sum(network.bytes) as total_bytes by host.name, interval=5m
    | where total_bytes > 1073741824
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Identify the affected host (`host.name`, `host.ip`) and quantify traffic (`total_bytes`).
- Determine destination patterns (`destination.ip`, `network.community_id`) and protocols.
- Cross-reference with known exfiltration destinations or DDoS C2 endpoints.

#### Containment

- Throttle or block outbound traffic from the host at the firewall.
- Isolate the host on a remediation VLAN or disable its network interface.
- Terminate suspicious processes or connections via EDR.

#### Remediation

- Investigate host for malware, misconfigured services, or compromised credentials.
- Apply least-privilege network segmentation to limit bulk transfers from endpoints.
- Enforce upload quotas and deep-packet inspection for high-volume flows.

#### Post-Incident Review

- Review historical traffic baselines and refine threshold values.
- Update detection logic to exclude approved backup or replication jobs.
- Incorporate findings into SOC playbooks and train analysts on host-based traffic anomalies.
