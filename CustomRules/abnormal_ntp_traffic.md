# Abnormal Network Time Protocol (NTP) Traffic

**Detects** anomalous NTP traffic patterns—such as excessive query rates, usage of the monlist command, or irregular time responses—that may indicate DDoS amplification attempts, time spoofing, or reconnaissance activity against NTP servers.



## Rules

```yaml
# rules/abnormal_ntp_traffic.yml
---
- name: Abnormal Network Time Protocol (NTP) Traffic
- description: Detects high-volume or unusual NTP requests/responses (e.g., monlist queries, spoofed time replies) that exceed normal baselines and may signal amplification attacks or time-based evasion techniques.

- references:
  - https://attack.mitre.org/techniques/T1571/
  - https://tools.ietf.org/html/rfc5905
  - https://datatracker.ietf.org/doc/html/rfc1305
- tags:
  - T1571
  - NTP
  - DDoS
  - Reconnaissance
  - Time Spoofing
- severity: medium
- risk_score: 60
- type: threshold
- index:
  - packetbeat-*
  - zeek-*
  - firewall-logs-*
- language: kuery
- query: >
    network.transport:udp
    AND network.protocol:ntp
    AND (ntp.query_type:version OR ntp.request_mode:7 OR ntp.request_mode:6)
- threshold:
    field: source.ip
    value: 100
    time_window: 1m
- schedule:
  - interval: 1m
  - enabled: true

```
## Remediation
#### Triage

- Identify source and destination IPs (`source.ip`, `destination.ip`) and count of NTP queries.
- Determine query types (`ntp.query_type`) and modes (`ntp.request_mode`) involved.
- Correlate with firewall or IDS logs to confirm volumetric or malformed traffic patterns.

#### Containment

- Rate-limit or block excessive NTP traffic from offending IPs at network perimeter.
- Disable or restrict monlist and other high-risk NTP modes on vulnerable servers (`ntpdc -c "monlist"`).
- Apply ACLs to allow NTP only from authorized time sources.

#### Remediation

- Patch NTP services to the latest version and disable insecure commands (e.g., `restrict default kod nomodify notrap nopeer noquery` in `ntp.conf`).
- Implement NTP traffic inspection and anomaly detection via IDS/IPS or network monitoring tools.
- Enforce NTP authentication (symmetric keys) to prevent spoofed time responses.

#### Post-Incident Review

- Review historical NTP traffic baselines and adjust thresholds based on normal usage.
- Document the incident, update your network security policies, and train operations teams on NTP best practices.
- Incorporate NTP anomaly detection into routine security monitoring playbooks.
