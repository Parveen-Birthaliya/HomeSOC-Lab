# Abnormal Traffic to Geographically Unusual Locations

**Detects** network connections from internal hosts to external IPs located in countries or regions that are rare or never seen in baseline traffic. Such anomalous geolocation patterns may indicate credentialed lateral movement, data exfiltration to offshore servers, or command-and-control channels using compromised hosts in unexpected locales.



## Rules

```yaml
# rules/abnormal_geo_unusual_traffic.yml
---
- name: Abnormal Traffic to Geographically Unusual Locations
- description: Detects outbound network flows to IPs in geographic regions outside of an established baseline for each host, highlighting potential exfiltration or C2 communication via uncommon locations.

- references:
  - https://attack.mitre.org/techniques/T1041/
  - https://dev.maxmind.com/geoip/geoip2/geolite2/
  - https://www.ripe.net/publications/docs/ripe-723
- tags:
  - T1041
  - GeoIP
  - Exfiltration
  - C2
  - Anomaly Detection
- severity: high
- risk_score: 80
- type: query
- index:
  - packetbeat-*
  - firewall-logs-*
  - netflow-*
- language: kuery
- query: >
    event.dataset:(packetbeat.network_traffic OR firewall.network_traffic OR netflow.flows)
    AND network.direction:outbound
    AND NOT source.geolocation.country_iso_code:("baseline_countries")
    AND destination.ip:*
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation
#### Triage

- **Identify Host & Destination**  
  Extract `host.name`, `host.ip`, and `destination.ip`; perform a GeoIP lookup to confirm actual country/region.  
- **Baseline Comparison**  
  Compare against historical `source.geolocation.country_iso_code` for this host to determine if the region is truly unusual.  
- **Context Correlation**  
  Correlate with user login events (`winlog.event_data.SubjectUserName` or authentication logs) and process metadata (`process.name`) to assess legitimacy.

#### Containment

- **Block Traffic**  
  Temporarily block outbound traffic to the suspicious geographic region at the firewall or proxy.  
- **Isolate Host**  
  Quarantine the affected host on a remediation VLAN pending further investigation.

#### Remediation

- **Validate Business Need**  
  Confirm if the destination region is part of legitimate business operations (e.g., cloud region, vendor site); update `baseline_countries` accordingly.  
- **Harden Egress Controls**  
  Enforce egress filtering by country on critical subnets; implement geo-blocking policies.  
- **Implement DLP/SSL Inspection**  
  Deploy Data Loss Prevention or SSL/TLS inspection on outbound flows to detect and block unauthorized exfiltration.

#### Post-Incident Review

- **Review GeoIP Baselines**  
  Recalculate normal geographic destinations per host over the past 90 days; adjust thresholds.  
- **Update Playbooks**  
  Incorporate geolocation anomaly detection into SOC runbooks; train analysts on interpreting GeoIP data.  
- **Improve Alerting**  
  Refine rule to allow short-lived business exceptions via whitelists and automated approval workflows.
