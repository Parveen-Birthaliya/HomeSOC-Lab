## Abnormal Account Lockout Frequency  
**Detects:** ≥ 3 lockouts of the same Windows account within 5 minutes  
**Data Source:** Winlogbeat (Event ID 4740)  
**Rule Type:** Threshold (group by `winlog.event_data.TargetUserName`)  
**Severity:** Medium | **Risk Score:** 47  
**Tags:** T1110, Account Lockout, Brute Force  

```yaml

name: Abnormal Account Lockout Frequency
type: threshold
index: ["winlogbeat-*"]
query: 'event.code:4740 AND NOT winlog.event_data.TargetUserName:("svc_*" OR "AD_sync" OR "krbtgt")'
threshold:
  field: winlog.event_data.TargetUserName
  value: 3
  time_window: 5m
schedule:
  interval: 1m
enabled: true
