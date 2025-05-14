# Abnormal Increase in Failed Command-Line Operations

**Detects** a surge in failed or non-zero-exit-code command executions on endpoints, which may indicate brute-forcing of CLI tools, malicious script execution errors, or reconnaissance attempts using automated tools. Rapid failure spikes can precede privilege escalation or lateral movement activities.



## Rules

```yaml
# rules/abnormal_failed_cli_operations.yml
---
- name: Abnormal Increase in Failed Command-Line Operations
- description: Detects when 20 or more command executions return a non-zero exit code within 10 minutes (Sysmon Event ID 1 & Windows Event ID 4688), indicating potential abuse of command-line tools or automated attack scripts.

- references:
  - https://attack.mitre.org/techniques/T1059/  
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688  
  - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon  
- tags:
  - T1059
  - Command-Line
  - Anomaly Detection
  - Reconnaissance
  - Automation Abuse
- severity: medium
- risk_score: 64
- type: threshold
- index:
  - winlogbeat-*
  - sysmon-*
- language: kuery
- query: >
    (event.provider:"Microsoft-Windows-Sysmon" AND event.code:1 AND process.exit_code:* AND process.exit_code:!0)
    OR
    (event.code:4688 AND winlog.event_data.Status:!0)
- threshold:
    field: host.name
    value: 20
    time_window: 10m
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Review failed command details (`process.command_line`, `process.exit_code`) and the invoking user (`winlog.event_data.SubjectUserName` or `user.name`).
- Correlate with prior successful executions or anomalous logon events on the same host.
- Determine if failures stem from misconfiguration, legitimate testing, or malicious tooling.

#### Containment

- Suspend or isolate the affected host to prevent further automated attacks.
- Block known malicious tools or scripts via application control (AppLocker, WDAC).
- Force logoff or disable credentials of accounts exhibiting excessive CLI failures.

#### Remediation

- Enforce least-privilege and restrict high-risk shell access to approved administrators.
- Harden endpoint configurations to limit script execution (e.g., Constrained Language Mode for PowerShell).
- Deploy EDR policies to alert on or block repeated command-line failures.

#### Post-Incident Review

- Analyze script repositories and scheduled tasks for unauthorized automation.
- Refine detection thresholds and exclude known benign maintenance jobs.
- Update SOC playbooks with discovered tools, exit codes, and user behaviors.
