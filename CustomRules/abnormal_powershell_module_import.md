# Abnormal PowerShell Module Import

**Detects** unauthorized or unusual imports of PowerShell modules, which may indicate lateral movement, persistence, or execution of custom offensive tooling. Attackers often load malicious or uncommon modules to evade detection or extend their capabilities.



## Rules

```yaml
# rules/abnormal_powershell_module_import.yml
---
- name: Abnormal PowerShell Module Import
- description: Detects any `Import-Module` invocation in PowerShell logs for modules not in the approved whitelist, signaling potential malicious tooling or unsanctioned scripts.

- references:
  - https://attack.mitre.org/techniques/T1086/
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4104
  - https://learn.microsoft.com/powershell/module/overview?view=powershell-7.2
- tags:
  - T1086
  - PowerShell
  - Module Import
  - Persistence
  - Lateral Movement
- severity: medium
- risk_score: 60
- type: query
- index:
  - winlogbeat-*
  - powershell-logs-*
- language: kuery
- query: >
    event.provider:"Microsoft-Windows-PowerShell"
    AND event.code:4104
    AND event.event_data.ScriptBlockText:("Import-Module")
    AND NOT event.event_data.ScriptBlockText:/Import-Module\s+(PSScheduledJob|PSReadline|Microsoft.PowerShell.Core|Microsoft.PowerShell.Management)/
- schedule:
  - interval: 1m
  - enabled: true
```

## Remediation
#### Triage

- Extract the module name from `event.event_data.ScriptBlockText`.
- Identify the invoking account (`winlog.event_data.UserID`) and source host (`host.name`, `source.ip`).
- Cross-reference with known deployment or patch activities to rule out legitimate imports.

#### Containment

- Quarantine the host if the module is confirmed malicious.
- Block or remove the module file from disk.
- Disable the involved user account or restrict its PowerShell execution.

#### Remediation

- Enforce Constrained Language Mode or AppLocker rules to restrict module loading.
- Maintain an approved module whitelist and monitor for deviations.
- Enable script signing policies to allow only signed modules.

#### Post-Incident Review

- Review other PowerShell activity (script block logs, module load events) around the same time.
- Update detection exclusions for any newly sanctioned modules.
- Incorporate findings into your PowerShell security policy and training.
