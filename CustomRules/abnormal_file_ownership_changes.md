# Abnormal Changes to File Ownership

**Detects** unauthorized or suspicious changes to file or folder ownership, which may indicate privilege escalation, preparation for data exfiltration, or attempts to bypass access control mechanisms. Attackers may modify ownership to gain persistent access or manipulate sensitive files outside their original permission scope.



## Rules

yaml

---
- name: Abnormal Changes to File Ownership
- description: Detects changes to file or directory ownership on Windows systems via Event ID 4670 or 5145, which may signal privilege abuse or pre-exfiltration activity.

- references:
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670
  - https://attack.mitre.org/techniques/T1222/001/ 
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5145 
- tags:
  - T1222.001
  - File Permission Change
  - Ownership Change
  - Privilege Escalation
- severity: high
- risk_score: 68
- type: query
- index:
  - winlogbeat-*
- language: kuery
- query: >
  event.code:(4670 or 5145)
  AND winlog.event_data.AccessList:*WRITE_OWNER*
  AND NOT winlog.event_data.SubjectUserName:("SYSTEM" OR "TrustedInstaller" OR "Administrator")
- schedule:
  - interval: 5m
  - enabled: true


## Remediation
#### Triage

- Identify the file or folder affected using `winlog.event_data.ObjectName`.
- Review the source user (`winlog.event_data.SubjectUserName`) and origin system (`host.name`, `source.ip`).
- Validate if the ownership change was part of an authorized activity (e.g., system patching, admin script).

#### Containment

- Revoke unauthorized access using `icacls` or via GUI permissions editor.
- Restore original ownership using PowerShell or takeown:

powershell
```bash
takeown /F "C:\Sensitive\File.txt" /A
icacls "C:\Sensitive\File.txt" /setowner "Administrators"
```
#### Remediation

- Implement tighter Group Policy Object (GPO) restrictions to prevent ownership modification by non-admin users.
- Enable file integrity monitoring (FIM) on sensitive directories.
- Apply Least Privilege principles to minimize unnecessary access to file system controls.

#### Post-Incident Review

- Investigate related access events and lateral movement attempts.
- Add known benign service accounts to exclusion list if needed.
- Update SIEM alert thresholds and detection logic based on findings.
