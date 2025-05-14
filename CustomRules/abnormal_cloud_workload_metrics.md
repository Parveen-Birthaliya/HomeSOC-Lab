# Abnormal Metrics in Cloud Workload Activity

**Detects** deviations in cloud workload performance metrics—such as CPU usage, memory consumption, network throughput, or request latency—that significantly differ from established baselines. These anomalies may indicate issues like misconfigurations, resource exhaustion, or potential malicious activities such as cryptojacking or DDoS attacks.

## Rules

```yaml
# rules/abnormal_cloud_workload_metrics.yml
---
- name: Abnormal Metrics in Cloud Workload Activity
- description: Detects significant deviations in cloud workload metrics (e.g., CPUUtilization, MemoryUtilization) that exceed established baselines, indicating potential misconfigurations, resource exhaustion, or malicious activities.

- references:
  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Anomaly_Detection.html
  - https://docs.datadoghq.com/monitors/types/anomaly/
  - https://www.uptycs.com/blog/enhancing-security-with-anomaly-detection
- tags:
  - CloudWatch
  - Anomaly Detection
  - Cloud Workload
  - Resource Utilization
  - Security Monitoring
- severity: high
- risk_score: 75
- type: anomaly
- index:
  - aws-cloudwatch-*
  - datadog-metrics-*
  - uptycs-logs-*
- language: kuery
- query: |
    anomaly("cloud.workload.cpu_usage", window=10m, threshold=3)
    OR
    anomaly("cloud.workload.memory_usage", window=10m, threshold=3)
    OR
    anomaly("cloud.workload.network_in", window=10m, threshold=3)
    OR
    anomaly("cloud.workload.network_out", window=10m, threshold=3)
- schedule:
  - interval: 5m
  - enabled: true
```

## Remediation

#### Triage

- **Identify Affected Workloads**: Determine which cloud workloads (e.g., EC2 instances, Kubernetes pods, Lambda functions) are exhibiting anomalous metrics.
- **Assess Impact**: Evaluate the severity of the anomaly to understand potential impacts on performance or security.
- **Correlate with Events**: Check for recent deployments, configuration changes, or external events that might have influenced workload behavior.

#### Containment

- **Isolate Workloads**: If the anomaly is linked to a specific workload, consider isolating it to prevent further impact.
- **Throttle Resources**: Temporarily limit resource allocation to the affected workload to mitigate potential damage.

#### Remediation

- **Adjust Resource Allocation**: Modify CPU, memory, or network settings to align with the workload's requirements.
- **Implement Auto-Scaling**: Configure auto-scaling policies to dynamically adjust resources based on workload demands.
- **Review Configurations**: Ensure that workload configurations adhere to best practices and organizational standards.

#### Post-Incident Review

- **Analyze Root Cause**: Investigate the underlying cause of the anomaly to prevent recurrence.
- **Update Baselines**: Adjust performance baselines to reflect the current operational environment.
- **Enhance Monitoring**: Implement additional monitoring or alerting mechanisms to detect similar anomalies in the future.
