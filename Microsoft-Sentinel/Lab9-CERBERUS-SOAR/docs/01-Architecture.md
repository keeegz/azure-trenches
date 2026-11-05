
# CERBERUS — System Architecture & Design

## 1. Architecture Overview

CERBERUS is a Microsoft Sentinel and Defender XDR security orchestration, automation, and response (SOAR) lab designed to investigate security incidents through automated endpoint telemetry analysis, behavioral risk scoring, and threat intelligence enrichment.

The solution integrates Microsoft Defender XDR, Microsoft Sentinel, Azure Logic Apps, Azure Key Vault, and the VirusTotal API to produce structured investigation reports for analyst review.

CERBERUS correlates endpoint process execution with outbound network activity using Kusto Query Language (KQL). Correlated events are evaluated against a weighted behavioral risk model, which determines whether additional IP reputation enrichment should occur.

The resulting investigation report combines incident metadata, endpoint evidence, behavioral risk assessment, and available threat intelligence into a single structured output.

The implementation was validated through a controlled, benign encoded PowerShell network simulation. Automated enrichment and report generation were successfully demonstrated without performing automatic endpoint isolation or remediation.


## 2. Technology Stack

CERBERUS integrates Microsoft security services and external threat intelligence to support automated incident investigation and analyst-assisted response.

| Technology | Role in CERBERUS |
|---|---|
| Microsoft Defender for Endpoint | Collects endpoint process and network telemetry from the onboarded Windows 11 virtual machine. |
| Microsoft Defender XDR | Provides Advanced Hunting, custom detection rules, alerts, and incident correlation. |
| Microsoft Sentinel | Provides incident-based automation triggers and orchestration integration. |
| Azure Logic Apps | Hosts the CERBERUS SOAR playbook, investigation queries, conditional logic, and report generation. |
| Kusto Query Language (KQL) | Correlates endpoint process execution with network connections and calculates behavioral risk scores. |
| Azure Key Vault | Stores the VirusTotal API credential for retrieval during enrichment. |
| VirusTotal API | Provides IP reputation data, including malicious, suspicious, harmless, and undetected detection counts. |
| Windows 11 Pro VM | Serves as the Defender-onboarded endpoint for controlled, benign security simulations. |
| GitHub | Hosts project documentation, implementation evidence, and reusable queries. |


## 3. End-to-End Data Flow

CERBERUS follows an incident-driven investigation workflow that connects endpoint detection, Microsoft Sentinel automation, behavioral analysis, and external threat intelligence.

### Stage 1 — Endpoint Telemetry Collection

A Defender-onboarded Windows 11 virtual machine (`nyc-cl11`) generates process execution and network connection telemetry. Microsoft Defender for Endpoint records the relevant activity in `DeviceProcessEvents` and `DeviceNetworkEvents`.

### Stage 2 — Detection and Incident Correlation

A custom Microsoft Defender XDR detection rule identifies encoded PowerShell activity associated with a successful outbound network connection.

Defender XDR generates an alert and correlates it with an incident. During final validation, the new alert was added to existing incident `2471`.

### Stage 3 — Microsoft Sentinel Automation

Microsoft Sentinel evaluates configured automation rules against incident creation or update events.

During final validation, an incident-update automation rule matched the addition of a CERBERUS test alert and invoked the `la-cerberus-soc-triage` Logic App playbook.

### Stage 4 — Automated Endpoint Investigation

The playbook receives incident metadata and performs Defender XDR investigation queries.

CERBERUS retrieves relevant endpoint process and network telemetry, then correlates process execution with outbound connections using KQL.

### Stage 5 — Behavioral Risk Assessment

Correlated events are evaluated using weighted behavioral indicators, including encoded PowerShell execution, download-and-execute patterns, unusual destination ports, and known routine Defender activity.

The resulting risk score is bounded between 0 and 100 and assigned a severity classification.

### Stage 6 — Conditional Threat Intelligence Enrichment

When a remote IP address is available and the selected correlated event meets the configured risk threshold of 25, CERBERUS enters its threat intelligence enrichment branch.

The playbook retrieves the VirusTotal API credential from Azure Key Vault and requests reputation information for the remote IP address.

If the conditions are not satisfied, enrichment is skipped.

### Stage 7 — Investigation Report Generation

CERBERUS generates a structured report containing incident metadata, endpoint evidence, process and network correlation, behavioral risk assessment, available threat intelligence, and an analyst assessment.

The report recommends analyst review before any containment decision.

### Validated Execution

On November 4, 2026, CERBERUS successfully processed incident `2471`, calculated a behavioral risk score of `25` (Medium), enriched remote IP `104.20.23.154` through VirusTotal, and generated a completed investigation report.

The successful Logic App execution completed in approximately 7.92 seconds. No automated endpoint isolation or remediation was performed.



## 4. Logic App Workflow Components

## 5. Detection and Incident Automation

## 6. Behavioral Risk Assessment

## 7. Threat Intelligence Enrichment

## 8. Investigation Report Generation

## 9. Architecture Diagram
