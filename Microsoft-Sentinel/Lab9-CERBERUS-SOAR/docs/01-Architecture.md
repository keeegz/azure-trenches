
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

## 4. Logic App Workflow Components

## 5. Detection and Incident Automation

## 6. Behavioral Risk Assessment

## 7. Threat Intelligence Enrichment

## 8. Investigation Report Generation

## 9. Architecture Diagram
