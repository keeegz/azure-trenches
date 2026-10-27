# Lab 7 — Authentication Detection & SOAR Automation
## Overview

This lab demonstrates an end-to-end authentication threat detection workflow using Windows Security Event logs, Microsoft Sentinel, and Microsoft Defender XDR.

A controlled authentication failure scenario was generated against a local Windows account to produce Windows Security Event ID 4625. The resulting telemetry was ingested into Microsoft Sentinel and analyzed using a custom KQL detection query.

A scheduled analytics rule was deployed to identify repeated failed network logons, generate security alerts, and create incidents for investigation.

An incident-triggered automation rule was then configured to apply a classification tag, demonstrating automated incident enrichment within the Microsoft security ecosystem.

## Objectives

- Generate and validate Windows Security Event ID 4625.
- Investigate failed network authentication attempts using KQL.
- Develop a threshold-based detection query.
- Deploy a scheduled Microsoft Sentinel analytics rule.
- Configure account, host, and IP entity mappings.
- Validate alert and incident generation in Microsoft Defender.
- Implement and verify incident-triggered automation.
- Document detection limitations and opportunities for improvement.

## Technologies Used

- Microsoft Sentinel
- Microsoft Defender XDR
- Azure Virtual Machines
- Windows 11
- Windows Security Event Logs
- Kusto Query Language (KQL)
- Microsoft Sentinel Analytics Rules
- Microsoft Sentinel Automation Rules

## MITRE ATT&CK Mapping

**Tactic:** Credential Access

**Technique:** T1110 — Brute Force

The detection models repeated authentication failures that may be associated with brute-force activity. The events were deliberately generated in a controlled lab environment and do not represent a confirmed malicious attack.

## Detection Engineering — Repeated Failed Network Logons

### Scenario

A non-administrative local Windows account named `SOAR-Test` was created on the Azure-hosted Windows 11 virtual machine `NYC-CL11`.

Controlled failed authentication attempts were generated using the Windows `net use` command against the local loopback address (`127.0.0.1`).

The attempts produced Windows Security Event ID **4625**, indicating failed logon activity.

The following event attributes were validated:

| Field | Value | Significance |
|---|---|---|
| Event ID | 4625 | Failed Windows authentication |
| Logon Type | 3 | Network logon attempt |
| Account | SOAR-Test | Controlled test account |
| Source IP | 127.0.0.1 | Local loopback test source |
| Computer | NYC-CL11 | Windows endpoint generating telemetry |

### KQL Detection Query

```kusto
let DetectionWindow = 1h;
let FailureThreshold = 2;
SecurityEvent
| where TimeGenerated >= ago(DetectionWindow)
| where EventID == 4625
| where LogonType == 3
| where Account contains "SOAR-Test"
| where isnotempty(IpAddress)
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, Account, IpAddress
| where FailedAttempts >= FailureThreshold
| project
    TimeGenerated = LastSeen,
    Computer,
    Account,
    IpAddress,
    FailedAttempts,
    FirstSeen,
    LastSeen
| order by FailedAttempts desc
```

### Detection Logic

The query searches the `SecurityEvent` table for failed network authentication attempts occurring within a one-hour detection window.

Events are grouped by computer, account, and source IP address. The query calculates the number of failed attempts and identifies the first and last observed timestamps.

A threshold of two failed attempts was selected to demonstrate detection behavior in a controlled lab environment.

**Production consideration:** This threshold is intentionally low and would require tuning to reduce false positives. A production implementation should consider account behavior, source IP reputation, authentication baselines, approved testing activity, and alert suppression.

### Validation Results

The query successfully returned a matching result containing:

- Host: `NYC-CL11`
- Account: `NYC-CL11\SOAR-Test`
- Source IP: `127.0.0.1`
- Failed attempts: `2`

This confirmed successful ingestion of Windows authentication telemetry and execution of the custom KQL detection logic.
