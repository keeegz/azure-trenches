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
