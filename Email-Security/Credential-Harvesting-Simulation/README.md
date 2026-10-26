# Credential Harvesting Simulation — Microsoft Defender for Office 365

## Overview

This lab documents an authorized credential-harvesting
phishing simulation conducted using Microsoft Defender
for Office 365 Attack Simulation Training.

The investigation examines phishing indicators, simulated
user interaction, and cross-portal telemetry visibility
using Microsoft Defender XDR and Kusto Query Language (KQL).

## Investigation Status

Completed — documentation in progress.

## Lab Environment

- **Platform:** Microsoft Defender for Office 365
- **Simulation tool:** Attack Simulation Training
- **Investigation platform:** Microsoft Defender XDR
- **Email client:** Outlook
- **Query language:** Kusto Query Language (KQL)
- **Scope:** Single-user Microsoft 365 test tenant
- **Simulation date:** October 26, 2026
- **Attack technique:** Credential Harvest
- **Payload:** Update your Office 365 Security

## Investigation Objectives

1. Execute an authorized credential-harvesting phishing simulation against a designated lab account.
2. Identify phishing indicators in the email and simulated Microsoft sign-in page.
3. Validate message delivery, user interaction, and credential-submission status using Attack Simulation Training reports.
4. Investigate email and URL-click telemetry using Defender Explorer and Advanced Hunting.
5. Correlate `UrlClickEvents` with `EmailEvents` using `NetworkMessageId`.
6. Document observed telemetry differences, investigation limitations, and defensive lessons.
