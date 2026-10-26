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

## Simulation Methodology

### 1. Simulation Configuration

A controlled phishing simulation was configured in Microsoft Defender for Office 365 Attack Simulation Training with the following settings:

- **Simulation name:** Lab 5 - Spearphishing Sim
- **Attack technique:** Credential Harvest
- **Delivery platform:** Email
- **Payload:** Update your Office 365 Security
- **Target scope:** Single-user lab tenant
- **Simulation launch:** October 26, 2026
- **Scheduled end:** October 28, 2026
- **User training:** Assigned through Attack Simulation Training

### 2. Phishing Email Examination

The simulation delivered an email with the subject **Warning: Verify your email address**, impersonating the Microsoft account team.

Observed indicators included:

- A sender domain that did not match Microsoft's legitimate authentication domains.
- An urgent request to update account security.
- Language suggesting potential data loss if the recipient ignored the message.
- An **Update Now** button directing the recipient to a simulated sign-in page.

### 3. Controlled User Interaction

The designated lab user opened the message and followed the embedded link. The destination displayed a Microsoft-branded sign-in interface hosted on a non-Microsoft authentication domain.

No real credentials were entered or submitted. The simulation report subsequently recorded the message as delivered, read, and clicked, with zero credential submissions.

All activity was performed within an authorized lab environment. The simulation was not a real-world compromise.
