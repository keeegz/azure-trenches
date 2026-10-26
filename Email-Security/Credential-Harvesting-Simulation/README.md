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
![Simulated phishing email impersonating Microsoft, showing the sender address, urgency, and Update Now button](screenshots/phishing-email.PNG)

The simulation delivered an email with the subject **Warning: Verify your email address**, impersonating the Microsoft account team.

Observed indicators included:

- A sender domain that did not match Microsoft's legitimate authentication domains.
- An urgent request to update account security.
- Language suggesting potential data loss if the recipient ignored the message.
- An **Update Now** button directing the recipient to a simulated sign-in page.

### 3. Controlled User Interaction
![Simulated Microsoft sign-in page hosted on a non-Microsoft domain](screenshots/simulated-login-page.PNG)

The designated lab user opened the message and followed the embedded link. The destination displayed a Microsoft-branded sign-in interface hosted on a non-Microsoft authentication domain.

No real credentials were entered or submitted. The simulation report subsequently recorded the message as delivered, read, and clicked, with zero credential submissions.

All activity was performed within an authorized lab environment. The simulation was not a real-world compromise.

## Investigation Findings

### 1. Attack Simulation Training Results
![Microsoft Defender Attack Simulation Training results showing message delivery, URL click activity, and zero credential submissions](screenshots/simulation-report.PNG)

Microsoft Defender for Office 365 Attack Simulation Training
confirmed the following activity:

| Metric | Result |
|---|---|
| Messages delivered | 1/1 |
| Messages read | 1/1 |
| Phishing links clicked | 1/1 |
| Credentials submitted | 0/1 |
| Users compromised | 0/1 |
| Users who reported the message | 0/1 |

The simulation confirmed that the designated user interacted
with the phishing link without submitting credentials.
A link click alone was not evidence of credential compromise.

### 2. Defender Explorer Investigation
![Defender Explorer showing three email records, including the training assignment notification, but not the simulated phishing payload](screenshots/explorer-results.PNG)

The simulated phishing message was not returned by a
subject-based search in Defender Explorer.

Removing the subject filter revealed other tenant email
activity, including a Microsoft Attack Simulation Training
assignment notification.

This established that Explorer contained email telemetry for
the investigation period, but the simulated phishing payload
was not visible in the results reviewed.

### 3. Advanced Hunting — EmailEvents
![Defender Advanced Hunting EmailEvents query showing four email subjects, including the training notification, but no simulated phishing payload](screenshots/email-events-query.PNG)

A search of `EmailEvents` for the simulated message subject
returned no matching records.

A broader query grouping email events by subject returned
four other messages, including the training assignment
notification.

This supported the observation that standard email telemetry
was available, while the simulated phishing payload was not
found using the queries performed.

### 4. Advanced Hunting — UrlClickEvents
![Defender Advanced Hunting UrlClickEvents showing the simulated phishing link interaction with ClickAllowed and IsClickedThrough set to zero](screenshots/url-click-event.PNG)

A search of `UrlClickEvents` identified the simulated phishing
link interaction.

| Field | Observed value |
|---|---|
| Event timestamp | October 26, 2026, 1:31:51 PM |
| ActionType | `ClickAllowed` |
| IsClickedThrough | `0` |
| Total matching clicks | 1 |
| Unique users | 1 |
| NetworkMessageId | Present |

`ClickAllowed` indicated that the recorded URL interaction
was allowed.

`IsClickedThrough = 0` did not negate the click; it indicated
that the event was not recorded as a user clicking through
a warning or block page.

### 5. Cross-Table Correlation
![Defender Advanced Hunting leftouter join correlating UrlClickEvents with EmailEvents, showing a recorded URL click without matching email fields](screenshots/click-correlation.PNG)

A `leftouter` join between `UrlClickEvents` and `EmailEvents`
on `NetworkMessageId` retained the URL-click record but
returned no matching email fields.

The investigation therefore confirmed URL-click telemetry
without locating a corresponding email record in the
queried `EmailEvents` data.

### 6. Key Finding and Limitations

**Key finding:** Attack Simulation Training recorded delivery
and user interaction, while Defender XDR Advanced Hunting
independently recorded the allowed URL click.

However, the simulated phishing payload was not found in
Defender Explorer or `EmailEvents` during this investigation.

This represents an observed telemetry visibility discrepancy
within the lab, not proof that Microsoft Defender universally
excludes attack simulation messages from email telemetry.

The investigation was limited to one authorized simulation,
one test account, the available tenant telemetry, and the
query time windows used.

No actual credential compromise was observed or demonstrated.
