
# CERBERUS — SOAR Automation & Logic Apps

## 1. SOAR Automation Overview

CERBERUS is an incident-driven Security Orchestration, Automation, and Response (SOAR) proof of concept built using Microsoft Sentinel, Azure Logic Apps, Microsoft Defender XDR, and Kusto Query Language (KQL).

The workflow automates investigative tasks following the ingestion of relevant security incidents. These tasks include incident metadata extraction, endpoint telemetry collection, process and network investigation, behavioral risk scoring, conditional threat intelligence enrichment, and structured investigation reporting.

The primary Logic App workflow is named `la-cerberus-soc-triage`.

CERBERUS is designed to support analyst decision-making rather than autonomously perform containment or remediation. The current implementation does not isolate endpoints, block network indicators, or enforce a human approval workflow.

### Automation Objectives

The SOAR implementation was designed to:

- Reduce repetitive manual investigation tasks.
- Retrieve relevant Microsoft Defender XDR endpoint telemetry.
- Correlate process execution with network activity.
- Calculate a transparent, rule-based behavioral risk score.
- Perform conditional VirusTotal reputation enrichment.
- Generate structured investigation results for analyst review.
- Preserve evidence of successful and unsuccessful execution paths.

## 2. Automation Components

### Technology Stack

| Component | Role in CERBERUS |
|---|---|
| Microsoft Sentinel | Incident ingestion and automation-rule evaluation |
| Microsoft Defender XDR | Detection, incident correlation, and endpoint investigation data |
| Azure Logic Apps | Workflow orchestration and conditional execution |
| Azure Monitor Logs / KQL | Endpoint telemetry retrieval and behavioral correlation |
| Azure Key Vault | Secure storage and retrieval of the VirusTotal API credential |
| VirusTotal API | External IP reputation enrichment |
| JSON | Structured investigation report output |

### Primary Logic App

**Workflow name:** `la-cerberus-soc-triage`

The Logic App receives incident context through the Microsoft Sentinel incident trigger and executes a sequence of investigation and enrichment actions.

Its orchestration logic includes:

1. Incident payload capture and metadata extraction.
2. Endpoint identification and telemetry retrieval.
3. Process and network investigation.
4. Behavioral correlation and risk scoring.
5. Conditional external threat intelligence enrichment.
6. Structured investigation report generation.
7. Configured severity-based routing.

The November 4, 2026 end-to-end validation confirmed successful investigation, risk assessment, conditional VirusTotal enrichment, and report generation.

Although severity-based routing cases were configured, that validation did not independently establish successful execution of every routing case.


## 3. Microsoft Sentinel Automation Rules

Microsoft Sentinel automation rules evaluate incident events and determine when the CERBERUS Logic App should be invoked.

During the November 4, 2026 validation, two controlled automation rules were configured to evaluate different incident lifecycle events.

### Incident Creation Rule

| Configuration | Value |
|---|---|
| Rule name | `CERBERUS - Controlled Incident Triage` |
| Rule order | 3 |
| Status during validation | Active |
| Trigger | When incident is created |
| Condition | Incident title contains `CERBERUS-FINAL-TEST` |
| Action | Run `la-cerberus-soc-triage` |

This rule was intended to invoke CERBERUS when a newly created Sentinel incident matched the designated test title.

However, the final Defender XDR alert was correlated into an existing incident rather than creating a new one. The existing incident retained the generic title `Execution incident on one endpoint`.

Consequently, the creation rule's trigger and title conditions did not match the observed scenario.

### Incident Update Rule

| Configuration | Value |
|---|---|
| Rule name | `CERBERUS - Controlled Incident Update Validation` |
| Rule order | 5 |
| Status during validation | Active |
| Trigger | When incident is updated |
| Update condition | Alerts added |
| Incident title condition | Contains `Execution incident on one endpoint` |
| Alert title condition | Contains `CERBERUS-FINAL-TEST` |
| Action | Run `la-cerberus-soc-triage` |
| Configured expiration | November 5, 2026, 11:59 PM |

The incident-update rule was designed to handle the alert-grouping behavior observed during final validation.

By evaluating alert additions and alert-level attributes, this configuration avoids relying exclusively on new incident creation.

### Final Validation Behavior

The custom Defender XDR alert was associated with existing incident `2471`.

A successful CERBERUS Logic App execution subsequently processed incident `2471` and the expected custom detection alert.

The available run evidence confirms successful incident processing but does not independently establish which Sentinel automation rule initiated the execution.

### Automation Design Considerations

Incident lifecycle events must be considered when designing reliable Sentinel SOAR workflows.

A detection alert can be grouped into an existing incident, and automation rules restricted to incident creation may not execute for subsequent alert additions.

For production use, automation conditions should be tested against expected incident creation, update, grouping, and deduplication behavior.

The incident-update rule was configured as a temporary validation mechanism rather than a permanent production automation policy.


## 4. Logic App Trigger & Incident Payload Processing

### Microsoft Sentinel Incident Trigger

The CERBERUS Logic App uses the Microsoft Sentinel incident trigger to receive incident context when the playbook is invoked.

The trigger provides structured incident information that the workflow uses to identify the relevant security event and initiate investigation.

During the November 4, 2026 validation, the workflow processed incident `2471`, which contained the expected custom Defender XDR alert.

### Incident Payload Capture

The workflow begins by capturing the incoming incident payload using the action:

`CERBERUS - Capture Incident Payload`

This action preserves the trigger content for subsequent metadata extraction and investigation steps.

### Metadata Extraction

CERBERUS processes the incident payload to retrieve relevant identifiers and alert information.

The workflow includes actions for:

1. Extracting incident metadata.
2. Filtering relevant alert information.
3. Extracting the associated Defender device identifier.
4. Preparing endpoint context for subsequent investigation queries.

These operations establish the relationship between the Sentinel incident and the Defender XDR endpoint telemetry used in later investigation stages.

### Validated Incident Context

The successful November 4 Logic App execution included the following incident context:

| Field | Observed Value |
|---|---|
| Incident ID | `2471` |
| Alert title | `CERBERUS-FINAL-TEST - Encoded PowerShell Network Activity` |
| Logic App | `la-cerberus-soc-triage` |
| Investigation endpoint | `nyc-cl11` |
| Execution outcome | Succeeded |

The observed incident and alert identifiers confirm that the successful workflow run processed the intended controlled detection scenario.

### Investigation Handoff

After extracting the required incident and device context, CERBERUS proceeds to Microsoft Defender XDR investigation queries.

These queries retrieve endpoint process and network telemetry, providing the data required for subsequent behavioral correlation and risk scoring.

The incident payload processing stage is therefore the connection between Sentinel incident automation and the endpoint investigation workflow.


## 5. Automated Endpoint Investigation

### Investigation Overview

After extracting the incident and Defender device context, CERBERUS performs automated endpoint investigation using Microsoft Defender XDR telemetry and Kusto Query Language (KQL).

The workflow examines process execution and network activity to identify potentially suspicious behavior associated with the affected endpoint.

### Endpoint Telemetry Overview

CERBERUS retrieves endpoint context to establish the device being investigated and prepare subsequent hunting queries.

The primary telemetry sources include:

| Telemetry Source | Investigation Purpose |
|---|---|
| `DeviceProcessEvents` | Examine process execution, command-line arguments, process identifiers, and execution timestamps. |
| `DeviceNetworkEvents` | Examine outbound network connections, initiating processes, destination IP addresses, URLs, and ports. |

### Process Investigation

The workflow executes the action:

`CERBERUS - Hunt Suspicious Process Activity`

This stage retrieves relevant process execution telemetry from Defender XDR.

The results are processed through subsequent workflow actions to produce a process investigation summary and evaluate potentially suspicious execution behavior.

Examples of investigated indicators include encoded PowerShell execution and command-line patterns associated with download-and-execute behavior.

### Network Investigation

The workflow executes the action:

`CERBERUS - Investigate Network Activity`

This stage retrieves relevant network telemetry associated with the investigated endpoint.

The investigation considers:

- Remote IP addresses and destination URLs.
- Remote network ports.
- Initiating process information.
- Network activity timestamps.
- Relationships between process execution and outbound connections.

The resulting network investigation summary provides context for subsequent behavioral correlation.

### Investigation Summaries

CERBERUS uses intermediate workflow actions to organize the retrieved telemetry into structured investigation outputs.

These include:

1. Endpoint telemetry overview.
2. Process investigation summary.
3. Behavioral investigation summary.
4. Network investigation summary.

These outputs support downstream correlation, risk assessment, and investigation reporting.

### Investigation Boundaries

The automated investigation is limited to the telemetry available through the configured Defender XDR environment and the KQL queries executed by the workflow.

A missing event or an empty query result does not independently establish that suspicious activity did not occur.

The workflow gathers investigative evidence but does not perform endpoint containment, process termination, or automatic remediation.

