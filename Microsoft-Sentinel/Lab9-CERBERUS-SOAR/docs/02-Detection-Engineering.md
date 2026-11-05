
# CERBERUS — Detection Engineering & KQL

## 1. Detection Engineering Overview

CERBERUS uses Microsoft Defender XDR Advanced Hunting and custom detection rules to identify suspicious endpoint activity and provide incident context for automated investigation through Microsoft Sentinel and Azure Logic Apps.

The detection engineering component focuses on observable endpoint behavior, including PowerShell execution, encoded command-line arguments, and associated outbound network connections.

The final validation used a controlled, benign encoded PowerShell simulation on the Defender-onboarded Windows 11 endpoint `nyc-cl11`. Microsoft Defender XDR generated a Medium-severity alert that was correlated into existing incident `2471`.

The resulting incident provided the context for a successful CERBERUS Logic App investigation, behavioral risk assessment, conditional VirusTotal enrichment, and structured report generation.

The detection identifies activity matching configured behavioral conditions; it does not independently establish malicious intent.

## 2. Detection Objectives

The detection engineering implementation was designed to:

- Identify PowerShell-initiated outbound network connections.
- Detect encoded PowerShell command-line execution.
- Correlate relevant process and network telemetry.
- Generate Defender XDR alerts for matching activity.
- Provide incident context for Microsoft Sentinel automation.
- Validate detection behavior using controlled, benign simulations.

Detection configuration, KQL implementation, test methodology, and validation evidence are documented in the following sections.


## 3. Telemetry Sources & Detection Logic

CERBERUS uses Microsoft Defender XDR Advanced Hunting to investigate endpoint process execution and network activity. The final custom detection rule was based on `DeviceNetworkEvents`, while the broader investigation workflow also uses `DeviceProcessEvents`.

### Telemetry Sources

| Data Source | Purpose |
|---|---|
| `DeviceNetworkEvents` | Identifies network connections, initiating processes, destination IP addresses, URLs, ports, and connection outcomes. |
| `DeviceProcessEvents` | Provides process execution details, command-line arguments, process identifiers, and creation timestamps for correlation. |

### Final Custom Detection Query

The following KQL was used for the November 4, 2026 controlled validation:

```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where DeviceName =~ "nyc-cl11"
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine contains "-EncodedCommand"
| where RemoteUrl =~ "example.com"
| where ActionType == "ConnectionSuccess"
| project
    Timestamp,
    DeviceId,
    DeviceName,
    ReportId,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessId,
    InitiatingProcessCommandLine
```

### Detection Conditions

The query requires all of the following:

1. Network activity observed within the preceding hour.
2. Activity originating from the designated lab endpoint `nyc-cl11`.
3. An outbound connection initiated by `powershell.exe`.
4. A process command line containing `-EncodedCommand`.
5. A remote URL matching the benign test destination `example.com`.
6. A successful network connection recorded as `ConnectionSuccess`.

The endpoint and destination filters intentionally restrict this detection to the controlled lab scenario.

### Detection Interpretation

Encoded PowerShell execution combined with outbound network activity can be relevant to suspicious execution and command-and-control investigations. However, these behaviors can also occur in legitimate administrative workflows.

This detection was designed to validate telemetry visibility, custom alert generation, and downstream incident processing. It does not classify the observed benign simulation as confirmed malicious activity.


## 4. Custom Detection Rule Configuration

The final validation query was configured as a Microsoft Defender XDR custom detection rule to generate an alert when matching endpoint network telemetry was observed.

### Rule Configuration

| Configuration | Validated Setting |
|---|---|
| Rule name | `CERBERUS-FINAL-TEST - Encoded PowerShell Network Activity` |
| Detection platform | Microsoft Defender XDR |
| Data source | `DeviceNetworkEvents` |
| Detection frequency | Every hour |
| Alert severity | Medium |
| MITRE ATT&CK technique | T1059 — Command and Scripting Interpreter |
| Device scope | NYC Client Machines |
| Incident correlation | Enabled |
| Detection environment | Controlled Windows 11 lab endpoint |

### Detection-to-Incident Behavior

During final validation, Defender XDR generated a Medium-severity alert associated with the encoded PowerShell network simulation.

Rather than creating a new incident, Defender correlated the alert into existing incident `2471`, titled `Execution incident on one endpoint`.

This distinction affected downstream automation because the existing incident was updated instead of a new incident being created.

### Engineering Considerations

The rule was deliberately scoped to a known endpoint and benign destination to support reproducible validation.

The hourly evaluation schedule introduces a detection interval; an observed event should not be interpreted as producing an immediate alert.

The detection query and rule configuration demonstrate a controlled proof of concept. Broader production deployment would require tuning, false-positive evaluation, appropriate entity mapping, and validation across additional endpoints and behaviors.


## 5. Controlled PowerShell Simulation

### Test Objective

Generate recognizable encoded PowerShell execution and outbound HTTPS network telemetry on the Defender-onboarded Windows 11 endpoint `nyc-cl11`.

The simulation used a benign request to `https://example.com` to validate the custom detection rule and downstream incident investigation pipeline.

### Simulation Commands

The following PowerShell commands were executed in the authorized lab environment:

```powershell
$script = 'Invoke-WebRequest -Uri "https://example.com" -UseBasicParsing | Out-Null'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
powershell.exe -NoProfile -EncodedCommand $encoded
```

The command encodes a benign HTTPS request as UTF-16LE Base64 and executes it using PowerShell's `-EncodedCommand` parameter.

This produces a recognizable command-line indicator while allowing Defender for Endpoint to observe the associated process and network activity.

### Observed Telemetry

| Field | Observed Value |
|---|---|
| Endpoint | `nyc-cl11` |
| Initiating process | `powershell.exe` |
| Process ID | `9048` |
| Remote URL | `example.com` |
| Remote IP | `104.20.23.154` |
| Remote port | `443` |
| Network action | `ConnectionSuccess` |
| Event timestamp | November 4, 2026, 3:52:18 PM (lab local time) |

### Validation Interpretation

The observed network event confirmed that Microsoft Defender XDR recorded a successful outbound connection associated with PowerShell execution.

The initiating process command line contained `-EncodedCommand`, satisfying the relevant custom detection condition.

The simulation was intentionally benign. The encoded command was used to validate detection visibility and alert generation, not to demonstrate malware execution, persistence, credential theft, or actual command-and-control activity.


