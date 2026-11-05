
# CERBERUS — Behavioral Risk Scoring & KQL

## 1. Behavioral Risk Scoring Overview

CERBERUS implements a rule-based behavioral risk scoring model to evaluate correlated endpoint process and network activity.

The scoring engine operates within the Azure Logic Apps investigation workflow `la-cerberus-soc-triage` and uses Microsoft Defender XDR telemetry queried through Kusto Query Language (KQL).

Rather than relying exclusively on an alert title or incident severity, CERBERUS evaluates observable endpoint behaviors and assigns weighted values to configured indicators.

The resulting score determines the behavioral risk classification and whether conditional VirusTotal enrichment should be performed.

### Scoring Objectives

The behavioral risk model was designed to:

- Correlate endpoint process execution with outbound network activity.
- Identify encoded PowerShell command-line execution.
- Identify configured download-and-execute command patterns.
- Identify network connections involving unusual destination ports.
- Reduce scores for recognized routine Defender activity.
- Produce a bounded numerical risk score.
- Classify results into Low, Medium, High, or Critical risk levels.
- Control conditional threat intelligence enrichment.

### Risk Model Boundaries

CERBERUS uses a deterministic, lab-defined scoring model rather than a statistically calibrated threat prediction system.

A higher score indicates that more configured suspicious indicators were observed. It does not independently establish malicious intent.

The behavioral risk classification is distinct from the Microsoft Sentinel incident severity.

VirusTotal reputation results provide additional investigation context but do not currently modify the behavioral risk score.

## 2. Scoring Architecture

### Telemetry Sources

The risk model uses two primary Microsoft Defender XDR Advanced Hunting tables:

| Table | Purpose |
|---|---|
| `DeviceProcessEvents` | Process execution, command-line arguments, process identifiers, and process creation timestamps |
| `DeviceNetworkEvents` | Network connections, destination indicators, initiating process information, and connection timestamps |

### Correlation Strategy

CERBERUS correlates process and network activity using device identity, process identifiers, and process creation timestamps.

These fields help associate outbound connections with the process instance responsible for initiating the activity.

The correlation query produces event-level investigation results that can be evaluated by the scoring engine.

### Workflow Integration

The scoring stage follows this logical sequence:

1. Retrieve endpoint process telemetry.
2. Retrieve endpoint network telemetry.
3. Correlate process and network events using KQL.
4. Evaluate configured behavioral indicators.
5. Calculate the raw risk score.
6. Clamp the result to the range `0–100`.
7. Assign a behavioral risk classification.
8. Select the highest-ranked correlated result.
9. Evaluate whether conditional threat intelligence enrichment is required.

### Result Selection

The correlation query ranks results by descending behavioral risk score, followed by descending network event timestamp, and returns up to 50 rows.

The current workflow uses the highest-ranked correlated result for its reported behavioral risk assessment. It does not calculate an aggregate risk score across all events or alerts associated with the Microsoft Sentinel incident.

Consequently, the final reported risk score represents the selected correlated result rather than an incident-wide assessment.


### Related Documentation

The complete system architecture is documented in [01 — System Architecture & Design](01-Architecture.md).

The orchestration and enrichment decision workflow is documented in [03 — SOAR Automation](03-SOAR-Automation.md).


## 3. Behavioral Indicators & Scoring Weights

### Scoring Methodology

CERBERUS evaluates correlated process and network events against a set of configured behavioral conditions.

Each matching indicator contributes a positive or negative adjustment to the raw risk score.

The model uses additive scoring, meaning multiple indicators can contribute to the same correlated result.

### Behavioral Indicator Weights

| Indicator | Score Adjustment | Detection Logic |
|---|---:|---|
| Encoded PowerShell execution | +25 | Process command line contains `-EncodedCommand` or `-enc ` |
| Download-and-execute pattern | +25 | Command line contains `DownloadString`, `Invoke-Expression`, or `IEX(` |
| Unusual destination port | +20 | Remote port is present and is not `80`, `443`, or `53` |
| Recognized routine Defender activity | -40 | Remote URL contains `winatp-gw` or command line contains `DataCollection.ps1` |

### Raw Risk Score Calculation

The raw risk score is calculated by adding the configured positive indicator weights and subtracting the routine Defender activity adjustment.

The exact `iff()` expressions implementing this calculation are documented in Section 4 — KQL Risk Scoring Implementation.


For example, a correlated event with encoded PowerShell execution and an unusual destination port, but no other matching indicators, produces:

`RawRiskScore = 25 + 0 + 20 - 0 = 45`

### Score Normalization

CERBERUS constrains the final risk score to the range `0–100` using the following KQL expression:

```kql
| extend RiskScore = max_of(0, min_of(100, RawRiskScore))
```

This prevents the final score from becoming negative when routine Defender activity receives a negative adjustment.

### Risk Classification Thresholds

| Final Risk Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–69 | High |
| 70–100 | Critical |

The classification is determined by the final normalized score, not the unbounded raw score.

### Model Interpretation

The assigned score represents a deterministic assessment of the configured behavioral indicators.

It is not a probability of malicious activity, and the risk thresholds have not been statistically calibrated against a production dataset.

The model is intended to support investigation prioritization and conditional enrichment rather than make autonomous incident-response decisions.


## 4. KQL Risk Scoring Implementation

### Implementation Overview

CERBERUS uses Kusto Query Language (KQL) to evaluate behavioral indicators within correlated Microsoft Defender XDR process and network telemetry.

The scoring expressions operate on results containing process command-line information, remote destination details, and event timestamps.

The following excerpts document the behavioral scoring logic used during the November 4, 2026 validation.

### Behavioral Indicator Expressions

```kql
| extend HasEncodedCommand =
    ProcessCommandLine contains "-EncodedCommand"
    or ProcessCommandLine contains "-enc "
| extend HasDownloadExecution =
    ProcessCommandLine contains "DownloadString"
    or ProcessCommandLine contains "Invoke-Expression"
    or ProcessCommandLine contains "IEX("
| extend HasUnusualDestination =
    RemotePort !in (80, 443, 53)
    and isnotnull(RemotePort)
| extend IsRoutineDefenderTraffic =
    RemoteUrl contains "winatp-gw"
    or ProcessCommandLine contains "DataCollection.ps1"
```

These expressions generate Boolean indicators for each correlated event.

### Raw Risk Score Calculation

```kql
| extend RawRiskScore =
    iff(HasEncodedCommand, 25, 0)
    + iff(HasDownloadExecution, 25, 0)
    + iff(HasUnusualDestination, 20, 0)
    - iff(IsRoutineDefenderTraffic, 40, 0)
```

Each condition contributes its configured numerical adjustment.

The routine Defender indicator applies a negative adjustment intended to reduce scores for recognized routine activity.

### Risk Normalization and Classification

```kql
| extend RiskScore = max_of(0, min_of(100, RawRiskScore))
| extend RiskLevel = case(
    RiskScore >= 70, "Critical",
    RiskScore >= 50, "High",
    RiskScore >= 25, "Medium",
    "Low"
)
```

The normalized score is assigned a categorical risk level using descending thresholds.

### Result Ordering

```kql
| order by RiskScore desc, NetworkTimestamp desc
| take 50
```

Results are ranked by behavioral risk score, with more recent network events used as a secondary ordering criterion.

The query returns up to 50 ranked results.

The CERBERUS workflow uses the highest-ranked result for the behavioral risk assessment included in the investigation report.

### Implementation Considerations

The expressions above are excerpts from the correlation query rather than a complete standalone KQL query.

They depend on upstream process-to-network correlation producing the expected field names and data types.

The scoring logic evaluates configured patterns and does not independently determine whether an observed event is malicious.

The complete correlation implementation should be reviewed alongside the workflow's query configuration when reproducing this model in another environment.


## 5. Process-to-Network Correlation & Field Mapping

### Correlation Overview

CERBERUS correlates Microsoft Defender XDR process execution and network telemetry to associate outbound connections with their initiating process instances.

The correlation stage uses `DeviceProcessEvents` and `DeviceNetworkEvents` to establish relationships between process creation and subsequent network activity.

This correlation provides the event context required for behavioral risk scoring.

### Correlation Fields

| Field | Source | Purpose |
|---|---|---|
| `DeviceId` | Both tables | Associates events with the same Defender endpoint |
| `ProcessId` | `DeviceProcessEvents` | Native process identifier used to match `InitiatingProcessId` |
| `InitiatingProcessId` | `DeviceNetworkEvents.InitiatingProcessId` | Identifies the process responsible for the network event |
| `ProcessCreationTime` | `DeviceProcessEvents` | Native process creation timestamp used to match `InitiatingProcessCreationTime` |
| `InitiatingProcessCreationTime` | `DeviceNetworkEvents` | Helps match network activity to the originating process instance |
| `ProcessCommandLine` | `DeviceProcessEvents` | Provides command-line context for behavioral scoring |
| `RemoteIP` | `DeviceNetworkEvents` | Identifies the remote destination for enrichment |
| `RemoteUrl` | `DeviceNetworkEvents` | Provides destination context |
| `RemotePort` | `DeviceNetworkEvents` | Supports unusual-port evaluation |
| `NetworkTimestamp` | Alias of `DeviceNetworkEvents.Timestamp` | Network event timestamp renamed during the final `project` operation for ordering and investigation chronology |

### Correlation Logic

The process and network records are associated using the following logical relationship:

```text
Process.DeviceId == Network.DeviceId

Process.ProcessId == Network.InitiatingProcessId

Process.ProcessCreationTime == Network.InitiatingProcessCreationTime
```

The process creation timestamp is important because process identifiers may be reused over time.

Using the device identifier, process identifier, and process creation timestamp together reduces the likelihood of associating a network event with an unrelated process instance.


### Join Behavior

CERBERUS uses a KQL `join kind=inner` operation to correlate `DeviceNetworkEvents` with `DeviceProcessEvents`.

Only records satisfying the configured device identifier, process identifier, and process creation timestamp relationships are retained.

Network events without a matching process record are excluded from the correlated results.

The query also restricts both telemetry sources to the preceding seven days and filters for PowerShell activity.

These constraints improve the focus of the investigation but can exclude relevant activity when matching telemetry is missing or falls outside the configured query window.


### Behavioral Scoring Inputs

After correlation, CERBERUS evaluates:

- Process command-line indicators.
- Remote destination port.
- Remote URL patterns.
- Network event timestamp.

The scoring logic described in Section 4 operates on these correlated results.

### Correlation Limitations

Correlation depends on the availability and consistency of endpoint telemetry.

Missing process events, missing network events, incomplete process metadata, or mismatched timestamps may prevent an otherwise relevant process-to-network relationship from appearing in the results.

A successful correlation establishes a telemetry relationship; it does not independently prove that the associated activity is malicious.


## 6. Validated Risk Scoring Results

### Controlled Validation Scenario

On November 4, 2026, CERBERUS was tested using a benign encoded PowerShell command on the Defender-onboarded Windows 11 endpoint `nyc-cl11`.

The simulation generated a successful outbound HTTPS connection to `example.com`, which was recorded in Microsoft Defender XDR endpoint telemetry.

The associated custom detection alert was correlated into existing incident `2471`.

### Observed Endpoint Telemetry

| Field | Observed Value |
|---|---|
| Endpoint | `nyc-cl11` |
| Initiating process | `powershell.exe` |
| Process ID | `9048` |
| Remote URL | `example.com` |
| Remote IP | `104.20.23.154` |
| Remote port | `443` |
| Network action | `ConnectionSuccess` |

### Behavioral Indicator Evaluation

| Indicator | Observed Result | Score Contribution |
|---|---|---:|
| Encoded PowerShell command | Matched | +25 |
| Download-and-execute pattern | Not matched | 0 |
| Unusual destination port | Not matched (`443`) | 0 |
| Routine Defender activity | Not matched | 0 |
| **Total** | | **25** |

The simulation's command line contained `-EncodedCommand`, satisfying the encoded PowerShell indicator.

The observed destination port was `443`, which is excluded from the unusual-port condition.

The configured download-and-execute and routine Defender patterns did not contribute to the final score.

### Final Risk Assessment

The successful CERBERUS investigation report contained:

```json
{
  "BehavioralRiskAssessment": {
    "RiskScore": 25,
    "RiskLevel": "Medium",
    "RemoteIP": "104.20.23.154",
    "Status": "Evaluated"
  }
}
```

### Enrichment Decision

The risk assessment satisfied both configured enrichment requirements:

1. Risk score greater than or equal to `25`.
2. Nonempty remote IP address.

Consequently, the Logic App executed the True branch of the threat intelligence condition.

The workflow retrieved the VirusTotal API credential from Azure Key Vault, performed an IP reputation lookup, and incorporated the returned reputation information into the final investigation report.

### Validation Interpretation

The observed score of `25` demonstrates that the configured behavioral scoring model identified the encoded PowerShell indicator and assigned the expected Medium classification.

The simulation was intentionally benign. The Medium classification reflects a configured behavioral condition, not confirmation of malicious activity.

The successful enrichment branch demonstrates the scoring model's integration with the downstream SOAR decision workflow.



## 7. Model Limitations & Engineering Improvements

### Current Model Limitations

CERBERUS uses a deterministic behavioral scoring model developed for a controlled security lab.

The model evaluates a limited set of configured indicators and does not represent a comprehensive assessment of endpoint compromise.

The current positive indicator weights total a maximum of 70 points. Consequently, the Critical classification is reachable only when all three positive indicators match without the routine Defender deduction.

Although the final score is normalized to the range `0–100`, the current indicator configuration cannot produce every value within that range.

### Pattern Matching Limitations

The scoring model relies on specific command-line strings, destination ports, and URL patterns.

Legitimate administrative activity may satisfy suspicious indicators, while malicious activity may avoid the configured patterns.

For example, the presence of an encoded PowerShell command does not independently establish malicious intent.

Likewise, traffic using a common destination port such as `443` is not necessarily benign.

### Correlation and Telemetry Limitations

The process-to-network correlation depends on the availability and consistency of Microsoft Defender XDR telemetry.

Missing events, incomplete command-line information, process identifier reuse, and timestamp inconsistencies can affect correlation accuracy.

The current workflow selects the highest-ranked correlated result rather than calculating an aggregate incident-wide score.

Consequently, the final score should not be interpreted as a comprehensive measure of every activity associated with an incident.

### Threat Intelligence Limitations

VirusTotal IP reputation results are used for enrichment and analyst context.

The current implementation does not modify the behavioral risk score based on VirusTotal reputation.

A reputation result containing zero malicious detections does not prove that an IP address is safe.

### Recommended Engineering Improvements

Before broader deployment, the scoring model would benefit from:

- Additional behavioral indicators, including process ancestry and suspicious parent-child relationships.
- More robust command-line pattern detection and normalization.
- Testing against representative benign and suspicious endpoint activity.
- False-positive analysis and scoring-weight calibration.
- Improved handling of missing or incomplete telemetry.
- Validation of process-to-network correlation across additional endpoints.
- Evaluation of incident-level aggregation versus event-level scoring.
- Explicit handling of empty query results and enrichment failures.
- Additional validation of the Low, Medium, High, and Critical routing paths.
- Clear analyst review procedures before any containment or remediation actions.

### Engineering Conclusion

CERBERUS demonstrates how endpoint telemetry, KQL correlation, weighted behavioral indicators, and conditional threat intelligence enrichment can be combined into an automated security investigation workflow.

The November 4, 2026 validation produced a behavioral risk score of `25`, correctly classified the selected result as Medium, and executed the configured VirusTotal enrichment branch.

The model provides a transparent foundation for further detection engineering while preserving the distinction between suspicious behavior, heuristic risk scoring, external reputation context, and confirmed malicious activity.

### Related Documentation

- [01 — System Architecture & Design](01-Architecture.md)
- [02 — Detection Engineering & KQL](02-Detection-Engineering.md)
- [03 — SOAR Automation & Logic Apps](03-SOAR-Automation.md)
