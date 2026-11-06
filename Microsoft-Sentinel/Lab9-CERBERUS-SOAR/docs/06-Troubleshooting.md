
# CERBERUS — Troubleshooting & Engineering Lessons Learned

## 1. Troubleshooting Overview

CERBERUS was developed through iterative testing, debugging, and validation within a controlled Microsoft Defender XDR, Microsoft Sentinel, and Azure Logic Apps environment.

During development, several challenges affected workflow execution, incident automation, telemetry correlation, and investigation reliability.

Troubleshooting focused on identifying the affected component, examining available evidence, isolating potential causes, and validating changes through subsequent tests.

### Troubleshooting Objectives

The troubleshooting process was designed to:

- Identify failures across the detection-to-investigation pipeline.
- Distinguish detection problems from automation and orchestration problems.
- Examine Logic App execution history and action-level results.
- Validate incident identifiers, alert metadata, and endpoint context.
- Investigate workflow errors without assuming their root cause.
- Document observed behavior, corrective actions, and remaining limitations.
- Improve the reproducibility and reliability of the CERBERUS lab.

### Troubleshooting Scope

The investigation pipeline includes several independently configured components:

| Component | Troubleshooting Focus |
|---|---|
| Microsoft Defender XDR | Custom detection results, alert generation, and incident correlation |
| Microsoft Sentinel | Automation rules, incident lifecycle triggers, and matching conditions |
| Azure Logic Apps | Workflow execution, action inputs and outputs, and execution failures |
| KQL / Advanced Hunting | Telemetry availability, field mappings, and process-to-network correlation |
| Azure Key Vault | Credential retrieval and access configuration |
| VirusTotal API | External reputation lookup and response processing |

### Evidence and Documentation Approach

Troubleshooting observations are distinguished from confirmed root causes.

A successful retry does not, by itself, establish why an earlier execution failed.

Similarly, a successful Logic App run confirms the execution of the observed workflow path but does not independently validate every possible failure condition or automation trigger.

The following sections document engineering challenges encountered during development and the lessons derived from them.

## 2. Troubleshooting Methodology

### Investigation Workflow

CERBERUS troubleshooting followed a structured approach:

1. Identify the failed or unexpected behavior.
2. Determine which component or workflow stage is affected.
3. Inspect available execution history, error messages, and relevant telemetry.
4. Form a testable hypothesis about the cause.
5. Apply a targeted configuration change or controlled test.
6. Re-run the affected workflow or investigation stage.
7. Compare the observed result against the expected behavior.
8. Record the outcome and any remaining uncertainty.

### Logic App Run History

Azure Logic Apps execution history provides action-level information useful for troubleshooting.

Relevant evidence may include:

- Workflow execution status and duration.
- Individual action success, failure, or skipped status.
- Trigger payload and incident metadata.
- Action inputs and outputs, where available and appropriately protected.
- HTTP response codes and connector error messages.
- Conditional branch selection and subsequent execution paths.

Sensitive values, including API credentials and authentication information, should not be copied into public troubleshooting documentation.

### Detection-to-Automation Validation

Troubleshooting requires examining the full sequence rather than assuming that one successful component guarantees the next.

The relevant stages are:

1. Endpoint activity is recorded in Defender XDR telemetry.
2. A custom detection rule evaluates matching events.
3. Defender XDR generates an alert and associates it with an incident.
4. Microsoft Sentinel evaluates configured automation rules.
5. A matching automation rule may invoke the CERBERUS Logic App.
6. The Logic App processes incident context and executes investigation actions.
7. Behavioral scoring and conditional enrichment contribute to the final report.

A failure or configuration mismatch at any stage can prevent the intended end-to-end result.

### Validation Principles

The troubleshooting process emphasizes three distinctions:

- **Observed behavior:** What execution history, telemetry, or configuration actually shows.
- **Hypothesized cause:** A possible explanation that requires further verification.
- **Validated resolution:** A corrective action followed by evidence that the expected behavior was restored.

These distinctions help prevent unsupported claims about root causes and system reliability.


## 3. HTTP 504 & Logic App Execution Troubleshooting

### Problem Overview

During CERBERUS development, Azure Logic Apps execution and testing encountered HTTP `504` errors.

These errors interrupted troubleshooting and complicated validation of the automated investigation workflow.

An HTTP 504 Gateway Timeout generally indicates that a gateway or intermediary did not receive a timely response from an upstream service.

However, the HTTP status code alone does not establish which component caused the timeout.

### Observed Behavior

During development, CERBERUS exhibited the following behavior:

- HTTP `504` errors were encountered during workflow testing.
- The errors prevented some tests from completing as expected.
- Investigation required examining Logic App execution behavior and the affected workflow stages.
- Subsequent testing demonstrated successful execution of the investigation workflow.

The available evidence does not establish a definitive root cause for every observed timeout.

### Troubleshooting Approach

The troubleshooting process focused on distinguishing between a failed workflow, an individual action timeout, and a request that timed out while the workflow continued processing.

Relevant diagnostic activities included:

1. Reviewing Logic App run history and execution status.
2. Inspecting failed or delayed actions where execution details were available.
3. Checking whether the Microsoft Sentinel trigger supplied the expected incident context.
4. Examining downstream investigation actions and their dependencies.
5. Performing controlled tests to isolate workflow behavior.
6. Repeating validation after adjustments and reviewing the resulting execution history.

These checks are useful for isolating timeout behavior, but they should not be interpreted as proof of a particular underlying cause without supporting diagnostic evidence.

### Resolution and Validation

Following iterative troubleshooting, CERBERUS successfully completed its end-to-end investigation workflow on November 4, 2026.

The validated execution included:

| Field | Observed Result |
|---|---|
| Logic App | `la-cerberus-soc-triage` |
| Validation date | November 4, 2026 |
| Execution time | Approximately 4:03:06 PM |
| Run status | Succeeded |
| Execution duration | 7.92 seconds |
| Processed incident | `2471` |
| Behavioral risk score | `25` |
| Threat intelligence enrichment | Executed successfully |
| Investigation report | Generated successfully |

This result demonstrates that the configured investigation and enrichment path was capable of completing successfully.

It does not independently establish the original cause of the HTTP 504 errors or guarantee that similar errors cannot recur.

### Engineering Lessons Learned

The troubleshooting experience highlighted several important principles:

- An HTTP timeout does not necessarily mean every downstream workflow action failed.
- Logic App run history is essential for distinguishing workflow status from individual action behavior.
- Trigger context and downstream action dependencies should be investigated separately.
- Successful retries provide evidence of recovery but do not automatically identify root cause.
- End-to-end validation is necessary after troubleshooting changes.

### Recommended Future Improvements

Further engineering work could include:

- Capturing detailed timeout diagnostics and correlation identifiers.
- Configuring appropriate action timeouts and retry policies.
- Adding explicit error-handling scopes.
- Implementing structured logging for critical investigation stages.
- Evaluating external service response times.
- Testing recovery behavior under simulated transient failures.

These improvements would help distinguish temporary service interruptions from configuration or workflow-design problems.


## 4. Microsoft Sentinel Incident Correlation & Automation Rule Troubleshooting

### Problem Overview

During the November 4, 2026 controlled validation, the CERBERUS custom detection successfully generated a Microsoft Defender XDR alert.

However, Defender XDR correlated the new alert into an existing incident rather than creating a new incident.

This behavior affected the Microsoft Sentinel automation rule originally configured to invoke the CERBERUS Logic App.

### Expected Behavior

The initial automation design expected the following sequence:

1. The custom Defender XDR detection identifies matching endpoint activity.
2. Defender XDR generates an alert.
3. A new incident is created with a title matching the custom detection.
4. Microsoft Sentinel evaluates an incident-creation automation rule.
5. The matching rule invokes `la-cerberus-soc-triage`.

The initial rule was configured as follows:

| Configuration | Value |
|---|---|
| Rule name | `CERBERUS - Controlled Incident Triage` |
| Rule order | `3` |
| Status during validation | Active |
| Trigger | When an incident is created |
| Condition | Incident title contains `CERBERUS-FINAL-TEST` |
| Action | Run `la-cerberus-soc-triage` |

### Actual Observed Behavior

The custom detection generated a Medium-severity alert named:

`CERBERUS-FINAL-TEST - Encoded PowerShell Network Activity`

However, the alert was associated with existing incident `2471`.

The incident retained the title:

`Execution incident on one endpoint`

Consequently, the observed scenario did not satisfy the initial automation rule's incident-creation trigger and title condition.

This demonstrated that alert generation, incident creation, and incident updates are distinct events that must be considered independently when designing SOAR automation.

### Investigation and Root Cause

The primary configuration mismatch was between the expected incident lifecycle event and the event observed during validation.

The original rule expected a newly created incident whose title contained the custom detection name.

Instead:

- Defender XDR generated the expected custom detection alert.
- The alert was correlated into an existing incident.
- The existing incident retained its generic title.
- The incident-creation rule's configured conditions did not match the observed scenario.

The evidence supports a rule-matching and incident-lifecycle mismatch.

It does not independently establish every internal decision made by Defender XDR's incident correlation engine.

### Incident Update Rule

To address the observed alert-grouping behavior, a second Microsoft Sentinel automation rule was configured.

| Configuration | Value |
|---|---|
| Rule name | `CERBERUS - Controlled Incident Update Validation` |
| Rule order | `5` |
| Status during validation | Active |
| Trigger | When an incident is updated |
| Update condition | Alerts added |
| Incident title condition | Contains `Execution incident on one endpoint` |
| Alert title condition | Contains `CERBERUS-FINAL-TEST` |
| Action | Run `la-cerberus-soc-triage` |
| Configured expiration | November 5, 2026, 11:59 PM |

This rule was designed to evaluate alert additions to an existing incident rather than relying exclusively on incident creation.

It also used alert-level title matching to identify the custom detection without requiring the incident itself to be renamed.

### Final Validation Outcome

The November 4, 2026 validation produced a successful CERBERUS Logic App execution.

The workflow processed incident `2471` and the expected custom detection alert.

The successful execution completed in `7.92 seconds` and generated the enriched investigation report.

The available execution evidence confirms that CERBERUS processed the intended incident context.

However, the successful Logic App run does not independently prove which Sentinel automation rule initiated it.

### Engineering Lessons Learned

The investigation demonstrated several important operational considerations:

1. A Defender XDR alert may be correlated into an existing incident.
2. Alert titles and incident titles are not necessarily identical.
3. Incident-creation automation rules do not cover every incident-update scenario.
4. Automation conditions should account for alert grouping and incident lifecycle behavior.
5. Alert-level attributes can be useful when incident titles are generic.
6. Successful downstream execution should be distinguished from proof of a particular automation trigger.

### Recommended Improvements

Future validation should include:

- Testing both newly created and updated incidents.
- Confirming automation-rule execution through appropriate audit or diagnostic evidence.
- Reviewing alert grouping and incident deduplication behavior.
- Testing automation conditions against multiple alert and incident titles.
- Avoiding overly restrictive title matching in broader deployments.
- Disabling or removing temporary validation rules after testing.

The incident-update rule was configured as a temporary validation mechanism and should not be treated as a permanent production automation policy.



## 5. KQL Correlation & Endpoint Telemetry Troubleshooting

### Investigation Overview

CERBERUS relies on Microsoft Defender XDR Advanced Hunting telemetry to correlate endpoint process execution with outbound network activity.

During development, investigation queries required validation of telemetry availability, process identifiers, field mappings, and correlation conditions.

The primary telemetry sources were:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`

### Correlation Challenges

Process and network events are stored in separate telemetry tables.

To associate a network connection with its initiating process, CERBERUS must identify matching records across both data sources.

The correlation query uses three relationships:

1. Matching Defender device identifiers.
2. Matching process identifiers.
3. Matching process creation timestamps.

These relationships help distinguish individual process instances and reduce incorrect associations caused by process identifier reuse.

### Validated KQL Join

The investigation query uses an inner join between network and process telemetry.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where DeviceId == "@{outputs('CERBERUS_-_Extract_Defender_Device_ID')}"
| where InitiatingProcessFileName =~ "powershell.exe"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "powershell.exe"
    | project
        DeviceId,
        ProcessId,
        ProcessCreationTime,
        ProcessCommandLine,
        AccountName
)
on DeviceId,
   $left.InitiatingProcessId == $right.ProcessId,
   $left.InitiatingProcessCreationTime == $right.ProcessCreationTime
```

The device identifier expression is populated by the Logic App during workflow execution.

The query therefore depends on successful extraction of the relevant Defender device identifier from the incident context.

### Telemetry and Correlation Failure Conditions

Several conditions can prevent the query from returning expected results:

| Condition | Potential Impact |
|---|---|
| Missing process telemetry | Inner join cannot match the initiating process |
| Missing network telemetry | No outbound connection available for correlation |
| Incorrect device identifier | Relevant endpoint events are excluded |
| Process identifier mismatch | Process and network records do not join |
| Process creation timestamp mismatch | Related events may not correlate |
| Events outside the seven-day window | Relevant records are filtered out |
| Non-PowerShell activity | Events are excluded by the configured process filters |

These are potential failure conditions inherent in the query design, not individually confirmed root causes of the earlier HTTP 504 errors.

### Troubleshooting Methodology

A systematic investigation can isolate correlation problems by:

1. Confirming that the endpoint is onboarded to Microsoft Defender for Endpoint.
2. Verifying that recent events exist in `DeviceProcessEvents`.
3. Verifying that recent events exist in `DeviceNetworkEvents`.
4. Checking the extracted `DeviceId` against the intended endpoint.
5. Examining process identifiers and creation timestamps independently.
6. Testing the query filters before introducing the join.
7. Applying the join and inspecting the correlated results.
8. Reviewing the returned command-line and network fields.

This approach helps distinguish missing telemetry from incorrect query logic.

### Final Validation Evidence

During the November 4, 2026 controlled validation, Defender XDR recorded the following network activity:

| Field | Observed Value |
|---|---|
| Endpoint | `nyc-cl11` |
| Initiating process | `powershell.exe` |
| Process ID | `9048` |
| Remote URL | `example.com` |
| Remote IP | `104.20.23.154` |
| Remote port | `443` |
| Network action | `ConnectionSuccess` |

The successful CERBERUS investigation subsequently produced a behavioral risk score of `25` and identified the expected remote IP address.

These observations support successful processing of the selected correlated endpoint behavior during final validation.

### Engineering Lessons Learned

The correlation implementation highlights several important considerations:

- A successful endpoint detection does not guarantee that every downstream hunting query will return results.
- Device identifiers must be mapped correctly between incident context and endpoint telemetry.
- Process creation timestamps help reduce ambiguity caused by process identifier reuse.
- Inner joins exclude records without matching entries in both telemetry sources.
- Narrow process filters improve investigation focus but can exclude relevant activity.
- Query results should be validated before relying on them for automated risk scoring.

### Recommended Improvements

Future development could include:

- Explicit handling of empty query results.
- Additional logging of extracted device identifiers.
- Validation of required telemetry fields before correlation.
- Investigation of unmatched network events.
- Broader behavioral coverage beyond PowerShell.
- Testing correlation accuracy across multiple endpoints and process instances.

The current correlation logic provides a useful foundation for automated endpoint investigation but requires broader validation before production deployment.
