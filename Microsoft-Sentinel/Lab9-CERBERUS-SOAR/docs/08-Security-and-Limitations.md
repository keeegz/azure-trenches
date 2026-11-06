
# CERBERUS — Security Architecture, Controls & Limitations

## 1. Security Overview

CERBERUS is a controlled security orchestration, automation, and response (SOAR) project built using Microsoft Defender XDR, Microsoft Sentinel, Azure Logic Apps, Azure Key Vault, KQL, and VirusTotal.

The project demonstrates automated endpoint investigation, behavioral risk assessment, conditional threat intelligence enrichment, and structured incident reporting.

Because CERBERUS processes security telemetry and interacts with external services, its architecture must account for credential exposure, identity permissions, sensitive investigation data, automation reliability, and the risks associated with automated response.

### Security Objectives

The principal security objectives are to:

1. Protect API credentials and other sensitive configuration values.
2. Restrict access to security resources using least privilege.
3. Limit unnecessary exposure of endpoint and incident telemetry.
4. Prevent unvalidated investigation results from triggering destructive actions.
5. Preserve human oversight of security decisions.
6. Identify workflow failures without assuming successful execution.
7. Document the boundaries between demonstrated lab functionality and production-ready controls.

### Security Design Principles

CERBERUS follows several security-oriented design principles:

| Principle | Architectural Application |
|---|---|
| Least privilege | Restrict identities to required resources and operations |
| Secret isolation | Retrieve API credentials from Azure Key Vault |
| Conditional execution | Invoke external enrichment only when configured conditions are satisfied |
| Defense in depth | Combine endpoint telemetry, behavioral analysis, and external intelligence |
| Human oversight | Recommend analyst review rather than automatically contain endpoints |
| Controlled testing | Use benign activity within an authorized lab |
| Evidence-based validation | Distinguish observed results from untested capabilities |

These principles describe the project's design approach and recommended security posture.

They do not imply that every production security control has been independently audited or enforced.

## 2. Credential Management & Azure Key Vault

### Credential Security Overview

CERBERUS integrates with the VirusTotal API to retrieve reputation information for selected network indicators.

The VirusTotal API requires an authentication credential.

Embedding that credential directly into KQL queries, workflow definitions, GitHub documentation, or other publicly accessible artifacts would introduce unnecessary exposure risk.

CERBERUS therefore uses Azure Key Vault as its credential retrieval component.

### Observed Credential Retrieval Flow

The configured enrichment workflow follows this sequence:

1. CERBERUS evaluates the behavioral risk score and remote IP.
2. The workflow determines whether enrichment conditions are satisfied.
3. The Logic App executes its Azure Key Vault retrieval action.
4. The retrieved credential is used for the VirusTotal API request.
5. The API response is processed into structured reputation statistics.
6. The final investigation report contains the enrichment results without including the API credential.

The November 4, 2026 validation demonstrated successful Key Vault retrieval and VirusTotal enrichment for the observed investigation.

### Credential Protection Considerations

The following safeguards are recommended when operating or extending the integration:

- Grant secret retrieval access only to the identity that requires it.
- Prefer managed identities over long-lived application credentials where supported.
- Avoid hardcoding API keys in workflow definitions, scripts, or repository files.
- Enable appropriate protection for sensitive Logic App inputs and outputs.
- Restrict access to workflow run history containing sensitive action data.
- Rotate exposed or compromised credentials promptly.
- Review Key Vault access permissions and relevant audit logs.
- Avoid printing authentication headers or secrets in diagnostic output.

### Security Boundary

Successful Azure Key Vault retrieval confirms that the configured integration functioned during the controlled test.

It does not independently verify:

- That the Logic App identity has only the minimum required permissions.
- That sensitive inputs and outputs are protected across every action.
- That secret rotation has been tested.
- That all relevant Key Vault auditing and alerting controls are enabled.
- That credential retrieval failures are handled securely.

These controls require separate configuration review and validation before production deployment.

### Validation Summary

| Security Consideration | Observed or Documented Status |
|---|---|
| Azure Key Vault integration | Successfully exercised |
| VirusTotal credential retrieval | Successful in final test |
| API credential omitted from final report | Confirmed in validated report |
| Least-privilege access review | Not independently verified |
| Sensitive workflow run-history protection | Not independently verified |
| Credential rotation procedure | Not tested |
| Key Vault failure handling | Not tested |

### Security Assessment

Using Azure Key Vault separates the VirusTotal credential from the published investigation report and provides a dedicated secret-management integration.

However, secure credential storage alone is insufficient.

The overall security posture also depends on identity permissions, workflow data exposure, credential lifecycle management, and error handling.

Further hardening should validate these controls before CERBERUS is used with sensitive production incident data.


## 3. Identity, Permissions & Least Privilege

### Security Objective

CERBERUS integrates multiple Microsoft security services and an external threat intelligence provider.

Each integration introduces an authorization boundary that must be protected against excessive permissions, credential misuse, and unauthorized access to investigation data.

The objective is to ensure that each workflow component receives only the permissions required to perform its intended function.

### Identity & Authorization Boundaries

The CERBERUS architecture includes the following authorization relationships:

| Integration Boundary | Required Capability |
|---|---|
| Microsoft Sentinel → Logic Apps | Authorized playbook execution |
| Logic Apps → Incident context | Access to relevant incident metadata |
| Logic Apps → Defender telemetry | Authorized execution of investigation queries |
| Logic Apps → Azure Key Vault | Retrieval of the required API credential |
| Logic Apps → VirusTotal | Authenticated reputation API requests |
| Analyst → Investigation results | Authorized access to security reports |

The permissions required for these interactions depend on the configured connectors, identities, and Azure resource scopes.

### Microsoft Sentinel & Logic Apps

Microsoft Sentinel automation rules can initiate configured Logic App playbooks when their trigger conditions are satisfied.

The identity and permissions used to invoke a playbook must be configured appropriately for the Sentinel integration.

Recommended safeguards include:

- Restricting who can create or modify automation rules.
- Limiting who can edit or execute security playbooks.
- Reviewing the permissions granted to Sentinel automation identities.
- Restricting Logic App resource access to authorized administrators.
- Auditing changes to workflow definitions and automation rules.
- Separating development and production automation environments.

The successful November 4 execution demonstrated that CERBERUS could process the expected incident context.

It did not independently establish that all associated permissions were restricted to the minimum necessary scope.

### Defender Telemetry Access

CERBERUS uses KQL to investigate endpoint process and network activity.

Access to this telemetry should be restricted because investigation results may contain:

- Device identifiers and hostnames.
- User and account information.
- Process command-line arguments.
- Network destinations and IP addresses.
- Security alerts and incident metadata.

Permissions should be scoped to the required investigation operations wherever supported.

Broad administrative access should not be granted solely to enable routine telemetry queries.

### Azure Key Vault Authorization

The Logic App requires permission to retrieve the VirusTotal API credential from Azure Key Vault.

The recommended authorization model is to grant the workflow identity access only to the required secret and operations, subject to the access-control model supported by the deployment.

Where supported, a managed identity can reduce dependence on manually maintained application credentials.

Additional controls should include:

- Reviewing Azure role assignments and Key Vault permissions.
- Avoiding unnecessary secret management privileges.
- Restricting administrative access to Key Vault configuration.
- Monitoring access and configuration changes.
- Removing permissions that are no longer required.

### External API Authorization

VirusTotal authentication introduces a separate trust boundary outside the Azure environment.

The API credential should be used only for its intended reputation lookup operations.

The workflow should avoid sending unnecessary endpoint metadata or internal investigation details to external services.

The observed enrichment request used the selected remote IP address as its reputation indicator.

### Least-Privilege Validation Status

| Security Control | Validation Status |
|---|---|
| Sentinel playbook execution | Successful workflow execution observed |
| Incident context access | Successfully exercised |
| Defender investigation access | Successfully exercised |
| Key Vault secret retrieval | Successfully exercised |
| Complete Azure RBAC review | Not independently verified |
| Managed identity configuration review | Not independently verified |
| Excessive permission assessment | Not independently verified |
| Production identity separation | Not implemented or validated |

### Security Assessment

CERBERUS successfully demonstrated functional access across its configured investigation and enrichment integrations.

However, successful access does not establish least privilege.

A production deployment would require an explicit identity and authorization review to verify that each integration operates with appropriately scoped permissions.

This review should include Azure RBAC, connector authorization, managed identities where applicable, Key Vault access, and restrictions on workflow administration.


## 4. Data Protection, Telemetry Privacy & External Exposure

### Security Objective

CERBERUS processes endpoint telemetry, incident metadata, network indicators, and investigation results.

Although these data sources are essential for security investigations, they may contain sensitive operational information.

The objective is to minimize unnecessary data exposure while preserving the evidence required for effective investigation and analyst review.

### Sensitive Telemetry Categories

CERBERUS may process the following information during an investigation:

| Data Category | Examples | Security Consideration |
|---|---|---|
| Endpoint identity | Device names and device IDs | Internal asset identification |
| Process telemetry | Executable names and command lines | Potential exposure of arguments or embedded credentials |
| Account information | Usernames and process account context | Identity and privacy considerations |
| Network telemetry | Remote IPs, domains, and ports | Exposure of communication patterns |
| Incident metadata | Incident IDs, alert titles, severity | Internal security operations information |
| Investigation results | Risk scores and reputation statistics | Potentially sensitive security findings |
| Workflow execution data | Action inputs, outputs, and errors | Possible exposure of investigation data or credentials |

The sensitivity of each field depends on the operational environment and the information contained within the event.

### Logic App Execution History

Azure Logic Apps provides execution history that can assist with debugging, validation, and incident investigation.

However, action inputs and outputs may contain sensitive information.

Potential exposure points include:

- Incident trigger payloads.
- KQL query results.
- Endpoint process command lines.
- Network indicators.
- Key Vault retrieval outputs.
- External API request headers.
- Threat intelligence responses.
- Generated investigation reports.

Production hardening should include reviewing which workflow actions require secure inputs and outputs, restricting access to run history, and limiting unnecessary diagnostic data retention.

The current project has not independently validated comprehensive sensitive-data protection across every Logic App action.

### External Threat Intelligence Exposure

CERBERUS uses VirusTotal to retrieve reputation statistics for a selected remote IP address.

The observed final investigation queried:

`104.20.23.154`

Submitting an indicator to an external service introduces a data-sharing boundary.

Before extending CERBERUS to production, organizations should evaluate:

1. Whether the indicator is appropriate for external submission.
2. Whether the indicator contains sensitive internal or private information.
3. Whether organizational policy permits the selected external service.
4. What information the provider may retain or log.
5. Whether API usage complies with applicable service terms and licensing.

The current enrichment design uses the selected remote IP as the lookup indicator rather than transmitting the complete investigation report.

This reduces the scope of the submitted data but does not eliminate all external data-sharing considerations.

### GitHub Repository Security

The Azure Trenches repository documents CERBERUS architecture, investigation logic, validation results, and selected screenshots.

Public documentation must not expose:

- API keys, passwords, or access tokens.
- Azure connection credentials.
- Sensitive authentication headers.
- Private tenant or subscription identifiers where disclosure is unnecessary.
- Real user information or confidential organizational telemetry.
- Secrets accidentally included in screenshots or execution outputs.

Screenshots should be reviewed and redacted before publication.

Sensitive values must also be excluded from commit history, not merely removed from the latest visible version of a file.

The published lab documentation uses controlled simulation evidence, but this does not replace a comprehensive repository secret and data exposure review.

### Data Minimization Recommendations

Recommended safeguards include:

- Retrieve only telemetry fields needed for the investigation.
- Avoid unnecessarily retaining complete raw incident payloads.
- Limit external enrichment to approved indicators.
- Apply appropriate access controls to investigation reports.
- Redact sensitive fields from public screenshots.
- Configure suitable log retention and diagnostic access policies.
- Review workflow outputs for accidental credential disclosure.
- Separate production investigation data from public demonstration artifacts.

### Data Protection Validation Status

| Control | Current Status |
|---|---|
| Controlled benign test telemetry | Demonstrated |
| IP-based VirusTotal enrichment | Demonstrated |
| Structured investigation reporting | Demonstrated |
| Credential excluded from final report | Observed |
| Comprehensive repository secret scanning | Not independently verified |
| Secure inputs and outputs across all actions | Not independently verified |
| Production data retention policy | Not established |
| External data-sharing policy review | Not performed |
| Comprehensive privacy impact assessment | Not performed |

### Security Assessment

CERBERUS demonstrates the ability to process security telemetry and enrich selected network indicators without placing the API credential in the final investigation report.

However, data protection extends beyond credential management.

A production implementation must also account for telemetry sensitivity, workflow execution history, external data sharing, repository hygiene, access controls, and retention requirements.

These safeguards should be validated before the system processes confidential organizational incidents.


## 5. Human Oversight, Automated Response & Safety Boundaries

### Security Objective

CERBERUS automates security investigation activities, including endpoint telemetry retrieval, behavioral analysis, risk scoring, and external threat intelligence enrichment.

However, automated investigation results do not necessarily establish that an endpoint is compromised.

The objective is to preserve human oversight of consequential response decisions while reducing the time required to collect and evaluate relevant evidence.

### Investigation Versus Response

CERBERUS currently focuses on automated investigation and reporting rather than autonomous endpoint containment.

| Capability | Current Implementation |
|---|---|
| Incident context processing | Implemented and validated |
| Endpoint telemetry investigation | Implemented and validated |
| Behavioral risk scoring | Implemented and validated for controlled test |
| Conditional threat intelligence enrichment | Implemented and validated |
| Structured investigation report | Implemented and validated |
| Analyst review recommendation | Included in report |
| Enforced analyst approval workflow | Not implemented |
| Automatic endpoint isolation | Not implemented |
| Automatic account disablement | Not implemented |
| Autonomous remediation | Not implemented |

The workflow provides investigation findings to support analyst decision-making.

It does not independently execute destructive or disruptive response actions.

### Analyst Review Requirement

The validated investigation report included:

```json
{
  "AnalystAssessment": {
    "Disposition": "Pending analyst review",
    "RecommendedAction": "Review collected evidence before containment"
  }
}
```

This output communicates that the investigation requires human evaluation before any containment decision.

Importantly, this is a recommendation recorded in the report.

It is not an enforced approval mechanism or a technical control preventing other systems from taking action.

### False Positive Considerations

The final controlled simulation produced a behavioral risk score of `25`, resulting in a Medium classification.

The simulation was intentionally benign.

This demonstrates that the behavioral scoring system identifies configured activity patterns rather than proving malicious intent.

Potential false-positive scenarios include:

- Legitimate administrative PowerShell automation.
- Authorized scripts using encoded command arguments.
- Routine software deployment activity.
- Approved connections to unfamiliar network destinations.
- Security tooling that generates unusual process or network telemetry.

Behavioral scores should therefore be interpreted alongside incident context, asset criticality, user activity, and additional investigation evidence.

### Threat Intelligence Limitations

VirusTotal enrichment provides reputation statistics for a selected indicator.

The final validation returned:

- Malicious detections: `0`
- Suspicious detections: `0`
- Harmless detections: `55`
- Undetected detections: `37`

These results do not establish that the observed activity was safe.

External reputation information can be incomplete, outdated, or unrelated to the specific behavior being investigated.

Similarly, a malicious reputation result does not independently establish that the endpoint is compromised.

Threat intelligence should supplement behavioral evidence rather than replace analyst judgment.

### Risks of Autonomous Containment

Automatically isolating an endpoint or disabling an account based solely on a behavioral score could introduce operational risks.

Examples include:

1. Interrupting critical business services.
2. Isolating an endpoint during legitimate administrative activity.
3. Disabling an account required for essential operations.
4. Triggering containment based on incomplete or stale telemetry.
5. Acting on an incorrectly correlated process or network event.
6. Escalating a false positive into a business disruption.

These risks become more significant when automation operates with elevated privileges.

### Recommended Approval Architecture

Before implementing automated containment, CERBERUS should introduce an explicit approval stage.

A proposed future workflow would follow:

1. Generate and correlate investigation evidence.
2. Calculate behavioral risk.
3. Enrich relevant indicators.
4. Produce an analyst-readable investigation summary.
5. Request approval from an authorized responder.
6. Validate the approval decision and target identity.
7. Execute only the specifically approved response action.
8. Record the decision, execution outcome, and audit evidence.

Additional safeguards should include approval expiration, authorization checks, duplicate-action prevention, and clear handling of rejected or timed-out requests.

This approval architecture is a future enhancement and has not been implemented or validated in the current lab.

### Safety Validation Summary

| Safety Control | Current Status |
|---|---|
| Benign controlled simulation | Validated |
| Behavioral scoring | Validated for observed scenario |
| Threat intelligence enrichment | Validated for observed scenario |
| Human-review recommendation | Present in final report |
| Enforced approval before containment | Not implemented |
| Automated endpoint isolation | Not implemented |
| Automated account disablement | Not implemented |
| Response authorization validation | Not tested |
| Containment rollback procedure | Not implemented |
| Response audit trail | Not validated |

### Security Assessment

CERBERUS demonstrates automated evidence collection and investigation while leaving consequential response decisions outside the current automation scope.

This reduces the risk of unintended disruption from an unvalidated containment mechanism.

However, the absence of automatic containment does not independently guarantee that the investigation workflow is secure.

Further hardening should address authorization, data protection, workflow reliability, error handling, and explicit human approval before expanding CERBERUS into automated remediation.


## 6. Failure Handling, Operational Reliability & Production Limitations

### Security Objective

Security automation must remain reliable when telemetry is incomplete, external services are unavailable, credentials cannot be retrieved, or workflow actions fail.

A successful investigation under controlled conditions does not guarantee consistent behavior across production incidents.

The objective is to identify CERBERUS operational failure scenarios, document observed reliability evidence, and establish priorities for future hardening.

### Observed HTTP 504 Troubleshooting

During development, CERBERUS encountered HTTP 504 errors while testing Logic App execution.

These errors complicated workflow validation and required investigation of the execution path.

Subsequent testing produced a successful end-to-end Logic App run on November 4, 2026.

| Observation | Recorded Outcome |
|---|---|
| Development issue | HTTP 504 errors encountered |
| Troubleshooting performed | Workflow execution and action behavior investigated |
| Confirmed root cause | Not conclusively established |
| Subsequent validation | Successful Logic App execution |
| Final run duration | 7.92 seconds |
| Final run status | Succeeded |

The successful final execution demonstrates that the observed investigation path completed during the controlled test.

It does not establish that the original timeout condition was permanently resolved or that the workflow will consistently meet production reliability requirements.

### Potential Failure Scenarios

The following conditions should be evaluated before CERBERUS is deployed in a production environment:

| Failure Scenario | Potential Impact |
|---|---|
| Missing Defender device identifier | Investigation cannot reliably identify the target endpoint |
| Empty KQL query results | Insufficient telemetry for behavioral assessment |
| Incorrect process/network correlation | Risk assessment may reference unrelated activity |
| Sentinel incident correlation changes | Automation conditions may fail to match |
| Logic App action timeout | Investigation may terminate or remain incomplete |
| Key Vault access failure | External enrichment credential unavailable |
| VirusTotal API rate limiting | Reputation enrichment delayed or unavailable |
| Malformed external API response | Reputation fields may not be populated correctly |
| Missing remote IP | Enrichment condition cannot be satisfied |
| Duplicate workflow execution | Repeated investigation or unnecessary API requests |
| Connector authorization failure | Required investigation actions may fail |

These represent potential operational risks rather than a list of failures observed during the final validation.

### Sentinel Automation Reliability

CERBERUS testing demonstrated that new Defender XDR alerts may be correlated into existing incidents.

This behavior affects Microsoft Sentinel automation rules configured to trigger only when incidents are created.

The original controlled automation rule expected a newly created incident with a specific title.

The observed alert was instead added to existing incident `2471`, which retained a generic incident title.

A separate incident-update validation rule was configured to address this behavior.

Although the final Logic App execution processed the expected incident context, the available evidence does not independently establish which automation rule initiated that execution.

Future validation should confirm rule execution attribution and test both incident creation and update scenarios.

### KQL Investigation Reliability

CERBERUS uses process-to-network correlation to evaluate endpoint behavior.

The investigation relies on matching endpoint identifiers, process identifiers, and process creation timestamps.

Potential limitations include:

- Delayed or missing endpoint telemetry.
- Process events that cannot be matched to network events.
- Multiple correlated events within the investigation window.
- Incomplete command-line information.
- Differences between endpoint event timestamps.
- Empty query results.
- Unrelated activity appearing in the same incident context.

The current risk assessment selects the highest-ranked correlated result rather than calculating an incident-wide aggregate score.

This design should be considered when interpreting investigations containing multiple devices, processes, or alerts.

### External Dependency Reliability

CERBERUS depends on Azure Key Vault and VirusTotal for the observed enrichment path.

External dependencies introduce additional failure conditions, including authentication errors, permission changes, network interruptions, service availability issues, and API usage limits.

A hardened implementation should:

1. Distinguish enrichment failure from a clean reputation result.
2. Record the reason an enrichment request failed or was skipped.
3. Apply bounded retries with appropriate backoff where supported.
4. Avoid exposing credentials in error messages.
5. Prevent failed API calls from producing misleading reputation statistics.
6. Continue producing a clearly labeled partial investigation report when appropriate.
7. Alert an operator when required investigation components repeatedly fail.

These behaviors are recommended future controls and have not been comprehensively validated in the current implementation.

### Recommended Error Handling Architecture

A future hardened CERBERUS workflow should separate successful investigation processing from failure and recovery paths.

A proposed approach would include:

1. **Investigation scope:** Retrieve incident and endpoint evidence.
2. **Validation scope:** Confirm required identifiers and telemetry are present.
3. **Enrichment scope:** Execute permitted external lookups.
4. **Failure handling scope:** Capture action failures and relevant diagnostics.
5. **Recovery logic:** Retry eligible transient failures within defined limits.
6. **Reporting scope:** Produce a complete or explicitly partial investigation report.
7. **Notification scope:** Inform authorized operators when manual intervention is required.

Failure handling should preserve sufficient evidence for troubleshooting without unnecessarily exposing sensitive data.

### Operational Validation Status

| Reliability Control | Current Status |
|---|---|
| Successful controlled Logic App execution | Validated |
| Incident context processing | Validated |
| Behavioral scoring | Validated for controlled scenario |
| Conditional VirusTotal enrichment | Validated |
| HTTP 504 root-cause identification | Not conclusively established |
| Automated retry and recovery behavior | Not comprehensively tested |
| Empty KQL result handling | Not comprehensively tested |
| Key Vault failure recovery | Not tested |
| VirusTotal failure recovery | Not tested |
| Duplicate execution prevention | Not validated |
| All severity-routing branches | Not independently validated |
| Production monitoring and alerting | Not validated |
| Sustained reliability under load | Not tested |

### Production Readiness Assessment

CERBERUS demonstrates a functional controlled investigation pipeline.

However, production readiness requires more than one successful execution.

Before production deployment, the workflow would require additional testing of failure handling, identity permissions, telemetry edge cases, automation triggers, API dependencies, monitoring, and operational recovery.

The current implementation should therefore be treated as a security engineering lab and portfolio demonstration rather than a production-ready SOAR platform.

### Related Documentation

See [06 — Troubleshooting](06-Troubleshooting.md) for documented development issues and engineering lessons.

See [07 — Validation](07-Validation.md) for the observed end-to-end test results and remaining validation gaps.


## 7. Security Hardening Roadmap & Final Engineering Assessment

### Security Hardening Overview

CERBERUS successfully demonstrated a controlled security investigation workflow integrating Microsoft Defender XDR, Microsoft Sentinel, Azure Logic Apps, KQL, Azure Key Vault, and VirusTotal.

The project also identified security and operational limitations that should be addressed before production deployment.

The following roadmap prioritizes improvements based on their potential impact on security, reliability, and operational safety.

### Phase 1 — Identity & Credential Hardening

**Priority: High**

Recommended activities:

1. Review Azure RBAC assignments associated with the workflow.
2. Verify least-privilege permissions for all connected services.
3. Review managed identity usage and connector authentication.
4. Restrict Key Vault secret access to authorized identities.
5. Protect sensitive Logic App inputs and outputs.
6. Review public repository content for exposed credentials.
7. Establish credential rotation and access review procedures.

**Expected outcome:** Reduced credential exposure and unnecessary authorization privileges.

### Phase 2 — Reliability & Error Handling

**Priority: High**

Recommended activities:

1. Introduce structured failure-handling scopes.
2. Validate required incident and device identifiers.
3. Handle empty KQL results explicitly.
4. Implement appropriate retry and backoff policies.
5. Handle VirusTotal API errors and rate limits.
6. Handle Key Vault authentication and retrieval failures.
7. Distinguish failed enrichment from clean reputation results.
8. Introduce monitoring for failed or incomplete investigations.

**Expected outcome:** More predictable workflow behavior during dependency failures and incomplete investigations.

### Phase 3 — Detection & Risk Model Improvements

**Priority: Medium**

Recommended activities:

1. Expand testing across multiple process and network events.
2. Evaluate incident-level risk aggregation.
3. Introduce additional behavioral indicators.
4. Review scoring weights against known benign and suspicious activity.
5. Evaluate false-positive and false-negative scenarios.
6. Validate process-to-network correlation edge cases.
7. Exercise Low, Medium, High, and Critical routing paths.

**Expected outcome:** Improved investigation coverage and more meaningful behavioral risk assessments.

### Phase 4 — Analyst Approval & Controlled Response

**Priority: High before implementing containment**

Recommended activities:

1. Design an explicit analyst approval workflow.
2. Require authorization before consequential response actions.
3. Validate the endpoint or account targeted for containment.
4. Introduce approval expiration and rejection handling.
5. Record analyst decisions and response execution results.
6. Implement safeguards against duplicate response actions.
7. Establish containment rollback and recovery procedures.
8. Test response actions in an isolated environment before broader deployment.

**Expected outcome:** Controlled response capabilities with stronger human oversight and operational safeguards.

### Phase 5 — Production Monitoring & Governance

**Priority: High before production deployment**

Recommended activities:

1. Define operational monitoring and alerting requirements.
2. Establish appropriate diagnostic logging and retention policies.
3. Review external threat intelligence data-sharing requirements.
4. Establish workflow change control and version management.
5. Define ownership for incident investigation and automation maintenance.
6. Conduct security and privacy reviews.
7. Test operational recovery and dependency failures.
8. Establish measurable reliability and performance objectives.

**Expected outcome:** Improved accountability, maintainability, and operational readiness.

### Hardening Priority Matrix

| Security Area | Current State | Priority |
|---|---|---|
| Credential retrieval | Key Vault integration validated | High — review access and output protection |
| Identity permissions | Functional access demonstrated | High — verify least privilege |
| Sensitive telemetry handling | Controlled lab data processed | High — validate protection controls |
| Error handling | Limited failure-path validation | High |
| Incident automation | Successful incident processing observed | High — verify rule attribution |
| Behavioral scoring | Controlled scenario validated | Medium |
| Severity routing | Configured; branches not fully validated | Medium |
| Human approval | Recommendation only | High before containment |
| Automated containment | Not implemented | Future enhancement |
| Production monitoring | Not comprehensively validated | High |

### Final Engineering Assessment

CERBERUS demonstrates practical security engineering across detection, investigation, orchestration, behavioral analysis, and threat intelligence enrichment.

The successful November 4, 2026 validation established that the workflow could process controlled endpoint activity and generate an enriched investigation report.

The final observed investigation included:

- Defender XDR alert correlation with incident `2471`.
- Successful Logic App execution in `7.92 seconds`.
- Correlated endpoint process and network telemetry.
- Behavioral risk score of `25`, classified as Medium.
- Conditional VirusTotal enrichment for `104.20.23.154`.
- Structured reporting with a pending analyst-review disposition.

These results support the project's demonstrated functionality within the controlled lab.

They do not establish production readiness, comprehensive threat detection, autonomous response safety, or reliability across all operational scenarios.

### Final Security Conclusion

CERBERUS was developed as a hands-on security engineering and SOAR automation project.

Its value lies in demonstrating the design, implementation, investigation, troubleshooting, and validation of a multi-service security workflow.

Equally important, the project documents where its capabilities end.

Future improvements should prioritize least privilege, sensitive-data protection, reliable error handling, stronger validation coverage, and explicit analyst authorization before implementing consequential response actions.

The current implementation should be considered a controlled lab demonstration and a foundation for further security engineering development.

### Related Documentation

- [01 — Architecture](01-Architecture.md)
- [02 — Detection Engineering](02-Detection-Engineering.md)
- [03 — SOAR Automation](03-SOAR-Automation.md)
- [04 — Risk Scoring](04-Risk-Scoring.md)
- [05 — Threat Intelligence](05-Threat-Intelligence.md)
- [06 — Troubleshooting](06-Troubleshooting.md)
- [07 — Validation](07-Validation.md)

Return to the [CERBERUS Project README](../README.md).

