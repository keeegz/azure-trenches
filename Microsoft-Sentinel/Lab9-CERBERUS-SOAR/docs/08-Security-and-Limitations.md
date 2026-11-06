
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
