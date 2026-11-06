
# CERBERUS — KQL Detection & Investigation Queries

## Overview

This directory contains Kusto Query Language (KQL) queries developed and documented for the CERBERUS security orchestration, automation, and response (SOAR) lab.

The queries demonstrate endpoint detection, process investigation, network investigation, and behavioral risk scoring using Microsoft Defender XDR Advanced Hunting telemetry.

CERBERUS integrates Microsoft Defender XDR, Microsoft Sentinel, Azure Logic Apps, Azure Key Vault, and VirusTotal to support automated security investigation.

## Query Catalog

| Query | Purpose | Validation Status |
|---|---|---|
| [01 — Encoded PowerShell Network Detection](01-Encoded-PowerShell-Network-Detection.kql) | Detect encoded PowerShell activity with a successful connection to the controlled test destination | Validated in lab |
| [02 — Endpoint Process Investigation](02-Endpoint-Process-Investigation.kql) | Investigate PowerShell execution, command lines, accounts, and parent processes | Standalone adaptation; not independently tested |
| [03 — Endpoint Network Investigation](03-Endpoint-Network-Investigation.kql) | Examine PowerShell network connections and behavioral indicators | Standalone adaptation; not independently tested |
| [04 — Process/Network Correlation & Risk Scoring](04-Process-Network-Correlation-Risk-Scoring.kql) | Correlate endpoint telemetry and calculate behavioral risk | Scoring logic validated in CERBERUS; standalone adaptation not independently tested |

## Execution Environment

These queries target Microsoft Defender XDR Advanced Hunting.

Primary telemetry tables:

- `DeviceProcessEvents`
- `DeviceNetworkEvents`

Requirements:

1. Access to Microsoft Defender XDR Advanced Hunting.
2. Defender-onboarded endpoints generating relevant telemetry.
3. Appropriate permissions to query endpoint data.
4. A suitable investigation time window.

The standalone investigation queries use:

```kql
let TargetDevice = "nyc-cl11";
let Lookback = 7d;
```

Update these parameters for the authorized investigation environment.

Query 01 uses a fixed one-hour detection window and the benign test destination `example.com`.

## Behavioral Risk Scoring

Query 04 implements the CERBERUS deterministic behavioral scoring model.

| Indicator | Score Adjustment |
|---|---:|
| Encoded PowerShell execution | +25 |
| Download-and-execute command pattern | +25 |
| Unusual destination port | +20 |
| Recognized routine Defender activity | -40 |

Risk classifications:

| Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–69 | High |
| 70–100 | Critical |

The scoring model evaluates individual correlated events.

The CERBERUS workflow selects the highest-ranked result rather than calculating an incident-wide aggregate score.

These values are lab-defined behavioral weights, not calibrated probabilities of malicious activity.

## Validation Evidence

The November 4, 2026 controlled test generated an encoded PowerShell detection and produced a successful CERBERUS investigation.

Observed results included:

- Defender XDR alert associated with incident `2471`.
- Successful Logic App execution in `7.92 seconds`.
- Behavioral risk score of `25` (Medium).
- VirusTotal enrichment of `104.20.23.154`.
- Structured investigation report recommending analyst review.

The final detection was validated during controlled testing.

Queries 02–04 are standalone analyst-hunting adaptations. Their exact standalone versions have not been independently executed and validated.

## Security & Operational Considerations

- Use these queries only in authorized environments.
- Review process command lines for sensitive information.
- Restrict access to endpoint telemetry.
- Validate query results before making response decisions.
- Do not treat behavioral scores as proof of compromise.
- Do not assume that a zero-detection reputation result establishes safety.
- Review query performance and telemetry coverage before production use.

## Related Documentation

- [Detection Engineering](../docs/02-Detection-Engineering.md)
- [SOAR Automation](../docs/03-SOAR-Automation.md)
- [Behavioral Risk Scoring](../docs/04-Risk-Scoring.md)
- [Validation Results](../docs/07-Validation.md)
- [Security & Limitations](../docs/08-Security-and-Limitations.md)

Return to the [CERBERUS Project README](../README.md).

