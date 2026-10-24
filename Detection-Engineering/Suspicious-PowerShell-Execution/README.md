# Suspicious PowerShell Execution

## Objective
Investigate PowerShell processes spawned by Windows scripting engines using Microsoft Defender XDR and Microsoft Sentinel.

## Hypothesis
PowerShell execution initiated by `wscript.exe` or `cscript.exe` may indicate suspicious script-based activity requiring further investigation.

## Lab Environment
- Windows 11 virtual machine
- Microsoft Defender for Endpoint
- Microsoft Defender XDR Advanced Hunting
- Microsoft Sentinel

## Investigation Status
**In Progress**

## Investigation Plan
1. Identify PowerShell execution events.
2. Analyze parent-child process relationships.
3. Examine command-line arguments.
4. Correlate related Defender alerts and network activity.
5. Evaluate findings and potential false positives.

## Findings
Pending investigation and validation.

## Lessons Learned
To be completed after the investigation.
