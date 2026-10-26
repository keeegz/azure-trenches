# Operation False Foothold
### Lab 6 — Multi-Stage Attack Emulation & Detection Engineering

> **Authorized Security Simulation**
>
> This lab documents controlled endpoint activity performed
> in an isolated Windows 11 Azure VM. No actual malware,
> credential theft, or unauthorized access was involved.

## Overview

Operation False Foothold is a multi-stage endpoint security lab
designed to simulate suspicious workstation behavior and investigate
the resulting telemetry using Microsoft Defender XDR.

The exercise covers PowerShell execution, system discovery,
scheduled-task execution, outbound HTTPS communication,
custom detection engineering, and incident response.

A custom Microsoft Defender XDR detection successfully generated
a Low-severity alert and **Incident #782**, which was investigated
and resolved as expected security-testing activity.

## Lab Environment

| Component | Technology |
|---|---|
| Endpoint | Windows 11 Azure VM |
| Endpoint Security | Microsoft Defender for Endpoint |
| Investigation Platform | Microsoft Defender XDR |
| SIEM | Microsoft Sentinel (workspace available) |
| Query Language | Kusto Query Language (KQL) |
| Framework | MITRE ATT&CK |
| Lab Date | October 26, 2026 |

---

## Stage 1 — Endpoint Validation

### Objective

Verify that the Windows 11 Azure VM was successfully onboarded
to Microsoft Defender for Endpoint and generating endpoint telemetry
before beginning the attack simulation.

### Validation Procedure

1. Navigated to Microsoft Defender XDR.
2. Opened **Assets → Devices**.
3. Located the Windows 11 endpoint `nyc-cl11`.
4. Confirmed that the Defender sensor was reporting as **Active**.
5. Executed `whoami` and `hostname` from PowerShell to generate
   benign process activity.

### KQL — Process Telemetry Validation
```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "nyc-cl11"
| where FileName in~ ("whoami.exe", "hostname.exe")
| project
    Timestamp,
    DeviceName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    AccountName
| order by Timestamp desc
```
### Results

Microsoft Defender successfully recorded process execution
telemetry from `nyc-cl11`.

- **Sensor health:** Active
- **Process events:** 225 events observed during the initial
  24-hour validation window
- **Validated processes:** `whoami.exe` and `hostname.exe`
- **Parent process:** `powershell.exe`

These findings confirmed that the endpoint was producing the
telemetry required for subsequent hunting and detection exercises.

**MITRE ATT&CK:** Not applicable to onboarding validation.
The commands were used to verify telemetry collection, not
to establish malicious discovery activity.

### Evidence

*Screenshot pending — Defender device onboarding and
Advanced Hunting process telemetry.*

---

## Stage 2 — Initial PowerShell Execution

### Objective

Simulate the execution of a PowerShell script on the Windows 11 endpoint and determine whether Microsoft Defender for Endpoint captures the associated process activity.

This stage establishes a baseline for investigating script execution and parent-child process relationships.

### Execution Procedure

A benign PowerShell script named `Stage1.ps1` was created in the following directory:

`C:\AzureTrenches\Lab6\Stage1.ps1`

The script contained:

```powershell
Write-Output "OPERATION FALSE FOOTHOLD - STAGE 1"
Write-Output "Simulated initial execution"
Write-Output "Timestamp: $(Get-Date -Format o)"
Write-Output "Computer: $env:COMPUTERNAME"
```

The script was executed using:

```powershell
powershell.exe -NoProfile -File "C:\AzureTrenches\Lab6\Stage1.ps1"
```

The command completed successfully and displayed the expected lab identifier, timestamp, and computer name.

### KQL — PowerShell Execution Investigation

Microsoft Defender XDR Advanced Hunting was used to identify the process execution:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "nyc-cl11"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "Stage1.ps1"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

### Results

Microsoft Defender successfully recorded the PowerShell process execution.

| Field | Observed Value |
|---|---|
| Device | `nyc-cl11` |
| Process | `powershell.exe` |
| Parent process | `powershell.exe` |
| Account | `azureuser` |
| Executed script | `Stage1.ps1` |
| Execution date | October 26, 2026 |

The telemetry demonstrated that Defender could identify the executed PowerShell process, its command-line arguments, and its initiating process.

The initial hunting attempt did not immediately return the event. A subsequent query identified the execution, illustrating that endpoint telemetry may not always be available for hunting immediately after an action occurs.

### MITRE ATT&CK Mapping

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The simulated activity used PowerShell to execute a local script.

This technique mapping describes the observed execution mechanism; it does not imply that the benign script was malicious.

### Evidence

*Screenshot pending — PowerShell script execution and Defender XDR Advanced Hunting results.*
