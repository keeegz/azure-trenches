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

---

## Stage 3 — System Discovery

### Objective

Simulate local host, user, and network discovery on the Windows 11 endpoint and investigate whether Microsoft Defender XDR records the executed commands and their parent-child process relationships.

These commands are legitimate Windows administration utilities but can also be used by adversaries during post-compromise reconnaissance.

### Execution Procedure

The following commands were executed from PowerShell on `nyc-cl11`:

```powershell
whoami /all
systeminfo
ipconfig /all
net user
```

Each command gathered a different category of information:

| Command | Purpose |
|---|---|
| `whoami /all` | Enumerate the current user's identity, groups, and privileges |
| `systeminfo` | Retrieve operating system and host configuration details |
| `ipconfig /all` | Enumerate local network adapter and IP configuration |
| `net user` | Enumerate local user accounts |

### KQL — Discovery Activity Investigation

Microsoft Defender XDR Advanced Hunting was used to identify the discovery commands:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName =~ "nyc-cl11"
| where FileName in~ (
    "whoami.exe",
    "systeminfo.exe",
    "ipconfig.exe",
    "net.exe",
    "net1.exe"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    ProcessId,
    InitiatingProcessId
| order by Timestamp asc
```

### Results

Microsoft Defender successfully captured the discovery activity in `DeviceProcessEvents`.

| Observed process | Parent process | Finding |
|---|---|---|
| `whoami.exe` | `powershell.exe` | User and privilege enumeration |
| `systeminfo.exe` | `powershell.exe` | Host configuration discovery |
| `ipconfig.exe` | `powershell.exe` | Network configuration discovery |
| `net.exe` | `powershell.exe` | Local account enumeration |
| `net1.exe` | `net.exe` | Additional child process associated with `net user` |

The discovery commands were executed within a short period, allowing the analyst to correlate the activity as a related sequence.

Of particular interest, Defender captured `net1.exe` as a child of `net.exe`. This illustrates why parent-child process relationships can provide valuable investigative context beyond individual command-line events.

### MITRE ATT&CK Mapping

| Technique | ID | Simulated behavior |
|---|---|---|
| System Owner/User Discovery | T1033 | `whoami /all` |
| System Information Discovery | T1082 | `systeminfo` |
| System Network Configuration Discovery | T1016 | `ipconfig /all` |
| Account Discovery: Local Account | T1087.001 | `net user` |

These mappings describe the observed discovery techniques, not confirmed malicious activity.

### Analyst Findings

The presence of discovery commands alone is insufficient to establish compromise.

An analyst should evaluate:

- The account executing the commands.
- The parent process and execution context.
- The frequency and sequence of discovery activity.
- Whether the commands correlate with other suspicious events.
- Whether the activity was authorized.

In this lab, the commands were explicitly executed as part of a controlled security simulation.

### Evidence

*Screenshot pending — Defender XDR Advanced Hunting results showing discovery commands and the `net.exe` → `net1.exe` process relationship.*
