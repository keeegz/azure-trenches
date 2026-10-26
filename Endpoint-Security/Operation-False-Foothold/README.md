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
