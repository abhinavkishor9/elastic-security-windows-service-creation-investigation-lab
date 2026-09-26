# Elastic Security Lab 07 — Suspicious Service Creation

## Overview

This lab investigates **Windows Service creation** as a potential persistence mechanism using Elastic Security and Elastic Defend.

Windows Services are commonly used by legitimate software and operating system components. Therefore, the creation of a new service is not automatically malicious. A SOC analyst should investigate the service name, display name, binary path, start type, service account, creating process, and related telemetry before making an assessment.

A controlled service named `ElasticLab07` was created using `sc.exe`. The service was configured to run:

```text
C:\Windows\System32\cmd.exe /c exit
```

with a demand-start configuration.

The service was then validated locally, investigated through Elastic process telemetry, examined through its Windows Registry configuration, and finally removed.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 10 Pro 22H2 |
| Host | `DESKTOP-9MMM37V` |
| User | `Dell` |
| Elastic Platform | Elastic Security Serverless |
| Endpoint Integration | Elastic Defend |
| Elastic Agent | `9.5.4` |
| Agent Policy | `Windows-SOC-Lab` |
| Investigation Interface | Discover / ES|QL |
| Shell | PowerShell 7.6.6 |
| Time Range | Last 15 minutes initially, expanded to Last 1 hour during investigation |

## Objectives

- Understand Windows Service creation as a persistence technique.
- Establish a service baseline before creating the controlled service.
- Create and inspect a temporary Windows Service.
- Analyze service configuration and execution context.
- Identify `sc.exe` process telemetry in Elastic.
- Investigate the service name through command-line hunting.
- Examine the Registry location used to store service configuration.
- Understand the difference between service configuration and observed process execution.
- Document telemetry limitations and incomplete event fields.
- Remove the controlled service and verify remediation.

## Scenario

A SOC analyst is investigating a Windows endpoint for a newly created service that could potentially provide persistence.

A controlled service named `ElasticLab07` is created with:

```text
Display Name:
Elastic Lab 07 Test Service
```

and:

```text
Binary Path:
C:\Windows\System32\cmd.exe /c exit
```

The service is configured for:

```text
Demand Start / Manual
```

and:

```text
Service Account:
LocalSystem
```

The analyst investigates both the local Windows configuration and Elastic endpoint telemetry to determine what evidence is available.

## Baseline

Before creating the test service, the analyst checked:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

No existing `ElasticLab07` service was found.

A sample of existing Windows services was also reviewed to provide environmental context.

## Service Creation

The following command created the controlled service:

```powershell
sc.exe create ElasticLab07 binPath= "C:\Windows\System32\cmd.exe /c exit" start= demand DisplayName= "Elastic Lab 07 Test Service"
```

Windows returned:

```text
[SC] CreateService SUCCESS
```

## Service Configuration

The service was inspected with:

```powershell
sc.exe qc ElasticLab07
```

Observed configuration:

```text
SERVICE_NAME: ElasticLab07
TYPE: 10 WIN32_OWN_PROCESS
START_TYPE: 3 DEMAND_START
ERROR_CONTROL: 1 NORMAL
BINARY_PATH_NAME: C:\Windows\System32\cmd.exe /c exit
DISPLAY_NAME: Elastic Lab 07 Test Service
SERVICE_START_NAME: LocalSystem
```

The service was also checked with:

```powershell
Get-Service -Name "ElasticLab07" | Select-Object Name, DisplayName, Status, StartType
```

Observed:

```text
Name         : ElasticLab07
DisplayName  : Elastic Lab 07 Test Service
Status       : Stopped
StartType    : Manual
```

## Service State

The detailed service query showed:

```text
Status: Ready
Run As User: Dell
Task To Run: N/A
```

For the Windows Service configuration itself, `sc.exe qc` reported:

```text
SERVICE_START_NAME: LocalSystem
```

The investigation therefore records the service configuration exactly as reported by Windows rather than assuming the interactive user context represents the service account.

## Elastic Process Telemetry

The following ES|QL query was used to locate activity associated with the service name:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Elastic returned process events for `sc.exe`.

### Service Creation Event

Observed:

```text
Sep 26, 2026 @ 05:54:16.453
```

Process:

```text
sc.exe
```

PID:

```text
29604
```

Parent:

```text
pwsh.exe
```

Parent PID:

```text
33488
```

The command line contained:

```text
sc.exe create ElasticLab07
```

The executable path was:

```text
C:\Windows\System32\sc.exe
```

## Service Query Activity

Additional `sc.exe` activity was captured.

Observed:

```text
Sep 26, 2026 @ 05:55:46.557
```

Process:

```text
sc.exe
```

PID:

```text
33872
```

Parent:

```text
pwsh.exe
```

Parent PID:

```text
33488
```

The command line contained:

```text
sc.exe qc ElasticLab07
```

This demonstrates that Elastic captured service-management activity performed from PowerShell.

## Binary Path Investigation

A focused search for the service binary path was performed:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*cmd.exe /c exit*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

Elastic returned one result associated with:

```text
sc.exe
```

The command line referenced the service creation operation.

This provided process-level evidence that the service was configured using the intended binary path.

## Registry Investigation

The service configuration was also examined locally at:

```text
HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07
```

The following command was used:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07"
```

Observed:

```text
Type: 16
Start: 3
ErrorControl: 1
ImagePath: C:\Windows\System32\cmd.exe /c exit
DisplayName: Elastic Lab 07 Test Service
ObjectName: LocalSystem
```

The Registry key itself was also verified.

## Elastic Registry Hunt

A Registry query was attempted:

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentControlSet*Services*"
| WHERE registry.value LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

Result:

```text
0 documents processed
```

No Registry telemetry matching those conditions was returned.

The local Registry evidence therefore remains authoritative for the configuration that was actually present on the endpoint, while the absence of Elastic Registry results is documented as a telemetry limitation.

## Service Execution

The service was configured as:

```text
DEMAND_START
```

and:

```text
STOPPED
```

The controlled service was not used to execute a malicious payload.

The investigation therefore focused primarily on:

```text
Service Creation
Service Configuration
Service Account
Binary Path
Elastic sc.exe Telemetry
```

rather than attempting unnecessary service execution.

## Key Findings

### Observed

- `ElasticLab07` was created successfully.
- The service was configured as `DEMAND_START`.
- The service status was `STOPPED`.
- The binary path was `C:\Windows\System32\cmd.exe /c exit`.
- The service display name was `Elastic Lab 07 Test Service`.
- The configured service account was `LocalSystem`.
- Elastic captured the `sc.exe create` activity.
- Elastic captured subsequent `sc.exe query` and `sc.exe qc` activity.
- The `ElasticLab07` Registry hunt returned no results in Elastic.
- Local Registry inspection confirmed the service configuration.
- The service was successfully deleted.

### Confirmed

- The controlled Windows Service existed.
- The service configuration was validated locally.
- The service creation command was captured by Elastic.
- The service management process was `sc.exe`.
- The service configuration referenced the intended executable path.
- The service was removed during remediation.

### Not Demonstrated

- Malicious service execution
- Malware execution
- Credential theft
- Privilege escalation
- Command-and-control
- Defense evasion
- Confirmed endpoint compromise

## Telemetry Limitations

The investigation identified several telemetry limitations:

- The Registry-specific Elastic query returned zero documents.
- Some `sc.exe` events contained incomplete PID, parent-process, or command-line fields.
- The service configuration was therefore validated primarily through local Windows commands.
- Service configuration evidence does not automatically prove that the configured binary executed.
- The process that created the service should not automatically be treated as the eventual service process.

## Investigation Principle

Service investigations should follow:

```text
Service Creation
      |
      v
Service Name
      |
      v
Binary Path
      |
      v
Start Type
      |
      v
Service Account
      |
      v
Creation Process
      |
      v
Execution Evidence
      |
      v
Related Activity
      |
      v
Assessment
```

A newly created service is an investigation starting point rather than an automatic malicious finding.

## MITRE ATT&CK

### T1543.003 — Create or Modify System Process: Windows Service

The controlled activity demonstrates Windows Service creation and configuration.

The ATT&CK mapping describes the mechanism demonstrated by the lab and does not indicate that the controlled service itself was malicious.

## Remediation

The controlled service was removed using:

```powershell
sc.exe delete ElasticLab07
```

Windows returned:

```text
[SC] DeleteService SUCCESS
```

Post-deletion verification was performed with:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

and:

```powershell
sc.exe query ElasticLab07
```

The service query returned:

```text
The specified service does not exist as an installed service.
```

The Registry was also checked:

```powershell
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07"
```

Result:

```text
False
```

## Final Assessment

The investigation successfully demonstrated controlled Windows Service creation and configuration.

Elastic captured the `sc.exe` service-management activity and provided useful process context for the creation and configuration commands. Local Windows and Registry inspection confirmed the service's binary path, startup configuration, and service account.

Elastic did not return matching Registry telemetry for the service, and no standalone service-binary execution event was established. These limitations were documented rather than inferred.

No malicious behavior or endpoint compromise was demonstrated.
