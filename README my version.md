# elastic-security-windows-service-creation-investigation-lab
## Overview
Windows Services are designed to run background applications and system components. Legitimate software frequently creates services, so the existence of a newly created service is not automatically malicious.

From a SOC perspective, investigate the full service-creation chain:

Service Creation
      ↓
Service Name
      ↓
Display Name
      ↓
Binary Path
      ↓
Start Type
      ↓
Service Account
      ↓
Service Start Activity
      ↓
Process Execution
      ↓
Assessment

A suspicious service may deserve additional investigation when it has characteristics such as:

An unexpected service name
A binary path in a user-writable directory
A script or command interpreter as the service binary
An unusual service account
Creation by an unexpected parent process
A recently created service with no legitimate software context


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

## Lab Objectives

The objectives of this lab are to:

- Establish whether the test service `ElasticLab07` already exists before performing the controlled activity.
- Create a Windows Service with a known service name, display name, binary path, startup mode, and service account.
- Inspect the service through Windows Service Manager and `sc.exe` to understand its configuration.
- Examine how `sc.exe` appears in Elastic process telemetry during service creation and configuration queries.
- Identify the parent process, process ID, user context, command line, and executable path associated with service-management activity.
- Validate the service configuration through the corresponding Windows Registry location.
- Compare locally confirmed service and Registry information with what is actually available in Elastic telemetry.
- Investigate why a Registry-focused Elastic query may return no results even when the service configuration exists locally.
- Distinguish service creation and configuration evidence from evidence of the service binary actually executing.
- Analyze incomplete process records without filling missing fields through assumption or inference.
- Understand the difference between the interactive user performing a service-management action and the account configured for the service itself.
- Examine how service startup type affects the persistence context of the controlled service.
- Practice correlating process telemetry, service configuration, Registry artifacts, and timestamps during a persistence investigation.
- Document telemetry gaps and explain how they affect the confidence of the investigation.
- Remove the controlled service and verify that both the service and its associated Registry configuration have been deleted.
- Map the observed behavior to the appropriate Windows Service persistence technique using evidence collected during the investigation.
  

## Lab Scenario

A SOC analyst is investigating a Windows endpoint for a newly created service that may represent a persistence mechanism. The analyst needs to determine how the service was created, what executable it is configured to use, which account it will run under, and what evidence is available in endpoint telemetry.

A controlled service named `ElasticLab07` is created using `sc.exe` with the following configuration:

```text
Service Name: ElasticLab07
Display Name: Elastic Lab 07 Test Service
Binary Path: C:\Windows\System32\cmd.exe /c exit
Start Type: Demand Start
Service Account: LocalSystem
```

The service is then examined through Windows service-management commands and its corresponding Registry location under `CurrentControlSet\Services`.

The investigation uses Elastic to trace the `sc.exe` activity associated with the service and examines:

- Service creation and configuration commands
- Parent process and process ID information
- User context and executable path
- Service binary path and startup configuration
- Local Registry configuration
- Availability of corresponding Registry telemetry in Elastic
- Differences between service configuration evidence and actual process-execution evidence

Elastic captures the relevant `sc.exe` creation and query activity, while the Registry-focused search does not return a matching event. This creates an important investigation point: locally confirmed configuration should not be represented as Elastic evidence when the telemetry does not support it.

The controlled service is removed after the investigation, and both the Windows service state and associated Registry path are checked to confirm that the test artifact has been successfully deleted.

The scenario is designed to demonstrate how a SOC analyst investigates **service creation as a potential persistence mechanism** while maintaining a clear distinction between confirmed configuration, endpoint telemetry, execution evidence, and telemetry limitations.


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


## MITRE ATT&CK

### T1543.003 — Create or Modify System Process: Windows Service

The controlled activity demonstrates Windows Service creation and configuration.

The ATT&CK mapping describes the mechanism demonstrated by the lab and does not indicate that the controlled service itself was malicious.

