# Investigation Notes 

## Baseline

Before creation, the following check was performed:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

No matching service was present.

A sample of existing services was also reviewed to establish the normal service environment on the endpoint.

## Service Creation

The service was created with:

```powershell
sc.exe create ElasticLab07 binPath= "C:\Windows\System32\cmd.exe /c exit" start= demand DisplayName= "Elastic Lab 07 Test Service"
```

Result:

```text
[SC] CreateService SUCCESS
```

## Local Service Validation

The service was checked with:

```powershell
Get-Service -Name "ElasticLab07"
```

Observed:

```text
Status: Stopped
Name: ElasticLab07
DisplayName: Elastic Lab 07 Test Service
```

A more detailed query showed:

```text
Name: ElasticLab07
DisplayName: Elastic Lab 07 Test Service
Status: Stopped
StartType: Manual
```

## Service Configuration

The following command was used:

```powershell
sc.exe qc ElasticLab07
```

Observed:

```text
SERVICE_NAME: ElasticLab07
TYPE: 10 WIN32_OWN_PROCESS
START_TYPE: 3 DEMAND_START
ERROR_CONTROL: 1 NORMAL
BINARY_PATH_NAME: C:\Windows\System32\cmd.exe /c exit
DISPLAY_NAME: Elastic Lab 07 Test Service
SERVICE_START_NAME: LocalSystem
```

The key configuration elements were:

```text
Service Name: ElasticLab07
Display Name: Elastic Lab 07 Test Service
Start Type: Demand Start
Binary Path: C:\Windows\System32\cmd.exe /c exit
Service Account: LocalSystem
```

## Registry Validation

Windows Service configuration was inspected under:

```text
HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07
```

PowerShell returned:

```text
Type: 16
Start: 3
ErrorControl: 1
ImagePath: C:\Windows\System32\cmd.exe /c exit
DisplayName: Elastic Lab 07 Test Service
ObjectName: LocalSystem
```

This independently confirmed the important service configuration.

## Elastic Service-Name Hunt

The following query was used:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

Elastic returned four documents during the broader investigation.

The most relevant complete process records included service creation and configuration commands.

## Service Creation Telemetry

Observed:

```text
Timestamp: Sep 26, 2026 @ 05:54:16.453
Process: sc.exe
PID: 29604
Parent: pwsh.exe
Parent PID: 33488
User: Dell
Executable: C:\Windows\System32\sc.exe
```

The command line contained the controlled creation command:

```text
sc.exe create ElasticLab07
```

This provided direct process telemetry for the service creation operation.

## Service Configuration Telemetry

Observed:

```text
Timestamp: Sep 26, 2026 @ 05:55:46.557
Process: sc.exe
PID: 33872
Parent: pwsh.exe
Parent PID: 33488
User: Dell
Executable: C:\Windows\System32\sc.exe
```

The command line contained:

```text
sc.exe qc ElasticLab07
```

This represented service configuration inspection rather than creation of another service.

## Binary Path Search

The following query was used:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*cmd.exe /c exit*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

One result was returned.

The result was associated with:

```text
sc.exe
```

and referenced the controlled service creation operation.

## Registry Telemetry Hunt

The following query was attempted:

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

No matching Registry telemetry was returned.

This did not contradict the local Registry evidence.

Instead, it established that the queried Elastic Registry dataset did not expose the controlled service configuration through those conditions.

## Service Execution Assessment

The service was configured with:

```text
Start Type: Demand Start
Status: Stopped
```

The service binary path was:

```text
C:\Windows\System32\cmd.exe /c exit
```

No malicious payload was introduced.

The investigation therefore did not require forcing the service to run.

The available evidence supports service creation and configuration, but it does not establish a separate service-binary execution event.

## Process Context

The controlled `sc.exe` commands were launched from:

```text
pwsh.exe
```

with:

```text
Parent PID: 33488
```

This describes the process responsible for performing the service-management operation.

It should not be treated as the parent process of a future service instance unless separate execution telemetry establishes that relationship.

## Metadata Limitations

Some returned `sc.exe` records contained incomplete fields, including:

```text
PID: null
Parent: null
Command Line: null
```

while still showing:

```text
C:\Windows\System32\sc.exe
```

These events were treated as incomplete telemetry rather than assigned additional meaning.

