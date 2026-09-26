# Timeline — Suspicious Service Creation

## Investigation Timeline

| Time | Activity | Process / Artifact | Evidence / Notes |
|---|---|---|---|
| Initial validation | Checked whether test service already existed | `ElasticLab07` | No matching service found before creation |
| 05:54:16.453 | Controlled service creation | `sc.exe` PID `29604` | Parent `pwsh.exe`, parent PID `33488`, service name `ElasticLab07` |
| 05:54 | Service created successfully | `ElasticLab07` | Windows returned `CreateService SUCCESS` |
| 05:55:46.557 | Service configuration query | `sc.exe` PID `33872` | Parent `pwsh.exe`, parent PID `33488`, `/qc ElasticLab07` |
| Investigation | Service configuration inspected | `ElasticLab07` | Demand Start, Stopped, binary `cmd.exe /c exit`, account `LocalSystem` |
| Investigation | Service Registry inspected | `HKLM\...\Services\ElasticLab07` | `ImagePath`, `Start`, `DisplayName`, and `ObjectName` confirmed locally |
| Investigation | Elastic Registry hunt performed | Registry telemetry | No matching Elastic documents returned |
| Investigation | Binary-path hunt performed | `sc.exe` | One matching event returned for `cmd.exe /c exit` |
| Remediation | Service deleted | `ElasticLab07` | `sc.exe delete` returned `DeleteService SUCCESS` |
| Post-remediation | Service query performed | `ElasticLab07` | Service no longer existed |
| Post-remediation | Registry verification performed | `ElasticLab07` | `Test-Path` returned `False` |

## Initial Baseline

The first validation checked:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

No matching service was found.

This established that the test service was not already installed before the controlled activity.

## 05:54:16.453 — Service Creation

Elastic recorded the controlled `sc.exe` execution.

Observed:

```text
Process: sc.exe
PID: 29604
Parent: pwsh.exe
Parent PID: 33488
User: Dell
Executable: C:\Windows\System32\sc.exe
```

The command line contained the creation of:

```text
ElasticLab07
```

The service was configured with:

```text
C:\Windows\System32\cmd.exe /c exit
```

and:

```text
start= demand
```

## Service Configuration Validation

Local Windows configuration showed:

```text
SERVICE_NAME: ElasticLab07
START_TYPE: 3 DEMAND_START
BINARY_PATH_NAME: C:\Windows\System32\cmd.exe /c exit
DISPLAY_NAME: Elastic Lab 07 Test Service
SERVICE_START_NAME: LocalSystem
```

PowerShell also showed:

```text
Status: Stopped
StartType: Manual
```

## Registry Configuration

The service Registry key was inspected at:

```text
HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07
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

This provided direct local evidence of the service configuration.

## 05:55:46.557 — Service Configuration Query

Elastic recorded a subsequent `sc.exe` query:

```text
Process: sc.exe
PID: 33872
Parent: pwsh.exe
Parent PID: 33488
User: Dell
```

The command line contained:

```text
sc.exe qc ElasticLab07
```

This was a configuration inspection event rather than a second service creation.

## Elastic Registry Hunt

A Registry query for:

```text
CurrentControlSet\Services
```

and:

```text
ElasticLab07
```

returned:

```text
0 documents processed
```

The timeline therefore records the service Registry artifact as **locally confirmed but not independently observed through the tested Elastic Registry query**.

## Binary Path Investigation

The following Elastic search was performed:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*cmd.exe /c exit*"
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, process.command_line, process.executable
| SORT @timestamp DESC
```

One event was returned and associated with:

```text
sc.exe
```

This provided process-level evidence for the service configuration command.

## Service Execution

The service remained:

```text
STOPPED
```

and:

```text
DEMAND_START
```

The investigation did not establish an independent process event for the configured service binary.

Therefore, the timeline does not claim a separately observed service-process execution.

## Remediation

The controlled service was deleted:

```powershell
sc.exe delete ElasticLab07
```

Windows returned:

```text
[SC] DeleteService SUCCESS
```

## Post-Deletion Verification

The following command produced no matching service:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

The service query:

```powershell
sc.exe query ElasticLab07
```

returned:

```text
The specified service does not exist as an installed service.
```

The Registry was checked using:

```powershell
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07"
```

Result:

```text
False
```

This confirmed the controlled service and its associated Registry configuration were removed.

## Final Assessment

```text
Baseline check
      ↓
Service created with sc.exe
      ↓
Service configuration validated
      ↓
Elastic sc.exe telemetry observed
      ↓
Service Registry configuration validated locally
      ↓
Elastic Registry hunt returned no matching event
      ↓
Independent service-process execution not demonstrated
      ↓
Service deleted
      ↓
Deletion verified through Service Manager and Registry
```

No malicious service execution, malware execution, credential theft, privilege escalation, command-and-control, or confirmed compromise was demonstrated.
