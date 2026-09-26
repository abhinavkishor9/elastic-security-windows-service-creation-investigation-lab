# Timeline

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

