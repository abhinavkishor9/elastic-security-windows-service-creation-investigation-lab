# Troubleshooting Notes — Suspicious Service Creation

## Issue 1 — Registry Hunt Returned 0 Documents

### Query

```esql
FROM logs-*
| WHERE registry.key LIKE "*CurrentControlSet*Services*"
| WHERE registry.value LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, registry.key, registry.value, registry.data.strings
| SORT @timestamp DESC
```

### Result

```text
0 documents processed
```

### Investigation

The service definitely existed locally and its Registry configuration could be read with PowerShell.

The local Registry path was:

```text
HKLM:\SYSTEM\CurrentControlSet\Services\ElasticLab07
```

However, no matching Registry event was returned by the Elastic query.

### Resolution

The Registry result was documented as a telemetry limitation.

The service was instead investigated through:

```text
Local Service Configuration
+
Local Registry Inspection
+
sc.exe Process Telemetry
```

### Lesson

Successful local Registry inspection does not guarantee that the same artifact will be available through the queried Elastic Registry dataset.

---

## Issue 2 — Service Name Search Was More Effective Through Process Command Line

The following query successfully identified service-management activity:

```esql
FROM logs-*
| WHERE process.command_line LIKE "*ElasticLab07*"
| KEEP @timestamp, host.name, user.name, process.name, process.pid, process.parent.name, process.parent.pid, process.command_line, process.executable
| SORT @timestamp DESC
```

This returned `sc.exe` activity containing the test service name.

### Lesson

When a structured Registry search is unavailable, a known service name can be used to locate the process that created or queried the service.

---

## Issue 3 — Broad `sc.exe` Operation Filter Returned 0 Results

The query:

```esql
FROM logs-*
| WHERE process.name == "sc.exe"
| WHERE process.command_line LIKE "*/*"
| KEEP @timestamp, host.name, user.name, process.command_line, process.parent.name, process.parent.pid
| SORT @timestamp DESC
```

returned:

```text
0 documents processed
```

### Investigation

The previous service-name search had already demonstrated that `sc.exe` telemetry was present.

The broader query therefore was not treated as evidence that `sc.exe` was absent.

### Lesson

A failed broad filter does not invalidate a previously confirmed event.

When a query returns zero results, review:

```text
Time Range
Field Values
Filter Logic
Query Specificity
```

---

## Issue 4 — `sc.exe` Events Had Incomplete Metadata

Some `sc.exe` records contained:

```text
PID: null
Parent: null
Command Line: null
```

while still showing:

```text
process.executable:
C:\Windows\System32\sc.exe
```

### Handling

These events were recorded as incomplete telemetry.

Complete events containing:

```text
PID
Parent Process
Parent PID
Command Line
User
```

were used for the main investigation.

### Lesson

Do not fill in missing process metadata from assumptions.

---

## Issue 5 — Service Account vs Interactive User

The service was created from PowerShell as user:

```text
Dell
```

However, `sc.exe qc ElasticLab07` reported:

```text
SERVICE_START_NAME: LocalSystem
```

The Registry configuration independently showed:

```text
ObjectName: LocalSystem
```

### Lesson

The user who creates a service and the account under which the service is configured to run are different investigation fields.

Always distinguish:

```text
Creating User
```

from:

```text
Service Start Account
```

---

## Issue 6 — Service Start Type Was Manual

The service configuration showed:

```text
START_TYPE: 3 DEMAND_START
```

PowerShell showed:

```text
StartType: Manual
```

### Interpretation

The service was not configured for automatic startup.

Therefore, the lab focused on **service creation and configuration** rather than demonstrating automatic startup persistence.

### Lesson

A service can exist without being configured for automatic startup.

Start type is an important persistence-context field.

---

## Issue 7 — Service Was Stopped

The service state was:

```text
STOPPED
```

This was expected for the controlled configuration.

The service was not required to remain running for the service-creation investigation.

### Lesson

Service creation, service configuration, and service execution are separate investigation stages.

---

## Issue 8 — Binary Execution Was Not Independently Confirmed

The service action was:

```text
C:\Windows\System32\cmd.exe /c exit
```

Elastic showed the creation/configuration command containing this value.

However, the investigation did not establish an independent service-process event showing that the configured binary executed.

### Lesson

Do not equate:

```text
Configured Binary Path
```

with:

```text
Observed Binary Execution
```

They are separate evidence points.

---

## Issue 9 — Parent Process Interpretation

The `sc.exe` creation event showed:

```text
Parent: pwsh.exe
```

This is the parent of the `sc.exe` process used to create the service.

It should not automatically be used as the parent of the eventual service process.

### Lesson

Keep these relationships separate:

```text
pwsh.exe
    ↓
sc.exe
    ↓
Service Configuration
```

versus:

```text
Service Control Manager
    ↓
Service Process
```

The second relationship requires its own telemetry evidence.

---

## Issue 10 — Time Range

The investigation initially used:

```text
Last 15 minutes
```

The Registry investigation was later performed with:

```text
Last 1 hour
```

The important Elastic timestamps included:

```text
05:54:16.453
```

for the service creation event and:

```text
05:55:46.557
```

for the service configuration query.

### Lesson

Always make sure the selected time range contains the controlled activity.

For troubleshooting, temporarily expanding the window is appropriate.

---

## Issue 11 — Service Deletion Verification

The service was removed using:

```powershell
sc.exe delete ElasticLab07
```

Windows returned:

```text
[SC] DeleteService SUCCESS
```

The service was then checked using:

```powershell
Get-Service -Name "ElasticLab07" -ErrorAction SilentlyContinue
```

and:

```powershell
sc.exe query ElasticLab07
```

The second command returned:

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

### Lesson

Validate remediation through more than one representation when possible:

```text
Service Manager
+
Service Query
+
Registry
```

---

## Investigation Lessons

### Service Creation Is Not the Same as Service Execution

```text
Service Created
       ≠
Service Executed
```

Both must be investigated independently.

### Creating User and Service Account Are Different

The interactive user was:

```text
Dell
```

while the service account was:

```text
LocalSystem
```

### Start Type Provides Persistence Context

The test service used:

```text
Demand Start / Manual
```

rather than automatic startup.

### Structured Telemetry May Be Missing

Elastic did not return the controlled service Registry artifact through the tested Registry query.

That limitation was documented instead of inferred away.

### Known Artifacts Help Hunting

Searching for:

```text
ElasticLab07
```

in `process.command_line` successfully identified relevant `sc.exe` activity.

### Evidence Must Drive the Assessment

The investigation followed:

```text
Local Configuration
      ↓
Elastic Process Telemetry
      ↓
Registry Validation
      ↓
Correlation
      ↓
Assessment
```

rather than:

```text
New Service
      ↓
Automatically Malicious
```
