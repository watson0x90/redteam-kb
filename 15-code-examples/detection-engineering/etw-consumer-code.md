# ETW Consumer Code for Red Team Operators

**MITRE ATT&CK Mapping**: Detection Engineering -- T1562.006 (Indicator Blocking), T1003.001 (LSASS Memory), T1055 (Process Injection), T1059.001 (PowerShell)

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

Event Tracing for Windows (ETW) is the telemetry backbone of modern Windows security monitoring.
Every major EDR product -- CrowdStrike, SentinelOne, Microsoft Defender for Endpoint, Elastic --
consumes ETW events as a primary data source. Red teamers must understand this pipeline because:

1. **Test your evasion.** Build an ETW consumer in your lab, run your tools, and observe exactly which events fire.
2. **Understand what you are disabling.** When you patch ETW, you blind specific providers. Knowing which providers emit which events tells you whether your patch is sufficient.
3. **OPSEC prioritization.** Not all providers are enabled on every endpoint. Knowing what is active helps assess risk.

## ETW Architecture: Providers -> Sessions -> Consumers

**Providers** emit events (kernel, .NET runtime, AMSI, etc.). **Sessions** buffer and route events
through kernel-mode circular buffers. **Consumers** process events in real time or from log files.
EDR agents are consumers that subscribe to security-relevant providers.

## Key ETW Providers for Security Monitoring

| # | Provider | GUID | Detects |
|---|---|---|---|
| 1 | Microsoft-Windows-Threat-Intelligence | `f4e1897a-bb5d-5668-f1d8-040f4d8dd344` | Kernel-level memory ops, code injection (requires PPL) |
| 2 | Microsoft-Windows-Kernel-Process | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` | Process creation, termination, image loads |
| 3 | Microsoft-Windows-DotNETRuntime | `e13c0d23-ccbc-4e12-931b-d9cc2eee27e4` | .NET assembly loading, JIT (detects execute-assembly) |
| 4 | Microsoft-Windows-PowerShell | `a0c1853b-5c40-4b15-8766-3cf1c58f985a` | Script block logging, module loading |
| 5 | Microsoft-Antimalware-Scan-Interface | `2a576b87-09a7-520e-c21a-4942f0271d67` | AMSI scan requests and results |

---

## Building a Real-Time ETW Consumer in C

```c
/*
 * etw_consumer.c -- Real-time ETW consumer monitoring .NET assembly loads.
 * Compile: cl.exe /W4 etw_consumer.c /link advapi32.lib tdh.lib
 * Run as Administrator. Detects execute-assembly and similar .NET tradecraft.
 */
#define UNICODE 1
#define _UNICODE 1
#include <windows.h>
#include <stdio.h>
#include <evntrace.h>   // StartTrace, OpenTrace, ProcessTrace
#include <evntcons.h>   // EVENT_TRACE_LOGFILE, EVENT_RECORD
#include <tdh.h>        // TdhGetEventInformation for event property decoding
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// Microsoft-Windows-DotNETRuntime GUID -- emits assembly load, JIT, GC events
static const GUID DotNetRuntimeGuid = {
    0xe13c0d23, 0xccbc, 0x4e12,
    { 0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4 }
};
#define SESSION_NAME L"RedTeamETWMonitor"
#define DOTNET_LOADER_KEYWORD 0x8  // LoaderKeyword: assembly load events only

static TRACEHANDLE g_SessionHandle = 0;
static TRACEHANDLE g_TraceHandle = INVALID_PROCESSTRACE_HANDLE;

/* EventRecordCallback -- fires for every event from subscribed providers.
 * EVENT_RECORD contains raw event data; TDH decodes property names/values. */
static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEvent)
{
    DWORD dwBufferSize = 0;
    PTRACE_EVENT_INFO pInfo = NULL;
    if (!IsEqualGUID(&pEvent->EventHeader.ProviderId, &DotNetRuntimeGuid))
        return;

    // Event ID 152 = AssemblyLoad/Start -- fires when any .NET assembly loads
    if (pEvent->EventHeader.EventDescriptor.Id == 152) {
        wprintf(L"\n[!] .NET Assembly Load Detected!\n");
        wprintf(L"    PID: %lu  TID: %lu  Time: %llu\n",
            pEvent->EventHeader.ProcessId,
            pEvent->EventHeader.ThreadId,
            pEvent->EventHeader.TimeStamp.QuadPart);
    }

    // TdhGetEventInformation: first call gets buffer size, second retrieves data
    DWORD status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &dwBufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        pInfo = (PTRACE_EVENT_INFO)malloc(dwBufferSize);
        if (!pInfo) return;
        status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &dwBufferSize);
        if (status == ERROR_SUCCESS) {
            if (pInfo->OpcodeNameOffset > 0)  // Print opcode name (e.g. "AssemblyLoad")
                wprintf(L"    Event: %s\n", (PWCHAR)((PBYTE)pInfo + pInfo->OpcodeNameOffset));
            // Iterate event properties -- each has name, type, data offset
            for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
                PWCHAR name = (PWCHAR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
                wprintf(L"    Property[%lu]: %s\n", i, name);
            }
        }
        free(pInfo);
    }
}

/* StartSession -- creates a real-time trace session and enables the provider. */
static ULONG StartSession(void)
{
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME)+1)*sizeof(WCHAR);
    PEVENT_TRACE_PROPERTIES props = (PEVENT_TRACE_PROPERTIES)calloc(1, bufferSize);
    if (!props) return ERROR_OUTOFMEMORY;

    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;                          // QPC clock resolution
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;         // No log file, real-time only
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&g_SessionHandle, SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {                    // Clean up stale session
        ControlTraceW(0, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&g_SessionHandle, SESSION_NAME, props);
    }
    if (status != ERROR_SUCCESS) { free(props); return status; }

    // Enable provider with TRACE_LEVEL_INFORMATION + LoaderKeyword filter
    status = EnableTraceEx2(g_SessionHandle, &DotNetRuntimeGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION, DOTNET_LOADER_KEYWORD, 0, 0, NULL);
    wprintf(L"[+] Session started, .NET Runtime provider enabled\n");
    free(props);
    return status;
}

int wmain(void)
{
    wprintf(L"=== Red Team ETW Monitor ===\n");
    if (StartSession() != ERROR_SUCCESS) return 1;

    // Configure consumer: real-time mode, new EVENT_RECORD format, our callback
    EVENT_TRACE_LOGFILEW logfile = { 0 };
    logfile.LoggerName = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;

    g_TraceHandle = OpenTraceW(&logfile);
    if (g_TraceHandle == INVALID_PROCESSTRACE_HANDLE) return 1;

    wprintf(L"[+] Waiting for events (Ctrl+C to stop)...\n\n");
    ProcessTrace(&g_TraceHandle, 1, NULL, NULL);  // Blocks, calls EventRecordCallback
    CloseTrace(g_TraceHandle);
    return 0;
}
```

---

## Python ETW Consumer

```python
#!/usr/bin/env python3
"""Multi-provider ETW consumer for red team detection validation.
Requires: pip install pywintrace. Run as Administrator."""

import sys, time, ctypes
from datetime import datetime
try:
    from etw import ETW, ProviderInfo
    from etw.GUID import GUID
except ImportError:
    print("[!] Install pywintrace: pip install pywintrace"); sys.exit(1)

# Security-relevant ETW providers with keyword filters
PROVIDERS = {
    "DotNETRuntime":  {"guid": "{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}",
                       "keywords": 0x8, "level": 4},    # LoaderKeyword
    "KernelProcess":  {"guid": "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}",
                       "keywords": 0x10, "level": 4},   # Process events
    "PowerShell":     {"guid": "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}",
                       "keywords": 0x1, "level": 5},    # Script block logging
    "AMSI":           {"guid": "{2a576b87-09a7-520e-c21a-4942f0271d67}",
                       "keywords": 0xFFFF, "level": 4}, # All AMSI events
}

class SecurityEventHandler:
    """Routes ETW events to provider-specific detection handlers."""
    def __init__(self):
        self.event_count = 0
        self.alerts = []

    def handle_event(self, event_data):
        self.event_count += 1
        pid = str(event_data.get("ProviderId", "")).lower()
        if "e13c0d23" in pid:   self._handle_dotnet(event_data)
        elif "22fb2cd6" in pid: self._handle_kernel_process(event_data)
        elif "a0c1853b" in pid: self._handle_powershell(event_data)
        elif "2a576b87" in pid: self._handle_amsi(event_data)

    def _handle_dotnet(self, event):
        """Detect execute-assembly: assemblies loaded from byte arrays (no file path)."""
        if event.get("EventId") == 152:  # AssemblyLoad/Start
            name = event.get("AssemblyName", "unknown")
            pid = event.get("ProcessId", 0)
            print(f"[CLR] Assembly loaded: {name} (PID: {pid})")
            if not event.get("FullyQualifiedAssemblyName", "").startswith("file:"):
                self._alert("IN_MEMORY_ASSEMBLY_LOAD",
                    f"Assembly '{name}' loaded from memory in PID {pid}", "HIGH")

    def _handle_kernel_process(self, event):
        """Detect unsigned DLL loads into sensitive processes (LSASS, svchost)."""
        if event.get("EventId") == 5:  # ImageLoad
            img = event.get("ImageName", "")
            proc = event.get("ProcessName", "").lower()
            pid = event.get("ProcessId", 0)
            if "lsass" in proc and img:
                self._alert("LSASS_IMAGE_LOAD",
                    f"Image '{img}' loaded into LSASS (PID {pid})", "CRITICAL")

    def _handle_powershell(self, event):
        """Detect suspicious script blocks: AMSI bypass, credential access, reflection."""
        if event.get("EventId") == 4104:  # Script Block Logging
            script = event.get("ScriptBlockText", "")
            suspects = ["AmsiScanBuffer", "Invoke-Mimikatz", "System.Reflection",
                        "VirtualAlloc", "DllImport", "-EncodedCommand"]
            for pattern in suspects:
                if pattern.lower() in script.lower():
                    self._alert("SUSPICIOUS_SCRIPT_BLOCK",
                        f"Script contains '{pattern}'", "HIGH")
                    print(f"    Script: {script[:200]}...")
                    break

    def _handle_amsi(self, event):
        """Monitor AMSI scan results (AMSI_RESULT_DETECTED = 32768+)."""
        if event.get("ScanResult", 0) >= 32768:
            print(f"[AMSI] Malicious content detected: {event.get('ContentName','?')}")

    def _alert(self, alert_type, detail, severity):
        alert = {"time": datetime.now().isoformat(), "type": alert_type,
                 "detail": detail, "severity": severity}
        self.alerts.append(alert)
        print(f"  [ALERT] {detail}")

    def print_summary(self):
        print(f"\n{'='*60}\nSession: {self.event_count} events, {len(self.alerts)} alerts")
        for a in self.alerts:
            print(f"  [{a['severity']}] {a['type']}: {a['detail']}")

def main():
    print("=== Red Team ETW Monitor (Python) ===\n")
    handler = SecurityEventHandler()
    providers = [ProviderInfo(n, GUID(c["guid"]), level=c["level"], keywords=c["keywords"])
                 for n, c in PROVIDERS.items()]
    etw_session = ETW(providers=providers, event_callback=handler.handle_event,
                      session_name="PythonRedTeamMonitor")
    try:
        etw_session.start()
        print(f"[+] Monitoring {len(providers)} providers. Ctrl+C to stop.\n")
        while True: time.sleep(1)
    except KeyboardInterrupt:
        etw_session.stop(); handler.print_summary()
    return 0

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Requires Administrator privileges."); sys.exit(1)
    sys.exit(main())
```

---

## Practical Detections

### 1. Detecting Execute-Assembly via CLR Loading

When Cobalt Strike's `execute-assembly` runs, the CLR is loaded into a process that does not
normally host .NET code (e.g., `rundll32.exe`). **Detection signal**: Event ID 152 (AssemblyLoad)
in an unusual host process, with assembly loaded from memory (no `file://` URI in
FullyQualifiedAssemblyName). Combine with process creation events to identify the parent.

### 2. Detecting LSASS Access for Credential Dumping

Credential dumping tools (Mimikatz, nanodump) call OpenProcess on lsass.exe with PROCESS_VM_READ.
**Detection signal**: Process access event targeting lsass.exe with access rights including 0x0010
(PROCESS_VM_READ) or PROCESS_ALL_ACCESS, where the source is not a known security product.
The Threat-Intelligence provider (requires PPL) generates ReadProcessMemory events.

### 3. Detecting Unsigned DLL Loads in Sensitive Processes

Reflective DLL injection results in image load events for unsigned DLLs. **Detection signal**:
ImageLoad (Event ID 5) in lsass.exe/svchost.exe/csrss.exe where the loaded image has no
Authenticode signature, resides in a temp directory, or has an empty path (memory-only load).

## OPSEC: Enumerating Active ETW Sessions

```
logman query providers              -- List all registered providers
logman query -ets                   -- List active trace sessions
logman query "EventLog-Security" -ets  -- Query a specific session's providers

Key questions for red teamers:
1. Is Threat-Intelligence active? -> PPL EDR is present, injection generates events
2. Is DotNETRuntime active? -> execute-assembly will be logged, prefer BOFs instead
3. Is PowerShell script block logging on? -> Avoid PowerShell, or bypass CLM
4. Which sessions consume events? -> EDR session names reveal the product in use
```

## Cross-References

- [ETW Evasion Techniques](../../06-defense-evasion/etw-evasion.md) -- patching EtwEventWrite and NtTraceEvent; this file shows what those patches disable
- [AV/EDR Evasion](../../06-defense-evasion/av-edr-evasion.md) -- EDR products are ETW consumers; understanding consumer code reveals EDR internals
- [AMSI Bypass Techniques](../../06-defense-evasion/amsi-bypass.md) -- AMSI events flow through ETW; patching AMSI changes what the AMSI provider reports
- [YARA Rule Development](yara-rule-development.md) -- YARA handles static detection; ETW handles runtime detection; both needed for purple teaming
- [Process Injection Techniques](../../06-defense-evasion/process-injection.md) -- the Threat-Intelligence ETW provider is designed to detect injection
