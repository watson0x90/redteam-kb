# Named Pipe C2 - Educational Protocol Analysis

> **MITRE ATT&CK**: T1570 (Lateral Tool Transfer) / T1021.002 (SMB/Windows Admin Shares)
> **Purpose**: Understanding named pipe IPC for internal C2 detection
> **Detection Priority**: Medium - Internal lateral communication mechanism

## Strategic Overview

Named pipes are a Windows inter-process communication (IPC) mechanism that can also work over the network via SMB. C2 frameworks use named pipes for internal peer-to-peer communication between implants, allowing lateral movement traffic to blend with normal SMB activity. Understanding pipe-based communication is essential for detecting internal C2 channels.

### Why This Matters for Red Team Leads
- Named pipes enable peer-to-peer C2 within a network (no external egress needed)
- SMB-based pipes blend with normal Windows domain traffic
- Only one implant needs external C2; others chain through pipes
- Common in Cobalt Strike (SMB Beacon) and other frameworks

### Detection Opportunity
Named pipe creation and connections are logged by Sysmon (Event IDs 17/18) and can be monitored by EDR solutions.

## Technical Deep-Dive

### Named Pipe Architecture

```
External C2 Channel (HTTPS):
┌──────────┐  HTTPS    ┌──────────┐
│ Beacon 1 │ ────────> │ C2 Server│
│ (pivot)  │ <──────── │          │
└────┬─────┘           └──────────┘
     │
     │ Named Pipe (SMB internally)
     │
┌────┴─────┐  Named Pipe  ┌──────────┐
│ Beacon 2 │ ────────────> │ Beacon 3 │
│          │ <──────────── │          │
└──────────┘               └──────────┘

Advantages:
- Only Beacon 1 needs external connectivity
- Beacons 2 & 3 communicate via internal pipes
- Pipe traffic rides over existing SMB connections
- No additional firewall rules needed
```

### Windows Named Pipe API (C - Educational)

```c
/*
 * Educational: Named Pipe server/client implementation.
 * Demonstrates the Windows API used for pipe-based IPC.
 * Understanding these APIs helps defenders:
 * 1. Know which API calls to monitor for pipe creation
 * 2. Understand pipe naming conventions used by C2 tools
 * 3. Build detection rules based on pipe behavior
 *
 * BUILD: cl.exe /nologo /W3 pipe_demo.c /link advapi32.lib
 */
#include <windows.h>
#include <stdio.h>

/*
 * Named Pipe Naming Convention:
 * \\.\pipe\<pipename>          - Local pipe
 * \\<hostname>\pipe\<pipename> - Remote pipe (over SMB)
 *
 * C2 Framework Default Pipe Names (DETECTION SIGNATURES):
 * ─────────────────────────────────────────────────────────
 * Cobalt Strike:  \\.\pipe\msagent_##    (default, configurable)
 *                 \\.\pipe\MSSE-####-server
 *                 \\.\pipe\status_##
 *                 \\.\pipe\postex_####
 *                 \\.\pipe\postex_ssh_####
 *
 * Metasploit:     \\.\pipe\meterpreter_####
 *
 * Covenant:       \\.\pipe\GruntSMB
 *
 * PsExec:         \\.\pipe\PSEXESVC
 *
 * Impacket:       \\.\pipe\RemSvc####
 *
 * DETECTION: Monitor for pipes matching these patterns!
 * However, mature adversaries customize pipe names to
 * mimic legitimate Windows pipes.
 */

#define PIPE_NAME L"\\\\.\\pipe\\demo_educational_pipe"
#define BUFFER_SIZE 4096

/*
 * Pipe Server - Creates and listens on a named pipe.
 *
 * Security Note: The security descriptor determines who
 * can connect. NULL DACL = everyone can connect (dangerous).
 * Proper ACLs should restrict to specific accounts.
 *
 * Detection:
 * - Sysmon Event ID 17 (PipeCreated) logs pipe creation
 * - Event fields: PipeName, Image (creating process)
 */
BOOL create_pipe_server(void) {
    HANDLE hPipe;
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;

    /* Create security descriptor */
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    /* In production, set proper DACL instead of NULL */
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    /*
     * CreateNamedPipe parameters analysis:
     *
     * PIPE_ACCESS_DUPLEX:  Bidirectional (both read and write)
     * PIPE_TYPE_MESSAGE:   Data sent as discrete messages
     * PIPE_WAIT:           Blocking mode
     * nMaxInstances:       1 = single client connection
     *
     * Detection: APIs monitored by EDR:
     * - NtCreateNamedPipeFile (kernel level)
     * - CreateNamedPipeW/A (user level)
     */
    hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,              /* Max instances */
        BUFFER_SIZE,    /* Output buffer size */
        BUFFER_SIZE,    /* Input buffer size */
        0,              /* Default timeout */
        &sa             /* Security attributes */
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("CreateNamedPipe failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[Server] Pipe created: %ls\n", PIPE_NAME);
    printf("[Server] Waiting for client connection...\n");

    /*
     * ConnectNamedPipe blocks until a client connects.
     *
     * Detection:
     * - Sysmon Event ID 18 (PipeConnected) logs connections
     * - Fields: PipeName, Image (connecting process)
     */
    if (!ConnectNamedPipe(hPipe, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            printf("ConnectNamedPipe failed: %lu\n", GetLastError());
            CloseHandle(hPipe);
            return FALSE;
        }
    }

    printf("[Server] Client connected!\n");

    /* Read/Write demonstration */
    char buffer[BUFFER_SIZE];
    DWORD bytesRead, bytesWritten;

    /* Read from client */
    if (ReadFile(hPipe, buffer, BUFFER_SIZE - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        printf("[Server] Received: %s\n", buffer);
    }

    /* Write response */
    const char *response = "Message received by server";
    WriteFile(hPipe, response, (DWORD)strlen(response), &bytesWritten, NULL);

    /* Cleanup */
    FlushFileBuffers(hPipe);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return TRUE;
}

/*
 * Pipe Client - Connects to an existing named pipe.
 *
 * For remote pipes, change PIPE_NAME to:
 * \\<remote_host>\pipe\<pipename>
 * This causes the connection to go over SMB (port 445)
 *
 * Detection:
 * - SMB connections to IPC$ share
 * - Sysmon Event ID 18 (PipeConnected)
 * - Network connections on port 445
 */
BOOL connect_pipe_client(void) {
    HANDLE hPipe;
    DWORD bytesRead, bytesWritten;
    char buffer[BUFFER_SIZE];

    /*
     * CreateFile on a pipe path connects to the server.
     * For remote connections, this triggers SMB negotiation.
     *
     * Detection: CreateFile calls targeting pipe paths,
     * especially to remote hosts (\\remote\pipe\name)
     */
    hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,              /* No sharing */
        NULL,           /* Default security */
        OPEN_EXISTING,  /* Must already exist */
        0,              /* Default attributes */
        NULL            /* No template */
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("Could not connect to pipe: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[Client] Connected to pipe\n");

    /* Set pipe to message read mode */
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

    /* Send message */
    const char *message = "Hello from client";
    WriteFile(hPipe, message, (DWORD)strlen(message), &bytesWritten, NULL);
    printf("[Client] Sent: %s\n", message);

    /* Read response */
    if (ReadFile(hPipe, buffer, BUFFER_SIZE - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        printf("[Client] Received: %s\n", buffer);
    }

    CloseHandle(hPipe);
    return TRUE;
}

/*
 * Pipe Enumeration - Useful for both attackers and defenders
 *
 * Defenders: Enumerate pipes to find suspicious pipe names
 * Attackers: Find available pipes for connection
 */
void enumerate_pipes(void) {
    WIN32_FIND_DATAW findData;
    HANDLE hFind;

    printf("=== Named Pipe Enumeration ===\n");
    printf("(Detection: Pipe enumeration itself is suspicious)\n\n");

    hFind = FindFirstFileW(L"\\\\.\\pipe\\*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Enumeration failed: %lu\n", GetLastError());
        return;
    }

    int count = 0;
    do {
        printf("  %ls\n", findData.cFileName);
        count++;
    } while (FindNextFileW(hFind, &findData));

    printf("\nTotal pipes: %d\n", count);
    FindClose(hFind);
}
```

### Pipe Monitoring (Python)

```python
"""
Educational: Named pipe monitoring and detection scripts.
These demonstrate how defenders can monitor pipe activity
on Windows systems.
"""
import subprocess
import re

def enumerate_named_pipes():
    """
    List all named pipes on the local system.

    PowerShell equivalent:
    Get-ChildItem \\.\pipe\ | Select-Object Name

    Use this to baseline normal pipes and identify anomalies.
    """
    try:
        result = subprocess.run(
            ['powershell', '-c', 'Get-ChildItem', r'\\.\pipe\\',
             '|', 'Select-Object', '-ExpandProperty', 'Name'],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip().split('\n')
    except Exception as e:
        return [f"Error: {e}"]


# Known suspicious pipe name patterns
SUSPICIOUS_PIPE_PATTERNS = [
    # Cobalt Strike defaults
    r'msagent_\w+',
    r'MSSE-\d+-server',
    r'status_\d+',
    r'postex_\d+',
    r'postex_ssh_\d+',

    # Metasploit
    r'meterpreter_\w+',

    # Covenant
    r'GruntSMB',

    # PsExec
    r'PSEXESVC',
    r'PSEXESVC-\w+',

    # Impacket
    r'RemSvc\w+',

    # Generic suspicious
    r'[a-f0-9]{32}',       # MD5-hash named pipes
    r'pipe_\d+',           # Simple numeric pipes
]

def check_suspicious_pipes(pipe_list: list) -> list:
    """
    Check pipe names against known C2 patterns.

    Production Use: Run this periodically or integrate
    with Sysmon Event ID 17 processing.
    """
    alerts = []
    for pipe in pipe_list:
        for pattern in SUSPICIOUS_PIPE_PATTERNS:
            if re.match(pattern, pipe, re.IGNORECASE):
                alerts.append({
                    'pipe_name': pipe,
                    'matched_pattern': pattern,
                    'severity': 'HIGH',
                    'recommendation': 'Investigate creating process and connections'
                })
    return alerts
```

## Detection & Evasion

### Sysmon Detection Rules

```xml
<!-- Sysmon Configuration for Named Pipe Monitoring -->

<!-- Event ID 17: Pipe Created -->
<PipeEvent onmatch="include">
    <!-- Cobalt Strike default pipes -->
    <PipeName condition="begin with">\msagent_</PipeName>
    <PipeName condition="begin with">\MSSE-</PipeName>
    <PipeName condition="begin with">\postex_</PipeName>
    <PipeName condition="begin with">\status_</PipeName>

    <!-- Metasploit pipes -->
    <PipeName condition="begin with">\meterpreter</PipeName>

    <!-- Impacket pipes -->
    <PipeName condition="begin with">\RemSvc</PipeName>

    <!-- PsExec -->
    <PipeName condition="is">\PSEXESVC</PipeName>
</PipeEvent>

<!-- Event ID 18: Pipe Connected - monitor connections -->
<PipeEvent onmatch="include">
    <!-- Same patterns as above for connection monitoring -->
    <PipeName condition="begin with">\msagent_</PipeName>
    <PipeName condition="begin with">\postex_</PipeName>
</PipeEvent>
```

### Detection Summary

| Indicator | Source | Event ID | Description |
|-----------|--------|----------|-------------|
| Pipe creation | Sysmon | 17 | New pipe with suspicious name |
| Pipe connection | Sysmon | 18 | Connection to suspicious pipe |
| SMB to IPC$ | Network | N/A | Remote pipe connection via SMB |
| Pipe enumeration | EDR | Varies | Process listing all pipes |
| Process → Pipe correlation | Sysmon | 17 + 1 | Which process created the pipe |

### Evasion Techniques (What to Watch For)
- **Custom pipe names**: Mimicking legitimate Windows pipes (e.g., `\lsass`, `\wkssvc`)
- **Short-lived pipes**: Created and destroyed quickly to avoid enumeration
- **Impersonation**: Using pipes for token impersonation attacks
- **Overlapping I/O**: Async pipe operations that are harder to trace

## Cross-References

- [Lateral Movement via SMB](../../09-lateral-movement/psexec-smbexec.md)
- [Cobalt Strike Cheatsheet](../../appendices/cobalt-strike-cheatsheet.md)
- [C2 Frameworks](../../11-command-and-control/c2-frameworks.md)
- [SMB Enumeration](../../01-reconnaissance/smb-enumeration.md)
- [Windows Internals](../../appendices/windows-internals-reference.md)

## References

- Microsoft: Named Pipe Operations Documentation
- Sysmon Event ID 17/18 Documentation
- MITRE ATT&CK T1570, T1021.002
- Cobalt Strike: SMB Beacon Documentation
- Elastic Security: Detecting Named Pipe Abuse
