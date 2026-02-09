# BOF (Beacon Object File) Development

> **Languages**: C
> **Purpose**: Writing custom BOFs for Cobalt Strike or any compatible COFF loader

## Overview

A Beacon Object File (BOF) is a compiled-but-not-linked C object file designed to be loaded
and executed by a COFF loader (such as Cobalt Strike's Beacon, or the standalone loaders in
this knowledge base). BOFs execute in-process with no new thread, no new process, and minimal
memory footprint. This guide covers the API surface, the Dynamic Function Resolution (DFR)
convention, and provides three complete, compilable BOF examples.

## BOF API Header (beacon.h)

```c
/*
 * beacon.h
 *
 * Minimal Beacon API header for BOF development. This file declares the
 * functions and types that the COFF loader provides to BOFs at runtime.
 *
 * These functions are resolved as external symbols by the loader -- the
 * BOF does not link against any library. The loader maps these symbol
 * names to its own internal implementations.
 *
 * Compatible with: Cobalt Strike 4.1+, TrustedSec COFFLoader, and any
 * loader that implements the Beacon API contract.
 */

#ifndef BEACON_H_
#define BEACON_H_

#include <windows.h>

/* ======================================================================
 * Output Type Constants
 *
 * These values are passed to BeaconPrintf and BeaconOutput to indicate
 * the type of output. The C2 framework uses these to route output to
 * the correct display channel.
 * ====================================================================== */

#define CALLBACK_OUTPUT      0x00  /* Standard output */
#define CALLBACK_OUTPUT_OEM  0x1E  /* OEM-encoded output */
#define CALLBACK_OUTPUT_UTF8 0x20  /* UTF-8 encoded output */
#define CALLBACK_ERROR       0x0D  /* Error output (displayed in red in CS) */

/* ======================================================================
 * Output Functions
 *
 * BeaconPrintf: printf-style formatted output, sent back to the operator.
 * BeaconOutput: raw binary/string output of a specific length.
 *
 * IMPORTANT: Do NOT use printf(), puts(), or any CRT output function.
 * BOFs have no C runtime. All output must go through these Beacon APIs.
 * ====================================================================== */

DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char* data, int len);

/* ======================================================================
 * Format API (Structured Output Buffer)
 *
 * The format API provides a growable string buffer for building output.
 * This is more efficient than many individual BeaconPrintf calls because
 * it batches output into a single transmission back to the C2 server.
 *
 * Usage pattern:
 *   formatp fp;
 *   BeaconFormatAlloc(&fp, 8192);
 *   BeaconFormatPrintf(&fp, "PID: %d\n", pid);
 *   BeaconFormatPrintf(&fp, "Name: %s\n", name);
 *   int len = BeaconFormatLength(&fp);
 *   char* output = BeaconFormatOriginal(&fp);
 *   BeaconOutput(CALLBACK_OUTPUT, output, len);
 *   BeaconFormatFree(&fp);
 * ====================================================================== */

typedef struct {
    char*  original;  /* Start of the allocated buffer                    */
    char*  buffer;    /* Current write position                           */
    int    length;    /* Number of bytes written so far                   */
    int    size;      /* Total allocated size                             */
} formatp;

DECLSPEC_IMPORT void  BeaconFormatAlloc(formatp* format, int maxsz);
DECLSPEC_IMPORT void  BeaconFormatReset(formatp* format);
DECLSPEC_IMPORT void  BeaconFormatFree(formatp* format);
DECLSPEC_IMPORT void  BeaconFormatAppend(formatp* format, char* text, int len);
DECLSPEC_IMPORT void  BeaconFormatPrintf(formatp* format, char* fmt, ...);
DECLSPEC_IMPORT char* BeaconFormatToString(formatp* format, int* size);
DECLSPEC_IMPORT int   BeaconFormatLength(formatp* format);
DECLSPEC_IMPORT char* BeaconFormatOriginal(formatp* format);

/* ======================================================================
 * Data Parser API (Argument Parsing)
 *
 * When the operator passes arguments to a BOF, they are packed into a
 * binary buffer using a type-length-value scheme. The data parser API
 * extracts values from this buffer in order.
 *
 * The operator (aggressor script / C2 client) packs arguments like:
 *   bof_pack("zi", "hostname", 443);  // string + int
 *
 * The BOF unpacks them with:
 *   datap parser;
 *   BeaconDataParse(&parser, args, len);
 *   char* host = BeaconDataExtract(&parser, NULL);
 *   int port   = BeaconDataInt(&parser);
 * ====================================================================== */

typedef struct {
    char* original;  /* Start of the argument buffer                     */
    char* buffer;    /* Current read position                            */
    int   length;    /* Remaining bytes to read                          */
    int   size;      /* Total buffer size                                */
} datap;

DECLSPEC_IMPORT void  BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int   BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int   BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char* BeaconDataExtract(datap* parser, int* size);

/* ======================================================================
 * Token and Injection APIs (Cobalt Strike specific)
 *
 * These provide access to Beacon's token management and process injection
 * capabilities. They are only available in Cobalt Strike's Beacon; custom
 * loaders may choose not to implement them.
 * ====================================================================== */

DECLSPEC_IMPORT BOOL  BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void  BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL  BeaconIsAdmin(void);

/* GetSpawnTo: Get the configured sacrificial process path for fork&run */
DECLSPEC_IMPORT void  BeaconGetSpawnTo(BOOL x86, char* buffer, int length);

/* Injection functions */
DECLSPEC_IMPORT void  BeaconInjectProcess(HANDLE hProc, int pid, char* payload,
                                           int payloadLen, int offset, char* arg,
                                           int argLen);
DECLSPEC_IMPORT void  BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo,
                                                    char* payload, int payloadLen,
                                                    int offset, char* arg, int argLen);
DECLSPEC_IMPORT void  BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

/* ======================================================================
 * Dynamic Function Resolution (DFR)
 *
 * THE CORE MECHANISM for calling Windows API from BOFs.
 *
 * Since BOFs cannot link against DLLs (they are unlinked object files),
 * all Windows API calls must be declared as external symbols that the
 * COFF loader resolves at load time.
 *
 * Convention: MODULENAME$FunctionName
 *
 * The loader splits on '$', calls LoadLibrary("MODULENAME.dll"), then
 * GetProcAddress(handle, "FunctionName"), and patches the relocation
 * with the resulting address.
 *
 * Example:
 *   DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(
 *       LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
 *
 * In BOF code, you call: KERNEL32$CreateFileA("test.txt", ...)
 * The loader resolves this to kernel32.dll!CreateFileA at load time.
 * ====================================================================== */

/* DFR convenience macros for common patterns */

/*
 * DFR_LOCAL: Declare a DFR import with full prototype.
 * Usage: DFR_LOCAL(KERNEL32, HANDLE, WINAPI, CreateFileA,
 *                  LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
 *                  DWORD, DWORD, HANDLE);
 */

/*
 * Simplified DFR macro - just the declaration.
 * The full prototype must be written manually, but this macro handles the
 * __declspec(dllimport) and name mangling.
 */

#endif /* BEACON_H_ */
```

## Example BOF 1: Process Listing

```c
/*
 * bof_processlist.c
 *
 * A BOF that enumerates all running processes using the ToolHelp32 API
 * and reports PID, parent PID, thread count, and executable name.
 *
 * Compile (MinGW):
 *   x86_64-w64-mingw32-gcc -c -o bof_processlist.o bof_processlist.c
 *
 * Compile (MSVC):
 *   cl.exe /c /GS- /O2 bof_processlist.c
 *
 * Usage (Cobalt Strike):
 *   inline-execute bof_processlist.o
 *
 * Usage (standalone loader):
 *   loader.exe bof_processlist.o
 */

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ======================================================================
 * DFR Declarations
 *
 * Every Windows API call must be declared here. The naming convention
 * is DLLNAME$FunctionName. The COFF loader sees these as external
 * symbols and resolves them via LoadLibrary + GetProcAddress.
 *
 * The function signatures must match the Windows SDK declarations
 * exactly, or you will get stack corruption and crashes.
 * ====================================================================== */

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(
    DWORD dwFlags, DWORD th32ProcessID);

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32FirstW(
    HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$Process32NextW(
    HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(
    HANDLE hObject);

/* ======================================================================
 * Entry Point
 *
 * All BOFs must export a function named "go" with this signature.
 * The args/len parameters contain packed arguments from the operator.
 * For this BOF, no arguments are needed, so we ignore them.
 * ====================================================================== */

void go(char* args, int len) {
    HANDLE hSnapshot;
    PROCESSENTRY32W pe32;
    int processCount = 0;

    /* Create a snapshot of all processes in the system */
    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);

    /* Allocate a format buffer for batch output.
     * 16384 bytes is enough for ~200 processes. If you expect more,
     * increase this or flush and reallocate. */
    formatp buffer;
    BeaconFormatAlloc(&buffer, 16384);

    /* Print header */
    BeaconFormatPrintf(&buffer,
        "%-8s %-8s %-6s %s\n"
        "-------- -------- ------ --------------------------------\n",
        "PID", "PPID", "Thrs", "Process Name");

    /* Iterate all processes */
    if (KERNEL32$Process32FirstW(hSnapshot, &pe32)) {
        do {
            BeaconFormatPrintf(&buffer, "%-8d %-8d %-6d %S\n",
                pe32.th32ProcessID,
                pe32.th32ParentProcessID,
                pe32.cntThreads,
                pe32.szExeFile);
            processCount++;
        } while (KERNEL32$Process32NextW(hSnapshot, &pe32));
    }

    BeaconFormatPrintf(&buffer, "\nTotal: %d processes\n", processCount);

    /* Send all output at once */
    int outputLen = BeaconFormatLength(&buffer);
    char* outputData = BeaconFormatOriginal(&buffer);
    BeaconOutput(CALLBACK_OUTPUT, outputData, outputLen);

    /* Cleanup */
    BeaconFormatFree(&buffer);
    KERNEL32$CloseHandle(hSnapshot);
}
```

## Example BOF 2: Token Information (Whoami)

```c
/*
 * bof_whoami.c
 *
 * A BOF that retrieves and displays the current user's token information,
 * including username, domain, token type, and privilege list.
 *
 * Compile: x86_64-w64-mingw32-gcc -c -o bof_whoami.o bof_whoami.c
 *          cl.exe /c /GS- bof_whoami.c
 */

#include <windows.h>
#include "beacon.h"

/* DFR: Kernel32 functions */
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);

/* DFR: Advapi32 functions */
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(
    HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(
    HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
    LPVOID TokenInformation, DWORD TokenInformationLength,
    PDWORD ReturnLength);

DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$LookupAccountSidA(
    LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName,
    LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse);

DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeNameA(
    LPCSTR lpSystemName, PLUID lpLuid, LPSTR lpName, LPDWORD cchName);

void go(char* args, int len) {
    HANDLE hToken = NULL;
    DWORD dwSize = 0;
    BYTE tokenUserBuf[256];
    BYTE tokenPrivBuf[4096];

    /* Open our own process token */
    if (!ADVAPI32$OpenProcessToken(
            KERNEL32$GetCurrentProcess(),
            TOKEN_QUERY,
            &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %d",
                     KERNEL32$GetLastError());
        return;
    }

    formatp buffer;
    BeaconFormatAlloc(&buffer, 8192);

    /* ---- Get User Information ---- */
    if (ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUserBuf,
                                      sizeof(tokenUserBuf), &dwSize)) {
        TOKEN_USER* pTokenUser = (TOKEN_USER*)tokenUserBuf;
        char userName[128] = {0};
        char domainName[128] = {0};
        DWORD userLen = sizeof(userName);
        DWORD domainLen = sizeof(domainName);
        SID_NAME_USE sidType;

        if (ADVAPI32$LookupAccountSidA(NULL, pTokenUser->User.Sid,
                userName, &userLen, domainName, &domainLen, &sidType)) {
            BeaconFormatPrintf(&buffer, "User:   %s\\%s\n", domainName, userName);
        }
    }

    /* ---- Get Token Elevation ---- */
    TOKEN_ELEVATION elevation;
    dwSize = sizeof(elevation);
    if (ADVAPI32$GetTokenInformation(hToken, TokenElevation, &elevation,
                                      sizeof(elevation), &dwSize)) {
        BeaconFormatPrintf(&buffer, "Elevated: %s\n",
                           elevation.TokenIsElevated ? "Yes" : "No");
    }

    /* ---- Get Token Type ---- */
    TOKEN_TYPE tokenType;
    dwSize = sizeof(tokenType);
    if (ADVAPI32$GetTokenInformation(hToken, TokenType, &tokenType,
                                      sizeof(tokenType), &dwSize)) {
        BeaconFormatPrintf(&buffer, "Token Type: %s\n",
            tokenType == TokenPrimary ? "Primary" : "Impersonation");
    }

    /* ---- Enumerate Privileges ---- */
    if (ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, tokenPrivBuf,
                                      sizeof(tokenPrivBuf), &dwSize)) {
        TOKEN_PRIVILEGES* pPrivs = (TOKEN_PRIVILEGES*)tokenPrivBuf;
        BeaconFormatPrintf(&buffer, "\nPrivileges (%d):\n", pPrivs->PrivilegeCount);
        BeaconFormatPrintf(&buffer,
            "%-40s %s\n"
            "---------------------------------------- --------\n",
            "Privilege Name", "Status");

        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            char privName[128] = {0};
            DWORD privNameLen = sizeof(privName);

            ADVAPI32$LookupPrivilegeNameA(NULL,
                &pPrivs->Privileges[i].Luid,
                privName, &privNameLen);

            DWORD attrs = pPrivs->Privileges[i].Attributes;
            const char* status = "Disabled";
            if (attrs & SE_PRIVILEGE_ENABLED)
                status = "Enabled";
            if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                status = "Default";

            BeaconFormatPrintf(&buffer, "%-40s %s\n", privName, status);
        }
    }

    /* Send output and cleanup */
    int outputLen = BeaconFormatLength(&buffer);
    char* outputData = BeaconFormatOriginal(&buffer);
    BeaconOutput(CALLBACK_OUTPUT, outputData, outputLen);

    BeaconFormatFree(&buffer);
    KERNEL32$CloseHandle(hToken);
}
```

## Example BOF 3: Registry Query

```c
/*
 * bof_regquery.c
 *
 * A BOF that queries a registry value and displays its type and data.
 * Accepts arguments from the operator: hive path, value name.
 *
 * Compile: x86_64-w64-mingw32-gcc -c -o bof_regquery.o bof_regquery.c
 *          cl.exe /c /GS- bof_regquery.c
 *
 * Usage (Cobalt Strike):
 *   inline-execute bof_regquery.o zi "SOFTWARE\Microsoft\Windows\CurrentVersion" "ProgramFilesDir"
 *
 * Argument packing (aggressor):
 *   bof_pack("zz", "SOFTWARE\\Microsoft\\...", "ProgramFilesDir");
 */

#include <windows.h>
#include "beacon.h"

/* DFR: Advapi32 registry functions */
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(
    HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
    REGSAM samDesired, PHKEY phkResult);

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(
    HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegEnumValueA(
    HKEY hKey, DWORD dwIndex, LPSTR lpValueName,
    LPDWORD lpcchValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);

/* DFR: Kernel32 for string formatting */
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);

/*
 * Helper: Convert a registry type code to a human-readable string.
 * No CRT needed -- just a switch statement.
 */
const char* RegTypeToString(DWORD type) {
    switch (type) {
        case REG_SZ:         return "REG_SZ";
        case REG_EXPAND_SZ:  return "REG_EXPAND_SZ";
        case REG_BINARY:     return "REG_BINARY";
        case REG_DWORD:      return "REG_DWORD";
        case REG_QWORD:      return "REG_QWORD";
        case REG_MULTI_SZ:   return "REG_MULTI_SZ";
        case REG_NONE:       return "REG_NONE";
        default:             return "UNKNOWN";
    }
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    /* Extract arguments: subkey path and (optional) value name */
    char* subKey   = BeaconDataExtract(&parser, NULL);
    char* valName  = BeaconDataExtract(&parser, NULL);

    if (subKey == NULL) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: bof_regquery <SubKeyPath> [ValueName]");
        return;
    }

    /* Open the registry key under HKLM (most common for enumeration) */
    HKEY hKey = NULL;
    LONG status = ADVAPI32$RegOpenKeyExA(
        HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey);

    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "RegOpenKeyExA failed for HKLM\\%s (error %d)", subKey, status);
        return;
    }

    formatp buffer;
    BeaconFormatAlloc(&buffer, 8192);
    BeaconFormatPrintf(&buffer, "Registry: HKLM\\%s\n\n", subKey);

    if (valName != NULL && valName[0] != '\0') {
        /* Query a specific value */
        BYTE data[1024] = {0};
        DWORD dataSize = sizeof(data);
        DWORD type = 0;

        status = ADVAPI32$RegQueryValueExA(
            hKey, valName, NULL, &type, data, &dataSize);

        if (status == ERROR_SUCCESS) {
            BeaconFormatPrintf(&buffer, "  Value: %s\n", valName);
            BeaconFormatPrintf(&buffer, "  Type:  %s\n", RegTypeToString(type));

            switch (type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    BeaconFormatPrintf(&buffer, "  Data:  %s\n", (char*)data);
                    break;
                case REG_DWORD:
                    BeaconFormatPrintf(&buffer, "  Data:  0x%08X (%u)\n",
                                       *(DWORD*)data, *(DWORD*)data);
                    break;
                case REG_QWORD:
                    BeaconFormatPrintf(&buffer, "  Data:  0x%016llX\n",
                                       *(UINT64*)data);
                    break;
                case REG_BINARY:
                    BeaconFormatPrintf(&buffer, "  Data:  (%d bytes) ", dataSize);
                    for (DWORD i = 0; i < dataSize && i < 64; i++)
                        BeaconFormatPrintf(&buffer, "%02X ", data[i]);
                    if (dataSize > 64)
                        BeaconFormatPrintf(&buffer, "...");
                    BeaconFormatPrintf(&buffer, "\n");
                    break;
                default:
                    BeaconFormatPrintf(&buffer, "  Data:  (%d bytes)\n", dataSize);
                    break;
            }
        } else {
            BeaconFormatPrintf(&buffer, "  Value '%s' not found (error %d)\n",
                               valName, status);
        }
    } else {
        /* Enumerate all values in the key */
        BeaconFormatPrintf(&buffer, "%-30s %-15s %s\n",
                           "Value Name", "Type", "Data");
        BeaconFormatPrintf(&buffer,
            "------------------------------ --------------- "
            "--------------------------------\n");

        for (DWORD idx = 0; ; idx++) {
            char  valueName[256] = {0};
            DWORD nameLen = sizeof(valueName);
            BYTE  data[1024] = {0};
            DWORD dataSize = sizeof(data);
            DWORD type = 0;

            status = ADVAPI32$RegEnumValueA(
                hKey, idx, valueName, &nameLen,
                NULL, &type, data, &dataSize);

            if (status == ERROR_NO_MORE_ITEMS) break;
            if (status != ERROR_SUCCESS) continue;

            /* Format the value based on type */
            BeaconFormatPrintf(&buffer, "%-30s %-15s ",
                               valueName, RegTypeToString(type));

            switch (type) {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    BeaconFormatPrintf(&buffer, "%s", (char*)data);
                    break;
                case REG_DWORD:
                    BeaconFormatPrintf(&buffer, "0x%08X", *(DWORD*)data);
                    break;
                case REG_QWORD:
                    BeaconFormatPrintf(&buffer, "0x%016llX", *(UINT64*)data);
                    break;
                default:
                    BeaconFormatPrintf(&buffer, "(%d bytes)", dataSize);
                    break;
            }
            BeaconFormatPrintf(&buffer, "\n");
        }
    }

    /* Send output and cleanup */
    int outputLen = BeaconFormatLength(&buffer);
    char* outputData = BeaconFormatOriginal(&buffer);
    BeaconOutput(CALLBACK_OUTPUT, outputData, outputLen);

    BeaconFormatFree(&buffer);
    ADVAPI32$RegCloseKey(hKey);
}
```

## Compilation Guide

```bash
# =====================================================================
# BOFs are compiled as OBJECT FILES ONLY -- never linked into an EXE.
# The .o / .obj file IS the BOF. A COFF loader handles the "linking."
# =====================================================================

# ----- MinGW (Linux cross-compile or Windows MSYS2) -----

# x64 BOF:
x86_64-w64-mingw32-gcc -c -o bof_processlist.o bof_processlist.c

# x86 BOF:
i686-w64-mingw32-gcc -c -o bof_processlist_x86.o bof_processlist.c

# With optimizations (smaller output):
x86_64-w64-mingw32-gcc -c -O2 -o bof_processlist.o bof_processlist.c

# ----- MSVC (Visual Studio Developer Command Prompt) -----

# x64 BOF:
cl.exe /c /GS- /O2 bof_processlist.c
# Output: bof_processlist.obj

# /c   = compile only, do not link
# /GS- = disable stack buffer overrun checks (no CRT dependency)
# /O2  = optimize for speed

# ----- Verify the output is a valid COFF object -----

# Check with dumpbin (MSVC tool):
dumpbin /headers bof_processlist.obj
# Should show: machine (x64), number of sections, symbol table

# Check with objdump (MinGW/binutils):
x86_64-w64-mingw32-objdump -h bof_processlist.o
# Should show .text, .data, .rdata sections

# Check with file (Linux):
file bof_processlist.o
# Should output: "Intel amd64 COFF object file"
```

## Common BOF Development Mistakes

1. **Using CRT functions**: `printf`, `malloc`, `strlen`, `memcpy` -- these require the C
   runtime library which is not available in a BOF. Use Beacon APIs for output. For memory,
   use `KERNEL32$HeapAlloc`/`KERNEL32$HeapFree` or `KERNEL32$VirtualAlloc`. For string
   operations, use `MSVCRT$strlen` via DFR (the loader can resolve msvcrt.dll exports).

2. **Forgetting `pe32.dwSize = sizeof(...)`**: The ToolHelp32 API requires you to set the
   `dwSize` field before calling `Process32First`. Forgetting this causes silent failure.

3. **Wrong function signatures**: If your DFR declaration has a different signature than the
   actual Windows API function, the calling convention mismatch will corrupt the stack. Always
   copy the exact signature from the Windows SDK headers.

4. **Buffer overflows**: BOFs run in-process. A buffer overflow in a BOF corrupts the host
   process (Beacon) and may crash it. Always bounds-check.

5. **Not compiling with `/GS-`**: MSVC's `/GS` flag inserts stack canary checks that call
   `__security_check_cookie` -- a CRT function. Without `/GS-`, the compiled object will
   have an unresolvable external symbol and the loader will fail.

6. **Forgetting to close handles**: Since BOFs run in the C2 process, leaked handles
   accumulate and can cause resource exhaustion over time.
