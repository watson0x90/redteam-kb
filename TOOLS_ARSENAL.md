# Red Team Tools Arsenal

> A consolidated quick-reference for offensive security tools, organized by operational category. Designed for rapid lookup during engagements and study.

---

## 1. Reconnaissance & OSINT

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Nmap** | Industry-standard network scanner with scripting engine (NSE) for service/version detection and vuln scanning | Port scanning, service enumeration, OS fingerprinting | Cross-platform | https://nmap.org |
| **Masscan** | Asynchronous TCP port scanner capable of scanning the entire internet in under 6 minutes | High-speed large-scale port scanning | Cross-platform | https://github.com/robertdavidgraham/masscan |
| **Amass** | OWASP project for attack surface mapping via DNS enumeration, scraping, and API integrations | Subdomain discovery, external asset enumeration | Cross-platform | https://github.com/owasp-amass/amass |
| **Subfinder** | Fast passive subdomain enumeration tool using multiple online sources and API keys | Passive subdomain discovery at scale | Cross-platform | https://github.com/projectdiscovery/subfinder |
| **theHarvester** | Gathers emails, subdomains, IPs, and URLs from multiple public data sources | OSINT collection on target organization | Cross-platform (Python) | https://github.com/laramies/theHarvester |
| **Shodan** | Search engine for internet-connected devices, indexes banners, certs, and service metadata | Finding exposed services, IoT devices, misconfigurations | Web / CLI | https://www.shodan.io |
| **Censys** | Internet-wide scan data search engine with certificate and host intelligence | TLS certificate recon, exposed service discovery | Web / CLI | https://censys.io |
| **SpiderFoot** | Automated OSINT framework that queries 200+ data sources and correlates results into a graph | Comprehensive automated OSINT on targets | Cross-platform (Python) | https://github.com/smicallef/spiderfoot |
| **Recon-ng** | Modular web reconnaissance framework written in Python with a Metasploit-like interface | Structured OSINT workflow with reusable modules | Cross-platform (Python) | https://github.com/lanmaster53/recon-ng |
| **GRE Tunnel Scanner** | PoC tool for discovering stateless GRE tunnel configurations via forged ICMP-encapsulated packets | Network infrastructure initial access without credentials or phishing | Cross-platform | https://github.com/123ojp/GRE-Tunnel-Scanner |
| **VXLAN Tunnel Scanner** | Exploits default Linux kernel/MikroTik "Learning Mode" vulnerability in VXLAN tunnels for initial access; companion to GRE Tunnel Scanner; presented at Black Hat USA 2025, DEF CON 33, HITCON 2025 | VXLAN tunnel exploitation for initial access | Cross-platform | https://github.com/123ojp/vxlan-scanner |

---

## 2. Active Directory

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **BloodHound** | Graph-based AD relationship visualizer that maps attack paths to high-value targets | AD attack path analysis, privilege escalation mapping | Cross-platform | https://github.com/BloodHoundAD/BloodHound |
| **SharpHound** | Official BloodHound data collector; queries AD via LDAP, SMB, and RPC to build the graph database | AD data ingestion for BloodHound | Windows | https://github.com/BloodHoundAD/SharpHound |
| **PowerView** | PowerShell-based AD enumeration toolkit (part of PowerSploit) for querying domain objects | AD enumeration: users, groups, GPOs, trusts, ACLs | Windows (PowerShell) | https://github.com/PowerShellMafia/PowerSploit |
| **ADModule** | Microsoft-signed ActiveDirectory PowerShell module usable without RSAT installation | Stealthy AD enumeration using a signed Microsoft DLL | Windows (PowerShell) | https://github.com/samratashok/ADModule |
| **Rubeus** | C# toolset for raw Kerberos interaction and abuse | Kerberoasting, AS-REP roasting, ticket manipulation, delegation abuse | Windows | https://github.com/GhostPack/Rubeus |
| **Certify** | C# tool to enumerate and abuse Active Directory Certificate Services (AD CS) misconfigurations | Find vulnerable certificate templates, request certs for privilege escalation | Windows | https://github.com/GhostPack/Certify |
| **Whisker** | C# tool to manipulate the msDS-KeyCredentialLink attribute for Shadow Credentials attacks | Shadow Credentials attack for NTLM hash or TGT acquisition | Windows | https://github.com/eladshamir/Whisker |
| **PingCastle** | AD security auditing tool that generates a risk score and report on domain health | AD security posture assessment, quick wins identification | Windows | https://www.pingcastle.com |
| **ADExplorer** | Sysinternals LDAP browser and snapshot tool for Active Directory | Browse AD objects live, take offline snapshots for later analysis | Windows | https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer |
| **ldapdomaindump** | Python tool that dumps AD information via LDAP into human-readable HTML/JSON/grep-friendly output | Quick AD dump of users, groups, computers, policies | Cross-platform (Python) | https://github.com/dirkjanm/ldapdomaindump |

---

## 3. Credential Access

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Mimikatz** | The definitive Windows credential extraction tool; reads LSASS, performs pass-the-hash, golden tickets, and more | Dump plaintext passwords, hashes, Kerberos tickets from memory | Windows | https://github.com/gentilkiwi/mimikatz |
| **Pypykatz** | Pure Python implementation of Mimikatz; parses LSASS minidumps, registry hives, and more without touching disk on target | Offline credential extraction from dumps, cross-platform analysis | Cross-platform (Python) | https://github.com/skelsec/pypykatz |
| **Impacket (secretsdump)** | Remotely dumps SAM, LSA secrets, cached credentials, and NTDS.dit via DRSUAPI or VSS | Remote credential dumping (DCSync, SAM, LSA) | Cross-platform (Python) | https://github.com/fortra/impacket |
| **LaZagne** | Retrieves stored passwords from browsers, mail clients, Wi-Fi, databases, sysadmin tools, and more | Local password recovery from installed applications | Cross-platform (Python) | https://github.com/AlessandroZ/LaZagne |
| **SharpDPAPI** | C# port of DPAPI-related Mimikatz functionality for decrypting DPAPI-protected blobs | Decrypt credentials, browser data, and vaults protected by DPAPI | Windows | https://github.com/GhostPack/SharpDPAPI |
| **NanoDump** | Stealthy LSASS minidump tool using syscalls, avoiding API hooks; supports multiple dump methods | Dump LSASS with minimal detection footprint | Windows | https://github.com/helpsystems/nanodump |
| **SafetyKatz** | Combines minidump of LSASS with an in-memory Mimikatz parse; avoids dropping Mimikatz to disk | In-memory LSASS credential extraction | Windows | https://github.com/GhostPack/SafetyKatz |
| **KeeThief** | Extracts KeePass 2.x master key material from memory | Steal KeePass database master keys from running processes | Windows | https://github.com/GhostPack/KeeThief |
| **Internal-Monologue** | Retrieves NTLM hashes without touching LSASS by downgrading and intercepting local NTLM auth | Covert NTLM hash extraction via SSP manipulation | Windows | https://github.com/eladshamir/Internal-Monologue |

---

## 4. Exploitation & Initial Access

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Metasploit** | Full-featured exploitation framework with 2000+ exploits, payloads, encoders, and post modules | Exploit development, payload delivery, post-exploitation | Cross-platform | https://github.com/rapid7/metasploit-framework |
| **Cobalt Strike** | Commercial adversary simulation platform with a robust Beacon payload and malleable C2 profiles | Red team operations, phishing, C2, lateral movement | Windows / Cross-platform (teamserver) | https://www.cobaltstrike.com |
| **GoPhish** | Open-source phishing framework with campaign management, email templates, and tracking | Phishing simulations, social engineering campaigns | Cross-platform | https://github.com/gophish/gophish |
| **Evilginx2** | Man-in-the-middle reverse proxy that captures credentials and session tokens bypassing MFA | Phishing with real-time session hijacking and MFA bypass | Cross-platform | https://github.com/kgretzky/evilginx2 |
| **SQLMap** | Automated SQL injection detection and exploitation tool with database takeover capabilities | SQL injection testing, database extraction, OS command exec | Cross-platform (Python) | https://github.com/sqlmapproject/sqlmap |
| **Burp Suite** | Integrated web application security testing platform with proxy, scanner, and extensibility | Web app testing, intercepting/modifying HTTP traffic | Cross-platform (Java) | https://portswigger.net/burp |
| **Ruler** | Exchange/Outlook abuse tool via MAPI/RPC; creates malicious rules, injects forms, sets home pages | Outlook persistence via rules (T1137.005), forms (T1137.003), and home pages (T1137.004) | Cross-platform (Go) | https://github.com/sensepost/ruler |
| **Certipy v5** | AD CS enumeration and exploitation tool supporting ESC1-ESC16, shadow credentials, and certificate auth | ADCS attacks including new ESC13-ESC16 vectors | Cross-platform (Python) | https://github.com/ly4k/Certipy |
| **Certify 2.0** | C# tool for AD CS enumeration and certificate request abuse; supports ESC1-ESC16 | ADCS template/CA enumeration and exploitation from Windows | Windows (.NET) | https://github.com/GhostPack/Certify |
| **DumpGuard** | Extracts NTLMv1 hashes via Remote Credential Guard protocol without LSASS access | Credential Guard bypass, NTLM hash extraction | Windows | https://github.com/bytewreck/DumpGuard |
| **RelayKing** | Comprehensive NTLM relay enumeration tool; scans 20K+ hosts for relay attack surfaces | NTLM relay reconnaissance and CVE-2025-33073 detection | Cross-platform (Python) | https://github.com/DepthSecurity/RelayKing |
| **Swarmer** | Registry persistence via offline hive manipulation (NTUSER.MAN); zero ETW telemetry | Stealthy registry persistence bypassing all monitoring | Windows | https://github.com/praetorian-inc/swarmer |
| **AdaptixC2** | Open-source C2 framework with Golang server, C++ QT GUI, SOCKS5, and BOF Extension-Kit | Post-exploitation C2 operations | Cross-platform | https://github.com/nicosec/AdaptixC2 |
| **Evilginx Pro** | Premium AiTM framework with rewritten proxy engine, Safe Browsing evasion, and advanced phishlet creation | Red team AiTM phishing operations with MFA bypass | Cross-platform | https://breakdev.org/evilginx-pro/ |
| **EvilWorker** | Service worker-based AiTM framework; no per-target phishlet config needed; fully autonomous interception | Novel AiTM phishing via browser service workers | Cross-platform | https://github.com/ahaz1701/EvilWorker |
| **EvilNoVNC** | Browser-based remote desktop phishing via noVNC; streams real browser session to victim; bypasses all MFA including FIDO2 | AiTM phishing that defeats hardware security keys | Cross-platform | https://github.com/JoelGMSec/EvilnoVNC |
| **SquarePhish2** | OAuth device code phishing toolkit with automatic redirect, QR code support, and Microsoft token polling | Device code flow phishing for M365 initial access | Cross-platform (Python) | https://github.com/nromsdahl/SquarePhish2 |
| **AITMWorker** | Cloudflare Workers as a serverless AiTM proxy; zero-cost, trusted CDN infrastructure, ephemeral execution with minimal forensic footprint | Serverless AiTM phishing via Cloudflare Workers | Cross-platform | https://github.com/zolderio/AITMWorker |

---

## 5. Lateral Movement

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Impacket psexec** | Python implementation of PsExec; creates a service on the remote host for command execution | Remote command execution via SMB service creation | Cross-platform (Python) | https://github.com/fortra/impacket |
| **Impacket smbexec** | Semi-interactive shell via SMB; uses a service but avoids dropping a binary on disk | Fileless remote command execution over SMB | Cross-platform (Python) | https://github.com/fortra/impacket |
| **Impacket wmiexec** | Remote command execution via WMI (DCOM); stealthier than psexec-style approaches | Semi-interactive shell via WMI | Cross-platform (Python) | https://github.com/fortra/impacket |
| **Impacket atexec** | Executes commands via the Windows Task Scheduler service remotely | One-shot remote command execution via scheduled tasks | Cross-platform (Python) | https://github.com/fortra/impacket |
| **CrackMapExec / NetExec** | Swiss-army knife for pentesting networks; supports SMB, LDAP, WinRM, MSSQL, SSH protocols | Credential spraying, command exec, enumeration across protocols | Cross-platform (Python) | https://github.com/Pennyw0rth/NetExec |
| **Evil-WinRM** | WinRM shell with file upload/download, in-memory PS module loading, and AMSI bypass | Interactive PowerShell access over WinRM (port 5985/5986) | Cross-platform (Ruby) | https://github.com/Hackplayers/evil-winrm |
| **Chisel** | Fast TCP/UDP tunnel over HTTP secured via SSH; single binary, no dependencies | Pivoting through firewalled networks, port forwarding | Cross-platform (Go) | https://github.com/jpillora/chisel |
| **Ligolo-ng** | Advanced tunneling tool using a TUN interface; no SOCKS overhead, feels like a VPN | Creating reverse tunnels for seamless network pivoting | Cross-platform (Go) | https://github.com/nicocha30/ligolo-ng |

---

## 6. C2 Frameworks

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Cobalt Strike** | Industry-standard commercial C2 with Beacon implant, malleable profiles, and BOF support | Full-spectrum red team C2 operations | Windows / Linux (teamserver) | https://www.cobaltstrike.com |
| **Sliver** | Open-source C2 by BishopFox; supports mTLS, WireGuard, HTTP(S), DNS C2 channels with implant generation | Modern open-source alternative to Cobalt Strike | Cross-platform (Go) | https://github.com/BishopFox/sliver |
| **Mythic** | Modular, multi-agent C2 platform with a web UI, Docker-based deployment, and community agents | Flexible multi-payload C2 with collaborative features | Cross-platform (Docker) | https://github.com/its-a-feature/Mythic |
| **Havoc** | Modern C2 framework with a Qt-based GUI, Demon agent, and extensible via Python/C modules | Feature-rich free C2 with a polished interface | Cross-platform | https://github.com/HavocFramework/Havoc |
| **Brute Ratel** | Commercial C2 designed to evade modern EDR/AV; uses syscalls and advanced evasion by default | Evasion-focused adversary simulation | Windows / Linux | https://bruteratel.com |
| **PoshC2** | Proxy-aware C2 framework with PowerShell, C#, and Python implants | C2 with multiple implant types and reporting | Cross-platform (Python) | https://github.com/nettitude/PoshC2 |
| **Covenant** | .NET-based C2 with a web interface, Grunt implants, and task-based interaction model | .NET-focused C2 operations with collaborative UI | Cross-platform (.NET) | https://github.com/cobbr/Covenant |

---

## 7. Defense Evasion

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **ScareCrow** | Payload creation framework that uses code signing, EDR unhooking, and loader techniques to bypass AV/EDR | Generating evasive shellcode loaders with signed binaries | Cross-platform (Go) | https://github.com/optiv/ScareCrow |
| **Nimcrypt2** | Nim-based packer/crypter using syscalls, unhooking, and sandboxing evasion | Encrypting and packing PE payloads for AV/EDR bypass | Windows (Nim) | https://github.com/icyguider/Nimcrypt2 |
| **donut** | Generates position-independent shellcode from .NET assemblies, PE files, and DLLs | Converting executables into injectable shellcode | Cross-platform | https://github.com/TheWover/donut |
| **sRDI** | Shellcode Reflective DLL Injection - converts any DLL to position-independent shellcode with a reflective loader prepended | Converting existing DLLs into injectable shellcode without recompilation; enables reflective loading of arbitrary DLLs via shellcode | Windows (Python + C) | https://github.com/monoxgas/sRDI |
| **SharpUnhooker** | C# tool that unhooks ntdll.dll by replacing the hooked copy with a clean one from disk or KnownDLLs | Removing EDR userland API hooks from the current process | Windows | https://github.com/GetRektBoy724/SharpUnhooker |
| **SysWhispers** | Generates header/ASM pairs for direct system calls, bypassing ntdll.dll hooks entirely | Direct syscall stub generation to evade API monitoring | Windows | https://github.com/jthuraisamy/SysWhispers |
| **HellsGate** | Runtime syscall number resolver that dynamically resolves SSNs from ntdll, avoiding hardcoded values | Dynamic direct syscall resolution for evasion | Windows | https://github.com/am0nsec/HellsGate |

---

## 8. Post-Exploitation & Privilege Escalation

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Seatbelt** | C# host-survey tool that runs security-relevant checks (credentials, configs, protections) | Windows host situational awareness and data collection | Windows | https://github.com/GhostPack/Seatbelt |
| **SharpUp** | C# port of PowerUp; checks for common Windows privilege escalation vectors | Windows privilege escalation enumeration | Windows | https://github.com/GhostPack/SharpUp |
| **winPEAS** | Comprehensive Windows privilege escalation enumeration script (colors, detailed output) | Automated Windows privesc vector discovery | Windows | https://github.com/peass-ng/PEASS-ng |
| **linPEAS** | Comprehensive Linux/macOS privilege escalation enumeration script | Automated Linux/macOS privesc vector discovery | Linux / macOS | https://github.com/peass-ng/PEASS-ng |
| **PEASS-ng** | Umbrella project containing winPEAS, linPEAS, and other privilege escalation tools | Cross-platform privilege escalation suite | Cross-platform | https://github.com/peass-ng/PEASS-ng |
| **PowerUp** | PowerShell script for finding common Windows privilege escalation misconfigurations | Service misconfigs, unquoted paths, DLL hijacking checks | Windows (PowerShell) | https://github.com/PowerShellMafia/PowerSploit |
| **PrivescCheck** | Modern PowerShell privilege escalation enumeration script; successor approach to PowerUp | Thorough Windows privesc checks with structured output | Windows (PowerShell) | https://github.com/itm4n/PrivescCheck |

---

## 9. Cloud Security

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Prowler** | AWS/Azure/GCP security assessment tool aligned with CIS benchmarks and multiple compliance frameworks | Multi-cloud security posture auditing | Cross-platform (Python) | https://github.com/prowler-cloud/prowler |
| **ScoutSuite** | Multi-cloud security auditing tool that generates an interactive HTML report from API data | AWS, Azure, GCP, Alibaba, and Oracle Cloud security review | Cross-platform (Python) | https://github.com/nccgroup/ScoutSuite |
| **CloudFox** | Enumerates attack paths in cloud infrastructure by analyzing IAM, networking, and secrets | Finding exploitable cloud misconfigurations and attack paths | Cross-platform (Go) | https://github.com/BishopFox/CloudFox |
| **Pacu** | AWS exploitation framework modeled after Metasploit with modules for enumeration and exploitation | AWS-specific offensive security testing | Cross-platform (Python) | https://github.com/RhinoSecurityLabs/pacu |
| **ROADtools** | Framework for interacting with Azure AD (Entra ID) via the internal ROADrecon and ROADlib components | Azure AD enumeration, token manipulation, data gathering | Cross-platform (Python) | https://github.com/dirkjanm/ROADtools |
| **AADInternals** | PowerShell module for Azure AD and M365 administration and red teaming | Azure AD exploitation, tenant recon, token theft, federation abuse | Windows (PowerShell) | https://github.com/Gerenios/AADInternals |
| **MicroBurst** | PowerShell toolkit for Azure service enumeration, access checks, and post-exploitation | Azure storage, key vault, and service abuse | Windows (PowerShell) | https://github.com/NetSPI/MicroBurst |
| **StormSpotter** | Creates an attack graph of Azure and Azure AD resources for visual path analysis | Azure resource relationship mapping | Cross-platform (Python) | https://github.com/Azure/Stormspotter |
| **Gato** | GitHub Actions enumeration and attack tool for CI/CD pipeline compromise | GitHub Actions self-hosted runner exploitation, secret extraction | Cross-platform (Python) | https://github.com/praetorian-inc/gato |
| **EntraFalcon** | PowerShell tool for Entra ID security assessment; enumerates users, groups, PIM-eligible roles, app registrations with scoring model | Entra ID enumeration and risk assessment for Azure red team recon | Cross-platform (PowerShell) | https://github.com/CompassSecurity/EntraFalcon |
| **AzureStrike** | HTA-based Azure AD offensive toolkit for red team simulations; recon, persistence, credential abuse, vulnerable Function deployment | Azure/Entra ID attack simulation covering full attack chain | Windows | https://github.com/dmcxblue/AzureStrike |
| **CloudConqueror** | Python tool exploiting AWS CloudControl API for offensive operations; resource listing, bruteforce, persistence creation | AWS CloudControl API attack surface mapping and persistence | Cross-platform (Python) | https://github.com/ExaForce/CloudConqueror |
| **XRayC2** | Serverless C2 framework using AWS X-Ray APIs as covert communication channel; encodes commands in trace segments | Cloud-native C2 via AWS X-Ray telemetry | Cross-platform (Python) | https://github.com/RootUp/XRayC2 |
| **Stratus Red Team** | Atomic Red Team for the cloud; emulates offensive techniques against live AWS, Azure, K8s, GCP environments with MITRE mapping | Cloud adversary emulation and detection validation | Cross-platform (Go) | https://github.com/DataDog/stratus-red-team |
| **AWSDoor** | Comprehensive AWS persistence automation; IAM keys, trust policy backdoors, Lambda layers, CloudTrail suppression, S3 lifecycle abuse | AWS persistence operations across IAM, Lambda, EC2, S3 | Cross-platform (Python) | https://github.com/Wavestone-RiskInsight/AWSDoor |
| **P0LR Espresso** | Cloud log normalization tool for threat response; unifies AWS, GCP, Azure, and SaaS logs into one schema; normalizes fields for P0 live response | Cloud log normalization for unified threat response | Cross-platform (Python) | https://github.com/Permiso-io-tools/p0lr-espresso |
| **CloudGoat** | Updated CloudGoat scenarios featuring vulnerable Lambda function attack paths; hands-on serverless exploitation training for AWS environments | AWS serverless exploitation training and attack path simulation | Cross-platform (Python) | https://github.com/RhinoSecurityLabs/cloudgoat |
| **AzureHound** | BloodHound extension for Azure AD; maps roles, group memberships, and privilege escalation paths via Graph API | Azure AD attack path analysis and privilege escalation mapping | Cross-platform | *Bishop Fox 2025 Red Team Tools Compendium* |
| **GraphRunner** | Fast Graph API querying from PowerShell for Azure AD exploration | Azure AD enumeration via Microsoft Graph API | Windows (PowerShell) | *Bishop Fox 2025 Red Team Tools Compendium* |
| **Azucar** | PowerShell-based Azure environment security auditor; enumerates storage accounts, VMs, web apps, SQL, Key Vaults, RBAC, and network configurations | Azure security posture assessment and resource enumeration | Windows (PowerShell) | https://github.com/nccgroup/azucar |
| **CursedChrome** | Real-time browser session hijacking for post-exploitation | Browser session hijacking and credential theft | Cross-platform | *Bishop Fox 2025 Red Team Tools Compendium* |

---

## 9a. AI Offensive Tools

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **PentAGI** | Automated security testing platform with autonomous AI agent using 20+ pentesting tools (nmap, Metasploit, Sqlmap) | AI-driven autonomous penetration testing | Cross-platform | PentAGI |
| **Deadend CLI** | Autonomous agent using self-correction to bypass security blocks; reads error responses and writes custom Python to evade defenses | AI-powered adaptive defense evasion | Cross-platform | Deadend CLI |
| **HexStrike AI** | MCP server connecting LLMs to 150+ security tools; enables AI agents to autonomously run penetration tests | LLM-integrated autonomous penetration testing | Cross-platform | HexStrike AI |
| **Strix** | Autonomous security testing system with AI agents that behave like human attackers; runs code in real conditions with PoC exploit verification | Autonomous AI-driven attack simulation with exploit verification | Cross-platform | Strix |
| **CAI** | Cybersecurity AI; open-source framework for building AI-powered offensive and defensive security agents | Building AI-powered offensive and defensive security agents | Cross-platform | CAI |

---

## 10. Password Cracking

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Hashcat** | World's fastest GPU-accelerated password recovery tool supporting 350+ hash types | Cracking hashes using GPU power with rules, masks, and combinator attacks | Cross-platform | https://hashcat.net/hashcat |
| **John the Ripper** | Venerable CPU-based password cracker with auto-detection and community-enhanced (Jumbo) version | CPU hash cracking, format auto-detection, custom rules | Cross-platform | https://github.com/openwall/john |
| **CeWL** | Custom wordlist generator that spiders a target website to build organization-specific word lists | Creating target-specific wordlists from web content | Cross-platform (Ruby) | https://github.com/digininja/CeWL |
| **CUPP** | Common User Password Profiler; generates candidate passwords from personal info about a target | Creating targeted wordlists from OSINT about an individual | Cross-platform (Python) | https://github.com/Mebus/cupp |
| **Mentalist** | GUI-based wordlist generation tool with chaining rules, substitutions, and append/prepend logic | Visual wordlist crafting for complex password policies | Cross-platform (Python) | https://github.com/sc0tfree/mentalist |

---

## 11. Network Attack & Analysis

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Responder** | LLMNR/NBT-NS/mDNS poisoner that captures NTLMv1/v2 hashes on the local network | Capturing credentials via name resolution poisoning | Cross-platform (Python) | https://github.com/lgandx/Responder |
| **ntlmrelayx** | Impacket tool that relays captured NTLM authentication to other services (SMB, LDAP, HTTP, MSSQL) | NTLM relay attacks for credential forwarding and code execution | Cross-platform (Python) | https://github.com/fortra/impacket |
| **mitm6** | Exploits IPv6 DNS takeover via DHCPv6 to perform man-in-the-middle attacks paired with ntlmrelayx | IPv6-based NTLM relay attacks in IPv4-only networks | Cross-platform (Python) | https://github.com/dirkjanm/mitm6 |
| **PetitPotam** | Coerces Windows hosts to authenticate to an attacker via MS-EFSRPC abuse | NTLM authentication coercion for relay attacks (e.g., AD CS ESC8) | Cross-platform (Python) | https://github.com/topotam/PetitPotam |
| **Coercer** | Comprehensive tool that uses multiple RPC methods to coerce Windows authentication | Automated authentication coercion across many MS-RPC protocols | Cross-platform (Python) | https://github.com/p0dalirius/Coercer |
| **Wireshark** | The premier GUI-based network protocol analyzer with deep packet inspection | Live traffic capture, protocol analysis, forensic investigation | Cross-platform | https://www.wireshark.org |
| **tcpdump** | Command-line packet capture and analysis tool; lightweight and ubiquitous on Linux | CLI packet capture, traffic filtering, pcap generation | Linux / macOS | https://www.tcpdump.org |

---

## 12. Utility & Tunneling

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Chisel** | HTTP-based tunnel using SSH under the hood; single binary client/server for fast pivoting | TCP/UDP tunneling through HTTP, SOCKS5 proxy | Cross-platform (Go) | https://github.com/jpillora/chisel |
| **proxychains** | Forces TCP connections through SOCKS4/5 or HTTP proxies for any dynamically linked program | Routing tools through tunnels and proxies transparently | Linux | https://github.com/haad/proxychains |
| **socat** | Multipurpose relay tool for bidirectional data transfer between two data channels | Port forwarding, reverse shells, encrypted relays, file transfer | Linux / macOS | http://www.dest-unreach.org/socat |
| **PowerShell Empire** | Post-exploitation agent and C2 framework with PowerShell, C#, and Python agents (now Starkiller GUI) | Post-exploitation automation, credential harvesting, persistence | Cross-platform (Python) | https://github.com/BC-SECURITY/Empire |
| **Covenant** | .NET-based collaborative C2 platform with a web interface and Grunt implants | .NET C2 with task-based agent management and team collaboration | Cross-platform (.NET) | https://github.com/cobbr/Covenant |
| **sshuttle** | Transparent VPN-like proxy over SSH; routes traffic through SSH connection without SOCKS | SSH-based VPN alternative, subnet routing | Linux / macOS (Python) | https://github.com/sshuttle/sshuttle |
| **iodine** | DNS tunneling tool; tunnels IPv4 data through DNS queries when firewalls block other traffic | DNS tunnel for firewall bypass | Cross-platform | https://github.com/yarrick/iodine |
| **dnscat2** | Command-and-control via DNS tunnel with encryption; interactive shell over DNS | DNS-based C2 and tunneling | Cross-platform (Ruby/C) | https://github.com/iagox86/dnscat2 |
| **Neo-reGeorg** | HTTP/S tunneling via web shell; successor to reGeorg with encrypted SOCKS proxy support | Web shell-based pivoting through HTTP | Cross-platform (Python) | https://github.com/L-codes/Neo-reGeorg |

---

## 13. Container & Kubernetes

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Peirates** | Kubernetes penetration testing tool; automates SA token abuse, secret extraction, pod exec, pivot attacks | Kubernetes cluster exploitation from compromised pod | Cross-platform (Go) | https://github.com/inguardians/peirates |
| **KubeHound** | Kubernetes attack graph tool that maps privilege escalation paths in clusters | K8s attack path analysis and RBAC abuse identification | Cross-platform | https://github.com/DataDog/KubeHound |
| **BOtB (Break out the Box)** | Container escape and post-exploitation tool; checks for privileged mode, Docker socket, CVE-2019-5736 | Automated container escape detection and exploitation | Linux (Go) | https://github.com/brompwnie/botb |
| **deepce** | Docker enumeration, escalation, and breakout tool; checks for common container misconfigurations | Docker container security assessment | Linux (Shell) | https://github.com/stealthcopter/deepce |
| **CDK** | Container penetration toolkit with exploit modules for container escapes and K8s attacks | Comprehensive container/K8s exploitation | Linux (Go) | https://github.com/cdk-team/CDK |
| **kube-hunter** | Kubernetes security tool that hunts for weaknesses in clusters | K8s vulnerability scanning and enumeration | Cross-platform (Python) | https://github.com/aquasecurity/kube-hunter |
| **kubectl-who-can** | kubectl plugin showing RBAC subjects with specified permissions in a cluster | K8s RBAC enumeration and privilege mapping | Cross-platform (Go) | https://github.com/aquasecurity/kubectl-who-can |

---

## 14. Web Application Testing

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **Burp Suite** | Integrated web application security testing platform with proxy, scanner, and extensibility | Web app testing, intercepting/modifying HTTP traffic | Cross-platform (Java) | https://portswigger.net/burp |
| **SQLMap** | Automated SQL injection detection and exploitation with database takeover capabilities | SQL injection testing and database extraction | Cross-platform (Python) | https://github.com/sqlmapproject/sqlmap |
| **Nuclei** | Fast template-based vulnerability scanner with community-maintained templates | Automated vulnerability detection at scale | Cross-platform (Go) | https://github.com/projectdiscovery/nuclei |
| **ffuf** | Fast web fuzzer for directory/file discovery, parameter fuzzing, and virtual host enumeration | Web content discovery and parameter fuzzing | Cross-platform (Go) | https://github.com/ffuf/ffuf |
| **ysoserial** | Java deserialization exploit payload generator for multiple gadget chains | Java deserialization RCE exploitation | Java | https://github.com/frohoff/ysoserial |
| **jwt_tool** | JWT security testing toolkit; supports alg:none, key confusion, claim tampering, brute force | JWT vulnerability testing and exploitation | Cross-platform (Python) | https://github.com/ticarpi/jwt_tool |
| **tplmap** | Server-Side Template Injection automatic exploitation tool | SSTI detection and exploitation | Cross-platform (Python) | https://github.com/epinna/tplmap |
| **GraphQLmap** | GraphQL endpoint exploitation tool for introspection, injection, and brute-force | GraphQL security testing | Cross-platform (Python) | https://github.com/swisskyrepo/GraphQLmap |

---

## 15. Wireless & Physical

| Tool | Description | Primary Use | Platform | Link/Reference |
|------|-------------|-------------|----------|----------------|
| **aircrack-ng** | Complete WiFi security assessment suite: monitoring, attacking, testing, and cracking | WPA/WPA2 handshake capture and cracking | Linux | https://www.aircrack-ng.org |
| **hcxdumptool** | PMKID/handshake capture tool for WPA/WPA2; works without deauthentication | PMKID-based WiFi cracking (clientless) | Linux | https://github.com/ZerBea/hcxdumptool |
| **eaphammer** | WPA2-Enterprise evil twin attack framework; credential harvesting and GTC downgrade | Enterprise WiFi attacks and credential capture | Linux (Python) | https://github.com/s0lst1c3/eaphammer |
| **bettercap** | Swiss Army knife for network reconnaissance and MITM attacks; WiFi, BLE, HID modules | Network/WiFi/BLE MITM and reconnaissance | Cross-platform (Go) | https://github.com/bettercap/bettercap |
| **Proxmark3** | RFID/NFC research device for badge cloning, access control bypass, and protocol analysis | RFID badge cloning (HID iCLASS, MIFARE) | Cross-platform | https://github.com/RfidResearchGroup/proxmark3 |
| **Flipper Zero** | Multi-tool for pentesters: Sub-GHz, RFID, NFC, IR, iButton, BadUSB, GPIO | Physical security assessment multi-tool | Hardware device | https://flipperzero.one |
| **USB Rubber Ducky** | USB HID injection tool; executes DuckyScript payloads as keyboard input | HID-based keystroke injection attacks | Hardware device | https://hak5.org/products/usb-rubber-ducky |
| **O.MG Cable** | USB cable with hidden WiFi implant; remote keystroke injection, keylogging, geofencing | Covert HID attacks via normal-looking USB cable | Hardware device | https://o.mg.lol |
| **ESPKey** | Postage-stamp WiFi board for intercepting Wiegand data from RFID readers; installs inline on reader wires for remote badge capture | Long-range RFID badge capture (modern Tastic Thief) | Hardware device | https://github.com/rfidtool/ESP-RFID-Tool |
| **Frida** | Dynamic instrumentation toolkit for hooking functions at runtime in native and managed (.NET/Java) applications | Runtime function hooking, bypass security controls, credential interception | Cross-platform | https://frida.re |
| **Fermion** | Electron-based GUI wrapper for Frida; script management, module exploration, real-time output | User-friendly Frida interface for .NET/native hooking | Windows, macOS, Linux | https://github.com/FuzzySecurity/Fermion |
| **DirtyLittleDotNetHooker** | Identifies .NET function signatures (module, class, method, params) for constructing Frida hooks | .NET function enumeration for Frida hooking | Windows | https://github.com/watson0x90/DirtyLittleDotNetHooker |

---

## Quick Reference: Common Engagement Workflow

```
Recon          -->  Amass/Subfinder + Nmap/Masscan + Shodan
Initial Access -->  GoPhish/Evilginx2 or exploit via Metasploit/Burp
Execution      -->  Cobalt Strike / Sliver / Havoc (Beacon/Implant)
Credential     -->  Mimikatz / secretsdump / Rubeus (Kerberoast)
Lateral Move   -->  CrackMapExec + wmiexec/psexec + Evil-WinRM
Privesc        -->  Seatbelt + winPEAS/SharpUp + BloodHound
Persistence    -->  Golden/Silver tickets, scheduled tasks, registry
Exfil / C2     -->  DNS/HTTPS C2 channels via framework of choice
Pivoting       -->  Chisel / Ligolo-ng / SSH tunnels + ProxyChains
Container      -->  deepce + CDK + Peirates (K8s)
Web Apps       -->  Burp Suite + SQLMap + Nuclei + ffuf
Physical       -->  Proxmark3 + Flipper Zero + WiFi Pineapple
```

---

*This document is intended for authorized security testing and educational purposes only. Always obtain proper authorization before using these tools against any target.*
