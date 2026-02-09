# SNMP Enumeration

> **MITRE ATT&CK**: Reconnaissance > T1046 - Network Service Scanning
> **Platforms**: Network devices, Windows, Linux, printers, IoT
> **Required Privileges**: None (community string knowledge)
> **OPSEC Risk**: Low-Medium (SNMP queries are standard network management traffic)

## Strategic Overview

Simple Network Management Protocol is a goldmine that red teams frequently overlook. SNMP
exposes detailed system information -- installed software, running processes, network
interfaces, routing tables, ARP caches, user accounts, and system configurations -- all
accessible with nothing more than a community string. SNMPv1 and v2c transmit community
strings in cleartext, and default strings ("public", "private") remain shockingly common in
production environments, particularly on network devices (routers, switches, firewalls),
printers, and legacy systems. For the Red Team Lead, SNMP enumeration is a low-risk,
high-reward activity: the traffic blends with legitimate network management, and the
information gathered can map entire network topologies, reveal software versions for
vulnerability targeting, and even expose credentials stored in device configurations.
SNMPv3 with authentication and encryption is more secure but can still be brute-forced
if weak credentials are used.

## Technical Deep-Dive

### SNMP Version Overview

```
SNMPv1: Community string authentication (cleartext), no encryption
        - Default strings: public (read), private (read/write)
        - Most commonly found on legacy and embedded devices

SNMPv2c: Same as v1 but with bulk operations and improved error handling
         - Still uses cleartext community strings
         - Most prevalent version in enterprise environments

SNMPv3: Username/password authentication + optional encryption
        - Auth protocols: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512
        - Privacy protocols: DES, 3DES, AES-128, AES-192, AES-256
        - Three security levels: noAuthNoPriv, authNoPriv, authPriv
```

### Community String Discovery

```bash
# onesixtyone - fast community string brute-force
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
  -i target-hosts.txt

# Hydra SNMP community string brute-force
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
  10.10.10.50 snmp

# snmpbrute - comprehensive brute-force including v3
python3 snmpbrute.py -t 10.10.10.50

# Nmap SNMP brute-force script
nmap -sU -p 161 --script snmp-brute \
  --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt \
  10.10.10.0/24

# Metasploit community string scanner
use auxiliary/scanner/snmp/snmp_login
set RHOSTS 10.10.10.0/24
set COMMUNITY_FILE /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
run

# Common default community strings to always try manually
# public, private, community, manager, admin, default, snmp, monitor
```

### SNMP Walking and Data Extraction

```bash
# Full SNMP walk with v2c
snmpwalk -v2c -c public 10.10.10.50

# Walk specific OID trees
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.1       # System info
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.2       # Network interfaces
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.4       # IP configuration
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.4    # Running processes (Windows)
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.6    # Installed software (Windows)

# SNMPv3 walk with authentication
snmpwalk -v3 -l authPriv -u admin -a SHA -A 'AuthPass123' \
  -x AES -X 'PrivPass123' 10.10.10.50

# Bulk walk for faster enumeration (v2c/v3)
snmpbulkwalk -v2c -c public -Cr25 10.10.10.50
```

### Critical OIDs for Red Teams

```bash
# System Description (OS, version, hostname)
snmpget -v2c -c public 10.10.10.50 1.3.6.1.2.1.1.1.0    # sysDescr
snmpget -v2c -c public 10.10.10.50 1.3.6.1.2.1.1.5.0    # sysName

# User accounts (Windows)
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.4.1.77.1.2.25    # Domain users

# Network interfaces and IP addresses
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.2.2.1.2      # Interface names
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.4.20.1.1      # IP addresses

# Routing table
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.4.21.1        # IP routes

# ARP cache (discover adjacent hosts)
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.3.1.1.2       # ARP table

# TCP connections (active connections reveal services)
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.6.13          # TCP connections

# Running processes
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.4.2.1.2    # Process names
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.4.2.1.5    # Process paths

# Installed software (useful for vulnerability identification)
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.2.1.25.6.3.1.2    # Software names
```

### Automated SNMP Enumeration Tools

```bash
# snmp-check - structured output of all common OIDs
snmp-check -c public -v 2c 10.10.10.50

# Nmap SNMP scripts for targeted enumeration
nmap -sU -p 161 --script snmp-info,snmp-interfaces,snmp-netstat,\
snmp-processes,snmp-sysdescr,snmp-win32-software,snmp-win32-users 10.10.10.50

# Braa - mass SNMP scanner
braa public@10.10.10.50:.1.3.6.1.2.1.1.1
braa public@10.10.10.0/24:.1.3.6.1.2.1.1.1    # Scan entire subnet

# Enyx - SNMP IPv6 enumeration (extract IPv6 from SNMP)
python3 enyx.py 2c public 10.10.10.50
# Reveals IPv6 addresses that may bypass IPv4-only firewalls
```

### Extracting Credentials from SNMP

```bash
# Cisco devices may expose community strings and passwords
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.4.1.9    # Cisco private MIB tree

# SNMP write access with "private" community string
# Can modify device configuration, routing tables, ACLs
snmpset -v2c -c private 10.10.10.50 1.3.6.1.2.1.1.6.0 s "Modified by SNMP"

# Check for write access
snmpset -v2c -c private 10.10.10.50 1.3.6.1.2.1.1.4.0 s "test"
# Success = read-write community string found
```

## Detection & Evasion

### What Defenders See
- SNMP queries appear as standard UDP port 161 traffic
- Network management systems generate identical traffic patterns
- High-volume SNMP walks from unexpected source IPs may raise alerts
- Community string brute-force attempts generate multiple failed authentication logs
- SNMPv3 failed authentications are logged more reliably than v1/v2c failures

### Evasion Techniques
- SNMP traffic is inherently difficult to distinguish from legitimate network management
- Query from a host that could plausibly be a management station (jump box, admin workstation)
- Rate-limit community string brute-force to avoid triggering SNMP trap thresholds
- Target specific OIDs rather than performing full walks to reduce traffic volume
- Use SNMPv2c bulk operations to reduce the number of packets

### Defensive Recommendations
- Replace SNMPv1/v2c with SNMPv3 using authPriv security level
- Change default community strings on all devices
- Restrict SNMP access to specific management IP addresses via ACLs
- Monitor for SNMP queries from unauthorized source IPs
- Disable SNMP entirely on devices that do not require remote monitoring
- Configure SNMP traps for authentication failures

## Cross-References

- **Active Scanning** (01-reconnaissance/active-scanning.md) -- UDP port 161 discovery
- **SMB Enumeration** (01-reconnaissance/smb-enumeration.md) -- SNMP reveals Windows system details
- **LDAP Enumeration** (01-reconnaissance/ldap-enumeration.md) -- user info from SNMP complements LDAP
- **External Remote Services** (02-initial-access/external-remote-services.md) -- SNMP on perimeter devices

## References

- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- onesixtyone: https://github.com/trze/onesixtyone
- snmp-check: https://www.nothink.org/codes/snmpcheck/
- Net-SNMP tools: http://www.net-snmp.org/
- SNMP OID Reference: http://www.oid-info.com/
- SecLists SNMP: https://github.com/danielmiessler/SecLists/tree/master/Discovery/SNMP
