# Password Cracking

> **MITRE ATT&CK**: Credential Access > T1110.002 - Brute Force: Password Cracking
> **Platforms**: Any (offline activity)
> **Required Privileges**: None (offline)
> **OPSEC Risk**: None (performed on attacker-controlled hardware)

## Strategic Overview

Password cracking is the offline process of recovering plaintext passwords from captured
hashes or encrypted data. As a purely offline activity, it carries zero OPSEC risk to
the target environment. However, as a Red Team Lead, your cracking strategy directly
impacts operational tempo -- efficient cracking means faster lateral movement and
escalation.

**Cracking prioritization framework:**
1. **NTLM hashes** (fast) - Crack first, immediate pass-the-hash if unsuccessful
2. **Net-NTLMv2** (medium) - From Responder/relay captures
3. **AS-REP hashes** (medium) - Quick wins from misconfigured accounts
4. **Kerberoast hashes** (medium-slow) - Service accounts often have weak passwords
5. **DCC2/mscash2** (very slow) - Only attempt with targeted wordlists
6. **PKZIP, Office, PDF** (varies) - Document passwords from file shares

**Key principle:** Time spent cracking is time not spent operating. Set up cracking rigs
to run autonomously while you continue the engagement. Prioritize attack techniques that
give access without cracking (relay, pass-the-hash) over techniques that require cracking.

## Technical Deep-Dive

### Hash Types and Hashcat Modes

```
# Common hash types encountered during engagements:
Mode  | Type                  | Speed (RTX 4090) | Example Source
------|----------------------|-------------------|----------------------------
1000  | NTLM                 | ~120 GH/s         | SAM, DCSync, LSASS
5600  | Net-NTLMv2           | ~8 GH/s           | Responder, relay capture
13100 | Kerberoast (RC4)     | ~1.5 GH/s         | Kerberoasting (TGS-REP)
19700 | Kerberoast (AES256)  | ~200 KH/s         | AES Kerberoasting
18200 | AS-REP (RC4)         | ~1.5 GH/s         | AS-REP Roasting
2100  | DCC2 / mscash2       | ~500 KH/s         | Cached domain credentials
3200  | bcrypt               | ~100 KH/s         | Web applications, Linux
1800  | sha512crypt           | ~300 KH/s         | Linux /etc/shadow
500   | md5crypt              | ~25 MH/s          | Older Linux /etc/shadow
5500  | Net-NTLMv1            | ~50 GH/s          | Legacy NTLM (rare)
16800 | WPA-PMKID             | ~1.5 MH/s         | Wi-Fi captures
13400 | KeePass               | ~250 KH/s         | KeePass database files
```

### Hashcat Fundamentals

```bash
# Basic syntax
hashcat -m <MODE> <hash_file> <wordlist> [options]

# Dictionary attack
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Dictionary + rules
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Multiple rules (applied sequentially)
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -r rules/best64.rule -r rules/toggles1.rule

# Status and performance
hashcat -m 1000 ntlm_hashes.txt rockyou.txt --status --status-timer=30

# Show cracked passwords
hashcat -m 1000 ntlm_hashes.txt --show

# Output cracked to file
hashcat -m 1000 ntlm_hashes.txt rockyou.txt -o cracked.txt

# Resume interrupted session
hashcat --restore

# Benchmark a specific hash type
hashcat -m 1000 -b
```

### John the Ripper Equivalents

```bash
# Basic dictionary attack
john --wordlist=rockyou.txt --format=NT ntlm_hashes.txt

# With rules
john --wordlist=rockyou.txt --rules=best64 --format=NT ntlm_hashes.txt

# Kerberoast
john --wordlist=rockyou.txt --format=krb5tgs kerberoast_hashes.txt

# AS-REP
john --wordlist=rockyou.txt --format=krb5asrep asrep_hashes.txt

# DCC2
john --wordlist=rockyou.txt --format=mscash2 dcc2_hashes.txt

# Show cracked
john --show --format=NT ntlm_hashes.txt

# John auto-detects format in many cases
john hashes.txt --wordlist=rockyou.txt
```

### Wordlist Strategies

```bash
# Tier 1: Standard wordlists
# rockyou.txt - 14 million passwords (the classic)
# SecLists/Passwords/ - curated password lists
# weakpass.com - large wordlists

# Tier 2: Custom wordlists with CeWL (crawl target website)
cewl https://www.targetcorp.com -d 3 -m 5 -w custom_wordlist.txt
# -d depth, -m minimum word length

# Tier 3: CUPP (Common User Passwords Profiler)
cupp -i
# Interactive mode: enter target's name, DOB, pet names, etc.
# Generates targeted password candidates

# Tier 4: Username-based mutations
# Company name + year + special char: CorpName2024!
# Username variations: john.doe → JohnDoe2024!
# Seasonal patterns: Summer2024!, Winter2024!

# Combine wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt

# Generate keyboard walks
kwprocessor --keywalk-south -o walks.txt
```

### Rule-Based Attacks

```bash
# Rules transform each word in the wordlist
# best64.rule - Top 64 most effective rules (fast, good coverage)
# d3ad0ne.rule - ~35,000 rules (comprehensive)
# dive.rule - ~100,000 rules (exhaustive)
# OneRuleToRuleThemAll.rule - Community-optimized mega rule

# Hashcat rule syntax examples:
# l         - lowercase all
# u         - uppercase all
# c         - capitalize first, lowercase rest
# $1        - append "1"
# $!        - append "!"
# ^1        - prepend "1"
# sa@       - substitute a→@
# ss$       - substitute s→$

# Custom rule file example (corporate_rules.rule):
# :                          # original word
# c                          # Capitalize
# c$1                        # Capitalize + append 1
# c$!                        # Capitalize + append !
# c$1$!                      # Capitalize + 1!
# c$2$0$2$4$!                # Capitalize + 2024!
# c$2$0$2$5$!                # Capitalize + 2025!

hashcat -m 1000 hashes.txt wordlist.txt -r corporate_rules.rule
```

### Mask Attacks (Pattern-Based Brute Force)

```bash
# Mask charsets:
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digit (0-9)
# ?s = special (!@#$%...)
# ?a = all printable
# ?b = all bytes (0x00-0xff)

# Common corporate password patterns:
# Capitalize + lowercase + digits + special
hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?l?l?d?d?s'          # Password12!
hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?l?l?l?d?d?d?d?s'    # Password2024!

# Season + Year + Special
hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?l?l?d?d?d?d'         # Summer2024
hashcat -m 1000 hashes.txt -a 3 '?u?l?l?l?l?l?d?d?d?d?s'       # Summer2024!

# Custom charset (specific positions)
hashcat -m 1000 hashes.txt -a 3 -1 '!@#$%' '?u?l?l?l?l?l?d?d?1'  # Custom special chars

# Incremental length
hashcat -m 1000 hashes.txt -a 3 --increment --increment-min 6 --increment-max 10 '?a?a?a?a?a?a?a?a?a?a'

# Hybrid: wordlist + mask
hashcat -m 1000 hashes.txt -a 6 wordlist.txt '?d?d?d?s'        # word + 123!
hashcat -m 1000 hashes.txt -a 7 '?u' wordlist.txt              # A + word
```

### Combinator and Prince Attacks

```bash
# Combinator: join two wordlists (word1+word2)
hashcat -m 1000 hashes.txt -a 1 wordlist1.txt wordlist2.txt

# Prince attack: generates candidates from input wordlist combinations
# Built into Hashcat as princeprocessor
pp64.bin wordlist.txt | hashcat -m 1000 hashes.txt

# prince with rules
pp64.bin --elem-cnt-min=2 --elem-cnt-max=3 wordlist.txt | hashcat -m 1000 hashes.txt -r best64.rule
```

### GPU Optimization

```bash
# Force specific GPU device
hashcat -m 1000 hashes.txt wordlist.txt -d 1

# Use multiple GPUs
hashcat -m 1000 hashes.txt wordlist.txt -d 1,2,3,4

# Workload profile (1=low, 2=default, 3=high, 4=nightmare)
hashcat -m 1000 hashes.txt wordlist.txt -w 3

# Optimize kernel (faster but uses more memory)
hashcat -m 1000 hashes.txt wordlist.txt -O

# Temperature management
hashcat -m 1000 hashes.txt wordlist.txt --hwmon-temp-abort=90

# Distributed cracking with Hashtopolis
# Server: Install Hashtopolis web interface
# Agents: Deploy hashtopolis-agent on each GPU rig
# Upload hashes, assign tasks, aggregate results
```

### Cracking Workflow for Engagements

```bash
# Phase 1: Quick wins (minutes)
hashcat -m 1000 ntlm.txt rockyou.txt                            # NTLM + rockyou
hashcat -m 1000 ntlm.txt -a 3 '?u?l?l?l?l?l?d?d?d?d?s'        # Common patterns

# Phase 2: Rule-based (hours)
hashcat -m 1000 ntlm.txt rockyou.txt -r best64.rule
hashcat -m 1000 ntlm.txt custom_corp.txt -r OneRuleToRuleThemAll.rule

# Phase 3: Kerberoast focused (hours-days)
hashcat -m 13100 kerb.txt rockyou.txt -r best64.rule
hashcat -m 13100 kerb.txt -a 3 --increment --increment-min 6 '?a?a?a?a?a?a?a?a'

# Phase 4: Slow hashes - targeted only (days)
hashcat -m 2100 dcc2.txt targeted_wordlist.txt -r best64.rule

# Always running: mask attacks on NTLM
hashcat -m 1000 ntlm.txt -a 3 --increment --increment-min 1 --increment-max 8 '?a?a?a?a?a?a?a?a'
```

## Detection & Evasion

### Detection Indicators

Password cracking is entirely offline -- there are no detection indicators in the target
environment. However, be aware of:

| Consideration | Detail |
|---------------|--------|
| Hash acquisition | The method used to obtain hashes IS detectable (see other files) |
| Password spraying | If cracked passwords are used for spraying, that generates logs |
| Account lockout | Using cracked credentials may trigger lockout if wrong account targeted |
| Credential reuse | Cracked password used on multiple systems creates correlation |

### Operational Considerations

1. **Dedicated cracking hardware** - Use purpose-built GPU rigs, not engagement infrastructure
2. **Secure hash storage** - Client credential data must be encrypted at rest
3. **Scope management** - Some RoE restrict password cracking; confirm with client
4. **Password reporting** - Report password patterns, not individual user passwords
5. **Data handling** - Destroy all hash data per engagement contract terms

## Cross-References

- [LSASS Dumping](lsass-dumping.md) - Source of NTLM hashes for cracking
- [SAM & LSA Secrets](sam-lsa-secrets.md) - Source of local NTLM and DCC2 hashes
- [DCSync](dcsync.md) - Source of domain-wide NTLM hashes
- [NTLM Theft](ntlm-theft.md) - Source of Net-NTLMv2 hashes
- [Kerberos Attacks](kerberos-credential-attacks.md) - Source of Kerberoast and AS-REP hashes
- [Credential Stores](credential-stores.md) - Source of application-specific hashes

## References

- https://attack.mitre.org/techniques/T1110/002/
- https://hashcat.net/wiki/
- https://github.com/openwall/john
- https://github.com/hashcat/hashcat
- https://github.com/s3inlc/hashtopolis
- https://weakpass.com/
- https://github.com/danielmiessler/SecLists
