# AD Defense & Hardening

> **Category**: Defense Knowledge
> **Audience**: Red Team Lead (must understand what good defense looks like)

---

## Strategic Overview

A Red Team Lead who only knows offense is half-effective. Understanding defensive controls serves four critical purposes: accurately assessing organizational security maturity during engagements, providing actionable remediation guidance that goes beyond "patch and pray," designing tests that validate whether specific controls actually work, and communicating credibly with blue teams and security leadership. When you can explain both how to execute an attack and precisely which control would have stopped it, you demonstrate the strategic thinking expected of a lead.

---

## Technical Deep-Dive

### Tiered Administration Model (Enterprise Access Model)

The tiered administration model is the single most impactful AD security control. It prevents credential exposure across trust boundaries within the environment.

```
Tier 0 - Control Plane (Identity):
  Assets: Domain Controllers, AD CS (PKI), Azure AD Connect, ADFS, PAM solutions
  Admins: Domain Admins, Enterprise Admins, Schema Admins
  Rule: Tier 0 credentials NEVER touch Tier 1 or Tier 2 systems

Tier 1 - Management Plane (Servers & Applications):
  Assets: Member servers, SQL servers, Exchange, SCCM, application servers
  Admins: Server admins, application admins, database admins
  Rule: Tier 1 credentials NEVER touch Tier 2 systems

Tier 2 - User Access Plane (Workstations & Devices):
  Assets: Workstations, laptops, printers, end-user devices
  Admins: Helpdesk, desktop support, local admins
  Rule: Tier 2 credentials stay on Tier 2

Why it matters for Red Team:
  - Without tiering: Compromise workstation → harvest DA creds from memory → game over
  - With tiering: Compromise workstation → only Tier 2 creds available → must find
    a path between tiers (much harder, often requires chaining multiple techniques)
  - Red team testing validates whether tier boundaries actually hold
```

### Privileged Access Workstations (PAWs)

```
Implementation Levels:
  Level 1: Separate admin accounts (different from daily-use accounts)
  Level 2: Dedicated admin workstations (no email, no browsing)
  Level 3: Hardware-isolated PAWs (TPM, Secure Boot, BitLocker, Credential Guard)

Red Team Implications:
  - If PAWs are properly implemented, credential harvesting from workstations
    yields no privileged credentials
  - Attack must target the PAW itself or find alternative paths (ACL abuse,
    AD CS, Kerberos delegation misconfiguration)
  - Test: Can you phish a DA into running something on their PAW?
  - Test: Is the PAW network properly segmented from user VLANs?

Jump Server Architecture:
  - All admin access flows through hardened jump servers
  - Jump servers log all sessions (keystroke logging, screen recording)
  - Red team must determine: Are jump servers the only path, or can admins
    bypass them via RDP directly to servers?
```

### Kerberos Hardening

```powershell
# KRBTGT Password Rotation
# Must be rotated TWICE with at least 12-24 hours between rotations
# (Kerberos uses current and previous password for TGT validation)
# First rotation invalidates Golden Tickets using the N-2 password
# Second rotation invalidates Golden Tickets using the N-1 password

# Check KRBTGT last password set date (red team recon)
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
# If years old: Golden Tickets will persist indefinitely after extraction

# AES-Only Kerberos (disable RC4/DES)
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings >
#       Local Policies > Security Options >
#       "Network security: Configure encryption types allowed for Kerberos"
# Set to: AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types

# Impact on Red Team:
#   - Cannot use /rc4: flag in ticket forging if RC4 disabled
#   - Must extract AES keys (mimikatz lsadump::dcsync still provides them)
#   - Downgrade attacks (forcing RC4) generate alerts

# Protected Users Group
# Members get: No NTLM auth, no delegation, no DES/RC4, no credential caching,
#              TGT lifetime reduced to 4 hours
# Add privileged accounts: Add-ADGroupMember "Protected Users" -Members "admin_account"
# Red Team impact: Cannot harvest NTLM hashes, cannot use cached creds offline,
#                  must rely on Kerberos-only attacks
```

### AD CS Hardening

```powershell
# ESC1: Remove "Enrollee Supplies Subject" from templates
# Check current state:
certutil -v -template | findstr /i "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT"

# ESC6: Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on CA
certutil -config "CA01\domain-CA" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
net stop certsvc && net start certsvc

# ESC8: Disable HTTP enrollment endpoints or enforce HTTPS + EPA
# Remove IIS bindings for certsrv virtual directory

# Template permission audit:
# Remove "Enroll" permission from "Domain Users" / "Authenticated Users"
# on sensitive templates (especially those with Client Authentication EKU)

# Manager approval for sensitive templates:
# Template Properties > Issuance Requirements > CA certificate manager approval

# Red Team perspective: Check all ESC conditions during engagement
# If hardened, pivot to NTLM relay, delegation abuse, or other paths
```

### Credential Protection Technologies

```powershell
# Credential Guard (Virtualization-Based Security for LSASS)
# Isolates LSASS secrets in a hypervisor-protected container
# Prevents: Mimikatz sekurlsa::logonpasswords, WDigest, NTLM hash extraction
# Does NOT prevent: Kerberos ticket extraction, DCSync, keylogging
# Enable: Group Policy > Computer Configuration > Administrative Templates >
#         System > Device Guard > Turn On Virtualization Based Security
# Verify: Get-ComputerInfo | Select-Object DeviceGuardSecurityServicesRunning

# LAPS (Local Administrator Password Solution)
# Randomizes local admin passwords, stores in AD, rotates automatically
# Red Team impact: No more Pass-the-Hash with shared local admin passwords
# Check if deployed: Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where-Object {$_.'ms-Mcs-AdmPwd' -ne $null}
# But: Who can READ LAPS passwords? That becomes the new attack path

# Windows LAPS (new, Windows Server 2022+)
# Stores passwords in msLAPS-Password (encrypted, in AD)
# Supports Azure AD backup and automatic rotation

# Disable WDigest (prevents cleartext password caching)
# Registry: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
# Value: UseLogonCredential = 0

# Disable NTLM (where possible)
# GPO: Network security: Restrict NTLM: Incoming/Outgoing NTLM traffic
# Audit first with: "Audit NTLM" settings to identify dependencies
# Red Team: If NTLM disabled, no relay attacks, no Pass-the-Hash via NTLM
#           Must pivot to Kerberos-based attacks exclusively

# Authentication Policies and Silos (Windows Server 2012 R2+)
# Restrict WHERE privileged accounts can authenticate
# Example: DA accounts can only authenticate TO Domain Controllers
# Silo: Group of accounts + policy defining allowed targets
# Red Team: If silos enforced, compromised DA creds cannot be used on workstations
```

### Monitoring & Detection

```
Critical Event IDs for AD Security Monitoring:

Authentication Events:
  4624  - Successful logon (watch for Type 3/10 from unexpected sources)
  4625  - Failed logon (brute force detection)
  4648  - Explicit credential logon (runas, credential reuse)
  4672  - Special privileges assigned (admin logon)
  4776  - NTLM authentication (should be rare in Kerberos environment)

Kerberos Events:
  4768  - TGT requested (Kerberos AS-REQ, watch for RC4 downgrade)
  4769  - TGS requested (Kerberoasting detection: high volume, RC4 encryption)
  4771  - Kerberos pre-auth failed (AS-REP Roasting: 0x18 error code)

Directory Service Events:
  4662  - Directory object accessed (DCSync: Replicating Directory Changes)
  5136  - Directory object modified (ACL changes, attribute modifications)
  5137  - Directory object created (new accounts, GPOs, trusts)
  5141  - Directory object deleted

Persistence Events:
  7045  - New service installed (service creation persistence)
  4697  - Service installed (audit version)
  4720  - User account created
  4732  - Member added to security-enabled local group
  4728  - Member added to global security group (e.g., Domain Admins)

Advanced Detection Strategies:
  - Honey tokens: Fake DA accounts that trigger alerts on any auth attempt
  - Honey SPNs: Service accounts with SPNs that alert on TGS requests
  - Canary objects: Files/shares that alert on access
  - Microsoft Defender for Identity (MDI, formerly ATA):
      Detects: DCSync, Pass-the-Hash, Golden Ticket, Kerberoasting,
               skeleton key, trust exploitation, lateral movement patterns
  - BloodHound as defense: Run weekly, identify and remediate attack paths
      before red team finds them
  - DCSync detection: Alert on 4662 with replication rights from non-DC IPs
```

### Group Policy Hardening

```powershell
# Disable LLMNR (prevents LLMNR poisoning)
# GPO: Computer Configuration > Administrative Templates > Network > DNS Client
# "Turn off multicast name resolution" = Enabled

# Disable NBT-NS (prevents NBNS poisoning)
# Per-interface: Network adapter > TCP/IP > Advanced > WINS > Disable NetBIOS over TCP/IP
# Or via DHCP Option 001: Set to 0x2

# Disable WPAD (prevents WPAD poisoning)
# GPO: Disable "Auto-detect proxy settings" in IE/Edge
# DNS: Create WPAD DNS entry pointing to legitimate PAC or nowhere

# SMB Signing enforcement
# GPO: "Microsoft network server: Digitally sign communications (always)" = Enabled
# GPO: "Microsoft network client: Digitally sign communications (always)" = Enabled
# Impact: Prevents SMB relay attacks entirely

# PowerShell Logging (essential for red team detection)
# Script Block Logging: Records every script block executed
# Module Logging: Records pipeline execution details
# Transcription: Records full PowerShell session transcripts
# GPO: Administrative Templates > Windows Components > Windows PowerShell
# Red Team must assume PowerShell is fully logged and use alternatives

# AppLocker / WDAC
# Restrict executable and script execution to approved applications
# Red Team: Must find approved LOLBins, use reflective loading, or bypass
# WDAC (Windows Defender Application Control) is stronger than AppLocker
#   - Kernel-mode enforcement vs. user-mode
#   - Cannot be bypassed by running as admin

# Restricted Groups / Group Policy Preferences
# Control local admin group membership via GPO
# Ensures only designated accounts are local admins
# Prevents persistence via local group manipulation
```

---

## Detection & Evasion

### How Mature Defense Impacts Red Team Operations

```
Low Maturity (most orgs):
  - No tiering, shared local admin passwords, minimal logging
  - Red Team: Standard attack chains work, quick DA compromise
  - Typical time to DA: Hours to days

Medium Maturity:
  - LAPS deployed, some logging, basic EDR, partial tiering
  - Red Team: Need Kerberos attacks, ACL abuse, AD CS, delegation
  - Typical time to DA: Days to weeks

High Maturity:
  - Full tiering, PAWs, Credential Guard, MDI, WDAC, NTLM restricted
  - Red Team: Need chained attacks, novel techniques, patience
  - Must target: Cloud integration (AAD Connect), trust relationships,
    AD CS misconfigurations, supply chain (third-party access)
  - Typical time to DA: Weeks to months (if at all)

Red Team Lead responsibility: Accurately assess maturity level and adjust
TTPs, timeline expectations, and reporting accordingly.
```

---

## Cross-References

- [AD Fundamentals](ad-fundamentals.md) - Architecture that defense protects
- [Detection Engineering Notes](../appendices/detection-engineering-notes.md) - Building detections
- [Purple Team Integration](../00-methodology/purple-team-integration.md) - Validating controls together
- [LAPS Abuse](../05-privilege-escalation/laps-abuse.md) - When LAPS is deployed but misconfigured
- [ADCS Abuse](adcs-abuse.md) - Attack paths that survive most hardening
- [Azure AD Integration](azure-ad-integration.md) - Cloud integration as an attack surface

---

## References

- Microsoft: Securing Privileged Access (Enterprise Access Model)
- Microsoft: Credential Guard documentation
- Microsoft: LAPS deployment guide
- Sean Metcalf (adsecurity.org): AD security best practices series
- Will Schroeder / Andy Robbins: "An ACE Up the Sleeve" (BloodHound for defense)
- ANSSI: Active Directory security assessment recommendations
- CERT-EU: Active Directory hardening guidelines
- NIST SP 800-63B: Digital Identity Guidelines (authentication controls)
