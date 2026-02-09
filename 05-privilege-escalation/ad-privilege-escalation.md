# Active Directory Privilege Escalation Overview

> **MITRE ATT&CK**: Privilege Escalation > Multiple Techniques
> **Platforms**: Windows / Active Directory
> **Required Privileges**: Domain User (minimum)
> **OPSEC Risk**: Varies by technique

## Strategic Overview

Active Directory privilege escalation represents the most impactful phase of an internal
engagement. A single misconfiguration -- an overly permissive ACL, a vulnerable certificate
template, a Kerberos delegation setting -- can provide a direct path from standard domain
user to Domain Admin. A Red Team Lead must understand the full attack surface and prioritize
techniques based on stealth requirements, available access, and detection maturity. This
hub page provides a structured overview of each AD escalation class with links to detailed
attack documentation.

## Attack Classes

### Kerberos Attacks

Abuse Kerberos authentication mechanisms to extract or forge tickets for privileged accounts.
Kerberoasting targets service accounts with SPNs, extracting their TGS tickets for offline
cracking. AS-REP Roasting targets accounts without pre-authentication. Both require only a
standard domain user account.

**Detailed Guide**: [Kerberos-Based Privilege Escalation](kerberos-attacks.md)

---

### Kerberos Delegation Abuse

Exploit delegation configurations (Unconstrained, Constrained, Resource-Based) to impersonate
privileged users against target services. Unconstrained delegation captures TGTs from
connecting users, while constrained and RBCD attacks use S4U extensions to forge service
tickets for arbitrary users.

**Detailed Guide**: [Kerberos Delegation Abuse](delegation-abuse.md)

---

### ACL Abuse

Misconfigured Access Control Lists on AD objects allow unprivileged users to modify critical
attributes, reset passwords, add group members, or grant themselves DCSync rights. ACL-based
attacks are often invisible to traditional monitoring because they use legitimate AD
modification operations.

**Detailed Guide**: [ACL Abuse in Active Directory](acl-abuse.md)

---

### Certificate Abuse (AD CS)

Active Directory Certificate Services misconfigurations (ESC1-ESC8) allow users to request
certificates for privileged accounts, enabling authentication as Domain Admins. Certificate-
based attacks are persistent (certificates remain valid even after password changes) and
often poorly monitored.

**Detailed Guide**: [Certificate-Based Privilege Escalation](certificate-abuse.md)

---

### LAPS Abuse

Local Administrator Password Solution (LAPS) stores randomized local admin passwords in AD.
Users or groups with explicit read permissions can extract these passwords, providing local
administrator access to target machines -- often a stepping stone to domain-wide compromise.

**Detailed Guide**: [LAPS Password Reading](laps-abuse.md)

---

### GPO Abuse

Group Policy Objects with overly permissive edit rights allow attackers to push malicious
configurations, scheduled tasks, or scripts to all computers and users within the GPO's
scope. High impact but also high OPSEC risk due to broad propagation.

**Detailed Guide**: [GPO Abuse](gpo-abuse.md)

---

### Active Directory Deep Dive

Comprehensive coverage of AD internals, advanced attack chains, trust abuse, forest
compromise, and persistence mechanisms.

**Full Reference**: [Active Directory Deep Dive](../12-active-directory-deep-dive/README.md)

## Decision Tree: Which AD Privesc to Try First

```
[Standard Domain User Access Obtained]
          |
          v
  [Run BloodHound Collection]
          |
          +---> Shortest Path to DA found?
          |         |
          |    YES: Follow the path (ACL chain, group membership, etc.)
          |         |
          |    NO:  Continue enumeration
          |
          v
  [Check for Quick Wins]
          |
          +---> Kerberoastable accounts with weak passwords?
          |         YES --> [Kerberos Attacks](kerberos-attacks.md)
          |
          +---> AS-REP Roastable accounts?
          |         YES --> [Kerberos Attacks](kerberos-attacks.md)
          |
          +---> Writable ACLs on privileged objects?
          |         YES --> [ACL Abuse](acl-abuse.md)
          |
          +---> Vulnerable ADCS templates (ESC1-ESC8)?
          |         YES --> [Certificate Abuse](certificate-abuse.md)
          |
          +---> LAPS read permissions?
          |         YES --> [LAPS Abuse](laps-abuse.md)
          |
          +---> Delegation misconfigurations?
          |         YES --> [Delegation Abuse](delegation-abuse.md)
          |
          +---> Writable GPOs linked to privileged OUs?
          |         YES --> [GPO Abuse](gpo-abuse.md)
          |
          v
  [No Direct Escalation Path]
          |
          +---> Lateral movement to find better-positioned user
          +---> Local privesc on current host for credential access
          +---> Check for credentials in shares, scripts, GPP
          +---> Coercion attacks (PetitPotam, PrinterBug) if relay possible
```

## Priority Matrix

| Technique | OPSEC Risk | Likelihood of Success | Noise Level | Time to Execute |
|-----------|-----------|----------------------|-------------|-----------------|
| Kerberoasting | Low | High (common misconfig) | Low | Minutes |
| AS-REP Roasting | Low | Medium | Low | Minutes |
| ACL Abuse | Medium | Medium | Low | Minutes |
| ADCS Abuse | Low-Medium | Medium-High | Low | Minutes |
| LAPS Reading | Low | Low-Medium | Very Low | Seconds |
| Delegation Abuse | Medium | Medium | Medium | Minutes-Hours |
| GPO Abuse | High | Low-Medium | High | Hours (GPO refresh) |

## Initial Enumeration Commands

```powershell
# BloodHound collection (choose appropriate method for OPSEC)
# SharpHound (C# collector)
.\SharpHound.exe -c All --excludedc

# BloodHound.py (from Linux, over the network)
bloodhound-python -d domain.local -u user -p 'pass' -c All -ns DC_IP

# Quick manual checks with PowerView
Get-DomainUser -SPN                          # Kerberoastable accounts
Get-DomainUser -PreauthNotRequired           # AS-REP Roastable accounts
Get-DomainComputer -Unconstrained            # Unconstrained delegation
Get-DomainComputer -TrustedToAuth            # Constrained delegation
Find-InterestingDomainAcl -ResolveGUIDs      # ACL misconfigurations

# Certify for ADCS enumeration
.\Certify.exe find /vulnerable

# LAPS check
Get-DomainComputer -Properties ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime
```

## Cross-References

- [Windows Local Privesc](windows-local-privesc.md) - local escalation before domain attacks
- [Credential Access](../06-credential-access/README.md) - extracting credentials post-escalation
- [Lateral Movement](../07-lateral-movement/README.md) - moving with escalated privileges
- [Domain Dominance](../11-domain-dominance/README.md) - post-DA objectives

## References

- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- https://orange-cyberdefense.github.io/ocd-mindmaps/
- https://adsecurity.org/
- https://bloodhound.readthedocs.io/
- https://www.thehacker.recipes/
