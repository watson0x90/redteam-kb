# Azure Attack Techniques

This subsection covers offensive techniques specific to Microsoft Azure environments. Azure's deep integration with on-premises Active Directory through Azure AD Connect creates unique hybrid attack opportunities not found in other cloud platforms.

---

**Navigation:**
| Parent | Section |
|--------|---------|
| [Cloud Security](../README.md) | **Azure Attack Techniques** |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Azure Initial Access | [azure-initial-access.md](azure-initial-access.md) | T1078.004 | Medium | Exposed service principals, OAuth app consent phishing, public blob storage, and password spraying against Azure AD |
| Azure AD Attacks | [azure-ad-attacks.md](azure-ad-attacks.md) | T1078.004 | Medium-High | Azure AD enumeration, token manipulation, PRT abuse, conditional access bypass, and directory role abuse |
| Azure Privilege Escalation | [azure-privilege-escalation.md](azure-privilege-escalation.md) | T1078.004 | Medium | Managed Identity abuse, RBAC escalation, subscription takeover, and Azure resource exploitation |
| Azure Persistence | [azure-persistence.md](azure-persistence.md) | T1098 | Medium-High | Service principal credential addition, OAuth app registration, runbook persistence, and federation manipulation |
| Azure Enumeration | [azure-enumeration.md](azure-enumeration.md) | T1087.004, T1069.003, T1538 | Low-Medium | Post-authentication Entra ID enumeration: users, groups, roles, apps, devices, CA policies, and administrative units |
| Azure Data Mining | [azure-data-mining.md](azure-data-mining.md) | T1530, T1552.005, T1213 | Medium | Key Vault extraction, ARM template secrets, Storage Account exploitation, SQL/CosmosDB access, Automation Account credentials |
| Azure Defenses & Bypass | [azure-defenses-bypass.md](azure-defenses-bypass.md) | T1562, T1550 | Medium-High | Conditional Access bypass, Identity Protection evasion, PIM timing attacks, MDI evasion, CAE bypass, MFA bypass, logging evasion |

---

## Section Overview

Azure attack techniques are distinguished by the platform's tight integration with Azure Active Directory (now Entra ID) and on-premises Active Directory environments. This creates a bidirectional attack surface where compromise of on-premises AD can lead to cloud takeover (via Azure AD Connect abuse, PHS extraction, or PTA agent compromise) and cloud-level access can enable on-premises persistence (via hybrid identity synchronization). The initial access section covers Azure-specific vectors including OAuth consent grant phishing, exposed automation runbooks, and public storage account enumeration. Azure AD attacks are particularly impactful because Azure AD serves as the identity provider for Microsoft 365, Azure resources, and thousands of SaaS applications. Privilege escalation in Azure leverages the Azure RBAC model, Managed Identities, and cross-subscription access patterns. Persistence mechanisms abuse Azure's own identity platform features to maintain long-term access. The enumeration guide covers comprehensive post-authentication Entra ID reconnaissance using Graph API, Az PowerShell, and tools like ROADrecon and AzureHound. The data mining section documents extraction techniques for Key Vault secrets, ARM deployment templates, Storage Accounts, and other Azure services that commonly store credentials. The defenses and bypass guide covers Conditional Access policy evasion, MFA bypass, PIM timing attacks, and Azure logging blind spots. Operators should use tools like ROADtools, AADInternals, GraphRunner, and AzureHound for Azure AD enumeration and attack execution.
