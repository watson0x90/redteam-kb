# MITRE ATT&CK Cross-Reference Index

This document provides a master cross-reference table mapping MITRE ATT&CK tactics and techniques to the relevant knowledge base articles. Use this index to quickly locate tradecraft guidance, understand tactic coverage, and assess OPSEC risk associated with each technique.

**Framework Updates**: ATT&CK v17 (April 2025) added T1204.004, ESXi platform. ATT&CK v18 (October 2025) replaced Detections with Detection Strategies/Analytics, overhauled Data Components, deprecated Data Sources. Enterprise additions include CI/CD pipelines, Kubernetes, cloud databases, and ransomware preparation behaviors.

---

## Reconnaissance (TA0043)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Reconnaissance | T1595.001 | Active Scanning: Scanning IP Blocks | [Network Scanning](network_scanning.md) | Medium |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | [Vulnerability Scanning](vulnerability_scanning.md) | Medium |
| Reconnaissance | T1589.001 | Gather Victim Identity: Credentials | [Credential Harvesting Recon](credential_harvesting_recon.md) | Low |
| Reconnaissance | T1589.002 | Gather Victim Identity: Email Addresses | [Email Enumeration](email_enumeration.md) | Low |
| Reconnaissance | T1590.001 | Gather Victim Network Info: Domain Properties | [Domain Recon](domain_recon.md) | Low |
| Reconnaissance | T1591.004 | Gather Victim Org Info: Identify Roles | [OSINT Org Recon](osint_org_recon.md) | Low |
| Reconnaissance | T1593.001 | Search Open Websites: Social Media | [Social Media Recon](social_media_recon.md) | Low |
| Reconnaissance | T1594 | Search Victim-Owned Websites | [Website Recon](website_recon.md) | Low |

---

## Resource Development (TA0042)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Resource Development | T1583.001 | Acquire Infrastructure: Domains | [Infrastructure Setup](infrastructure_setup.md) | Low |
| Resource Development | T1583.003 | Acquire Infrastructure: Virtual Private Server | [C2 Infrastructure](c2_infrastructure.md) | Low |
| Resource Development | T1587.001 | Develop Capabilities: Malware | [Payload Development](payload_development.md) | Medium |
| Resource Development | T1587.003 | Develop Capabilities: Digital Certificates | [Certificate Cloning](certificate_cloning.md) | Low |
| Resource Development | T1588.002 | Obtain Capabilities: Tool | [Tooling Procurement](tooling_procurement.md) | Low |
| Resource Development | T1588.005 | Obtain Capabilities: Exploits | [Exploit Acquisition](exploit_acquisition.md) | Medium |
| Resource Development | T1585.001 | Establish Accounts: Social Media Accounts | [Pretext Development](pretext_development.md) | Low |
| Resource Development | T1608.001 | Stage Capabilities: Upload Malware | [Payload Staging](payload_staging.md) | Medium |

---

## Initial Access (TA0001)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | [Phishing Campaigns](phishing_campaigns.md) | High |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | [Phishing Campaigns](phishing_campaigns.md) | High |
| Initial Access | T1078.002 | Valid Accounts: Domain Accounts | [Valid Account Usage](valid_account_usage.md) | Medium |
| Initial Access | T1190 | Exploit Public-Facing Application | [Web Application Exploitation](web_app_exploitation.md) | High |
| Initial Access | T1133 | External Remote Services | [VPN and Remote Access](vpn_remote_access.md) | Medium |
| Initial Access | T1199 | Trusted Relationship | [Supply Chain and Trusts](supply_chain_trusts.md) | Medium |
| Initial Access | T1091 | Replication Through Removable Media | [Physical Access Attacks](physical_access.md) | High |
| Initial Access | T1195.002 | Supply Chain Compromise: Software Supply Chain | [Supply Chain and Trusts](supply_chain_trusts.md), [CI/CD Pipeline Attacks](02-initial-access/cicd-pipeline-attacks.md) | High |
| Initial Access | T1200 | Hardware Additions | [Wireless & Physical Attacks](02-initial-access/wireless-physical-attacks.md) | Medium |
| Initial Access | T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | [Phishing Payloads](02-initial-access/phishing-payloads.md) | Medium |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | [Cloud Credential Access](07-credential-access/cloud-credential-access.md) | Medium |
| Initial Access | T1671 | Cloud Application Integration | [Office 365 Initial Access](02-initial-access/office365-initial-access.md) | Medium |

---

## Execution (TA0002)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | [PowerShell Tradecraft](powershell_tradecraft.md) | High |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | [CMD Execution](cmd_execution.md) | Medium |
| Execution | T1059.005 | Command and Scripting Interpreter: Visual Basic | [VBS and HTA Execution](vbs_hta_execution.md) | Medium |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | [WSH Execution](wsh_execution.md) | Medium |
| Execution | T1047 | Windows Management Instrumentation | [WMI Tradecraft](wmi_tradecraft.md) | Medium |
| Execution | T1053.005 | Scheduled Task/Job: Scheduled Task | [Scheduled Task Abuse](scheduled_task_abuse.md) | Medium |
| Execution | T1204.001 | User Execution: Malicious Link | [Social Engineering Execution](social_engineering_execution.md) | Medium |
| Execution | T1204.002 | User Execution: Malicious File | [Payload Delivery](payload_delivery.md) | High |
| Execution | T1204.004 | User Execution: Malicious Copy and Paste | [ClickFix Execution](03-execution/clickfix-execution.md) | Medium |
| Execution | T1059 | Command and Scripting Interpreter | [VDI/Citrix Breakout](03-execution/vdi-breakout.md) | Medium |

---

## Persistence (TA0003)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Persistence | T1547.001 | Boot or Logon Autostart: Registry Run Keys | [Registry Persistence](registry_persistence.md) | Medium |
| Persistence | T1053.005 | Scheduled Task/Job: Scheduled Task | [Scheduled Task Abuse](scheduled_task_abuse.md) | Medium |
| Persistence | T1543.003 | Create or Modify System Process: Windows Service | [Service Persistence](service_persistence.md) | High |
| Persistence | T1546.003 | Event Triggered Execution: WMI Event Subscription | [WMI Persistence](wmi_persistence.md) | Medium |
| Persistence | T1546.012 | Event Triggered Execution: Image File Execution Options | [IFEO Persistence](ifeo_persistence.md) | Medium |
| Persistence | T1546.015 | Event Triggered Execution: COM Hijacking | [COM Hijacking](com_hijacking.md) | Medium |
| Persistence | T1556.001 | Modify Authentication Process: Domain Controller | [DCShadow Persistence](dcshadow_persistence.md) | Critical |
| Persistence | T1098 | Account Manipulation | [Account Persistence](account_persistence.md) | High |
| Persistence | T1137.003 | Office Application Startup: Outlook Forms | [Outlook Persistence](04-persistence/outlook-persistence.md) | Medium |
| Persistence | T1137.004 | Office Application Startup: Outlook Home Page | [Outlook Persistence](04-persistence/outlook-persistence.md) | Medium |
| Persistence | T1137.005 | Office Application Startup: Outlook Rules | [Outlook Persistence](04-persistence/outlook-persistence.md) | Medium |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | [Linux Persistence](04-persistence/linux-persistence.md) | Medium |
| Persistence | T1543.002 | Create or Modify System Process: Systemd Service | [Linux Persistence](04-persistence/linux-persistence.md) | Medium |
| Persistence | T1547.006 | Boot or Logon Autostart: Kernel Modules and Extensions | [Linux Persistence](04-persistence/linux-persistence.md) | Medium |
| Persistence | T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | [Linux Persistence](04-persistence/linux-persistence.md) | Medium |
| Persistence | T1556.003 | Modify Authentication Process: Pluggable Authentication Modules | [Linux Persistence](04-persistence/linux-persistence.md) | High |
| Persistence | T1543.004 | Create or Modify System Process: Launch Daemon | [macOS Persistence](04-persistence/macos-persistence.md) | Medium |
| Persistence | T1547.011 | Boot or Logon Autostart: Plist Modification | [macOS Persistence](04-persistence/macos-persistence.md) | Medium |
| Persistence | T1547.015 | Boot or Logon Autostart: Login Items | [macOS Persistence](04-persistence/macos-persistence.md) | Low |

---

## Privilege Escalation (TA0004)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Privilege Escalation | T1548.002 | Abuse Elevation Control: Bypass UAC | [UAC Bypass Techniques](uac_bypass.md) | Medium |
| Privilege Escalation | T1134.001 | Access Token Manipulation: Token Impersonation | [Token Manipulation](token_manipulation.md) | Medium |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | [Local Privilege Escalation](local_privesc.md) | High |
| Privilege Escalation | T1078.002 | Valid Accounts: Domain Accounts | [Valid Account Usage](valid_account_usage.md) | Medium |
| Privilege Escalation | T1484.001 | Domain Policy Modification: GPO Modification | [GPO Abuse](gpo_abuse.md) | High |
| Privilege Escalation | T1611 | Escape to Host | [Container Escape](container_escape.md) | High |
| Privilege Escalation | T1543.003 | Create or Modify System Process: Windows Service | [Service Privesc](service_privesc.md) | High |
| Privilege Escalation | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | [DLL Hijacking](dll_hijacking.md) | Medium |
| Privilege Escalation | T1648 | Serverless Execution | [AWS Services Abuse](13-cloud-security/aws/aws-services-abuse.md) | Medium |
| Privilege Escalation | T1098.003 | Account Manipulation: Additional Cloud Roles | [Azure AD Attacks](13-cloud-security/azure/azure-ad-attacks.md) | High |
| Privilege Escalation | T1548.004 | Abuse Elevation Control: Elevated Execution with Prompt | [macOS Privesc](05-privilege-escalation/macos-privesc.md) | Medium |
| Privilege Escalation | T1574.004 | Hijack Execution Flow: Dylib Hijacking | [macOS Privesc](05-privilege-escalation/macos-privesc.md) | Medium |

---

## Container & Kubernetes

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Privilege Escalation | T1611 | Escape to Host | [Container Escapes](13-cloud-security/containers/container-escapes.md) | High |
| Execution | T1609 | Container Administration Command | [Kubernetes Attacks](13-cloud-security/containers/kubernetes-attacks.md) | Medium |
| Execution | T1610 | Deploy Container | [Kubernetes Attacks](13-cloud-security/containers/kubernetes-attacks.md) | Medium |
| Discovery | T1613 | Container and Resource Discovery | [Kubernetes Attacks](13-cloud-security/containers/kubernetes-attacks.md) | Low |

---

## Defense Evasion (TA0005)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | [EDR Evasion](edr_evasion.md) | Critical |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | [Log Evasion](log_evasion.md) | High |
| Defense Evasion | T1027.002 | Obfuscated Files: Software Packing | [Payload Obfuscation](payload_obfuscation.md) | Medium |
| Defense Evasion | T1055.001 | Process Injection: DLL Injection | [Process Injection](process_injection.md) | High |
| Defense Evasion | T1218.005 | System Binary Proxy Execution: Mshta | [LOLBAS Execution](lolbas_execution.md) | Medium |
| Defense Evasion | T1218.011 | System Binary Proxy Execution: Rundll32 | [LOLBAS Execution](lolbas_execution.md) | Medium |
| Defense Evasion | T1562.002 | Impair Defenses: Disable Windows Event Logging | [ETW Bypass](etw_bypass.md) | Critical |
| Defense Evasion | T1622 | Debugger Evasion | [Anti-Analysis Techniques](anti_analysis.md) | Medium |
| Defense Evasion | T1211 | Exploitation for Defense Evasion | [BYOVD Attacks](byovd_attacks.md) | High |
| Defense Evasion | T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | [Phishing Payloads](02-initial-access/phishing-payloads.md) | Medium |
| Defense Evasion | T1578.001 | Modify Cloud Compute Infrastructure: Create Snapshots | [Cloud Lateral Movement](09-lateral-movement/cloud-lateral.md) | Medium |
| Defense Evasion | T1578.002 | Modify Cloud Compute Infrastructure: Create Cloud Instance | [Cloud Lateral Movement](09-lateral-movement/cloud-lateral.md) | Medium |
| Defense Evasion | T1578.003 | Modify Cloud Compute Infrastructure: Delete Cloud Instance | [Cloud Lateral Movement](09-lateral-movement/cloud-lateral.md) | High |
| Defense Evasion | T1578.004 | Modify Cloud Compute Infrastructure: Revert Cloud Instance | [Cloud Lateral Movement](09-lateral-movement/cloud-lateral.md) | Medium |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | [Anti-Forensics](06-defense-evasion/anti-forensics.md) | Medium |
| Defense Evasion | T1070.004 | Indicator Removal: File Deletion | [Anti-Forensics](06-defense-evasion/anti-forensics.md) | Low |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | [Anti-Forensics](06-defense-evasion/anti-forensics.md) | Medium |
| Defense Evasion | T1014 | Rootkit | [EDR Internals](06-defense-evasion/edr-internals.md) | Critical |
| Defense Evasion | T1562 | Impair Defenses | [Azure Defenses & Bypass](13-cloud-security/azure/azure-defenses-bypass.md) | Medium-High |

---

## Credential Access (TA0006)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | [LSASS Dumping](lsass_dumping.md), [Credential Guard Bypass](07-credential-access/credential-guard-bypass.md) | Critical |
| Credential Access | T1003.006 | OS Credential Dumping: DCSync | [DCSync Attack](dcsync_attack.md) | Critical |
| Credential Access | T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | [Kerberoasting](kerberoasting.md) | Medium |
| Credential Access | T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | [AS-REP Roasting](asrep_roasting.md) | Low |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | [Certificate Theft](certificate_theft.md) | Medium |
| Credential Access | T1555.003 | Credentials from Password Stores: Web Browsers | [Browser Credential Theft](browser_cred_theft.md) | Medium |
| Credential Access | T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning | [LLMNR Poisoning](llmnr_poisoning.md) | High |
| Credential Access | T1556.005 | Modify Authentication Process: Reversible Encryption | [DPAPI Abuse](dpapi_abuse.md) | Medium |
| Credential Access | T1528 | Steal Application Access Token | [Cloud Credential Access](07-credential-access/cloud-credential-access.md), [M365 Initial Access](02-initial-access/office365-initial-access.md), [Entra ID Token Security](13-cloud-security/azure/entra-id-token-security.md) | Medium |
| Credential Access | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | [Linux Credential Access](07-credential-access/linux-credential-access.md) | Medium |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | [Linux Credential Access](07-credential-access/linux-credential-access.md) | Low |
| Credential Access | T1555.001 | Credentials from Password Stores: Keychain | [macOS Credential Access](07-credential-access/macos-credential-access.md) | Medium |
| Credential Access | T1539 | Steal Web Session Cookie | [macOS Credential Access](07-credential-access/macos-credential-access.md), [Entra ID Token Security](13-cloud-security/azure/entra-id-token-security.md) | Medium |

---

## Discovery (TA0007)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Discovery | T1087.002 | Account Discovery: Domain Account | [AD Enumeration](ad_enumeration.md) | Medium |
| Discovery | T1482 | Domain Trust Discovery | [Trust Enumeration](trust_enumeration.md) | Medium |
| Discovery | T1615 | Group Policy Discovery | [GPO Enumeration](gpo_enumeration.md) | Low |
| Discovery | T1046 | Network Service Discovery | [Service Enumeration](service_enumeration.md) | Medium |
| Discovery | T1069.002 | Permission Groups Discovery: Domain Groups | [BloodHound Collection](bloodhound_collection.md) | Medium |
| Discovery | T1018 | Remote System Discovery | [Host Enumeration](host_enumeration.md) | Medium |
| Discovery | T1083 | File and Directory Discovery | [File Enumeration](file_enumeration.md) | Low |
| Discovery | T1016 | System Network Configuration Discovery | [Network Enumeration](network_enumeration.md) | Low |
| Discovery | T1087.004 | Account Discovery: Cloud Account | [Azure Enumeration](13-cloud-security/azure/azure-enumeration.md) | Low-Medium |
| Discovery | T1069.003 | Permission Groups Discovery: Cloud Groups | [Azure Enumeration](13-cloud-security/azure/azure-enumeration.md) | Low |
| Discovery | T1538 | Cloud Service Dashboard | [Azure Enumeration](13-cloud-security/azure/azure-enumeration.md) | Low |

---

## Lateral Movement (TA0008)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Lateral Movement | T1021.001 | Remote Services: RDP | [RDP Lateral Movement](rdp_lateral_movement.md) | Medium |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | [SMB Lateral Movement](smb_lateral_movement.md) | High |
| Lateral Movement | T1021.003 | Remote Services: DCOM | [DCOM Lateral Movement](dcom_lateral_movement.md) | Medium |
| Lateral Movement | T1021.006 | Remote Services: Windows Remote Management | [WinRM Lateral Movement](winrm_lateral_movement.md) | Medium |
| Lateral Movement | T1550.002 | Use Alternate Authentication: Pass the Hash | [Pass the Hash](pass_the_hash.md) | High |
| Lateral Movement | T1550.003 | Use Alternate Authentication: Pass the Ticket | [Pass the Ticket](pass_the_ticket.md) | Medium |
| Lateral Movement | T1047 | Windows Management Instrumentation | [WMI Lateral Movement](wmi_lateral_movement.md) | Medium |
| Lateral Movement | T1570 | Lateral Tool Transfer | [Tool Staging](tool_staging.md) | High |
| Lateral Movement | T1550.001 | Use Alternate Authentication: Application Access Token | [Azure AD Attacks](13-cloud-security/azure/azure-ad-attacks.md), [Entra ID Token Security](13-cloud-security/azure/entra-id-token-security.md) | Medium |
| Lateral Movement | T1572 | Protocol Tunneling | [Network Pivoting](09-lateral-movement/network-pivoting.md) | Medium |
| Lateral Movement | T1210 | Exploitation of Remote Services | [Database Exploitation](09-lateral-movement/database-exploitation.md) | High |

---

## Collection (TA0009)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | [Data Staging](data_staging.md) | Medium |
| Collection | T1005 | Data from Local System | [Local Data Collection](local_data_collection.md) | Low |
| Collection | T1039 | Data from Network Shared Drive | [Share Enumeration](share_enumeration.md) | Medium |
| Collection | T1114.001 | Email Collection: Local Email Collection | [Email Collection](email_collection.md) | Medium |
| Collection | T1114.002 | Email Collection: Remote Email Collection | [Exchange Abuse](exchange_abuse.md) | High |
| Collection | T1213.002 | Data from Information Repositories: SharePoint | [SharePoint Collection](sharepoint_collection.md) | Medium |
| Collection | T1119 | Automated Collection | [Automated Data Harvesting](automated_data_harvesting.md) | High |
| Collection | T1185 | Browser Session Hijacking | [Browser Hijack](browser_hijack.md) | High |
| Collection | T1530 | Data from Cloud Storage | [Azure Data Mining](13-cloud-security/azure/azure-data-mining.md) | Medium |
| Collection | T1213 | Data from Information Repositories | [Azure Data Mining](13-cloud-security/azure/azure-data-mining.md) | Medium |
| Collection | T1552.005 | Unsecured Credentials: Cloud Instance Metadata | [Azure Data Mining](13-cloud-security/azure/azure-data-mining.md) | Medium |

---

## Command and Control (TA0011)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | [HTTP C2](http_c2.md) | Medium |
| Command and Control | T1071.004 | Application Layer Protocol: DNS | [DNS C2](dns_c2.md) | Low |
| Command and Control | T1572 | Protocol Tunneling | [C2 Tunneling](c2_tunneling.md) | Medium |
| Command and Control | T1573.002 | Encrypted Channel: Asymmetric Cryptography | [Encrypted C2](encrypted_c2.md) | Low |
| Command and Control | T1090.002 | Proxy: External Proxy | [C2 Redirectors](c2_redirectors.md) | Low |
| Command and Control | T1105 | Ingress Tool Transfer | [Tool Transfer](tool_transfer.md) | Medium |
| Command and Control | T1219 | Remote Access Software | [Remote Access Tools](remote_access_tools.md) | Medium |
| Command and Control | T1102 | Web Service | [Cloud C2](cloud_c2.md) | Low |

---

## Exfiltration (TA0010)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Exfiltration | T1041 | Exfiltration Over C2 Channel | [C2 Exfiltration](c2_exfiltration.md) | Medium |
| Exfiltration | T1048.002 | Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2 | [Alternative Exfil](alternative_exfil.md) | Medium |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | [Cloud Exfiltration](cloud_exfiltration.md) | Medium |
| Exfiltration | T1029 | Scheduled Transfer | [Timed Exfiltration](timed_exfiltration.md) | Low |
| Exfiltration | T1030 | Data Transfer Size Limits | [Chunked Exfiltration](chunked_exfiltration.md) | Low |
| Exfiltration | T1537 | Transfer Data to Cloud Account | [Cloud Account Exfil](cloud_account_exfil.md) | Medium |

---

## Impact (TA0040)

| Tactic | Technique ID | Technique Name | KB Article | OPSEC Risk |
|--------|-------------|----------------|------------|------------|
| Impact | T1486 | Data Encrypted for Impact | [Ransomware Simulation](ransomware_simulation.md) | Critical |
| Impact | T1531 | Account Access Removal | [Account Lockout Impact](account_lockout.md) | Critical |
| Impact | T1490 | Inhibit System Recovery | [Recovery Inhibition](recovery_inhibition.md) | Critical |
| Impact | T1489 | Service Stop | [Service Disruption](service_disruption.md) | High |
| Impact | T1529 | System Shutdown/Reboot | [System Disruption](system_disruption.md) | Critical |
| Impact | T1565.001 | Data Manipulation: Stored Data Manipulation | [Data Integrity Attack](data_integrity.md) | Critical |

---

## OPSEC Risk Legend

| Rating | Description |
|--------|-------------|
| **Low** | Minimal detection surface. Passive or commonly blended with normal activity. |
| **Medium** | Moderate detection surface. May trigger alerts if detections are tuned. |
| **High** | Significant detection surface. Likely to generate alerts in mature environments. |
| **Critical** | Extremely high detection surface. Will almost certainly trigger alerts; requires careful planning and justification. |

---

> **Note:** This index follows the MITRE ATT&CK Enterprise framework v15. Technique IDs and names correspond to the official MITRE ATT&CK knowledge base at [https://attack.mitre.org](https://attack.mitre.org). KB Article links point to the corresponding knowledge base markdown files in this repository.
