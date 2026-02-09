# Threat Modeling and Adversary Emulation Planning

> **Category**: Methodology
> **Audience**: Red Team Lead

---

## Strategic Overview

Threat modeling is the intellectual foundation of red team operations. Without it, a red
team is just a penetration testing team with fancier tools. The ability to translate cyber
threat intelligence (CTI) into actionable adversary emulation plans is the defining skill
of a Red Team Lead.

---

## Threat Intelligence Integration

### Consuming CTI Reports

A Red Team Lead is not a threat intelligence analyst, but must be a sophisticated consumer
of CTI products. Key sources include:

- **Commercial CTI feeds**: Mandiant, CrowdStrike, Recorded Future, and similar vendors
  publish detailed reports on threat actor TTPs.
- **Open-source intelligence**: MITRE ATT&CK knowledge base, CISA advisories, vendor
  threat reports, and academic research.
- **Internal telemetry**: The organization's own SIEM data, incident history, and threat
  hunting findings provide context that external sources cannot.
- **ISACs**: Industry-specific Information Sharing and Analysis Centers (FS-ISAC, H-ISAC,
  E-ISAC) share sector-relevant threat information.

### Mapping Intelligence to Operations

Raw intelligence must be transformed into operational requirements:

1. **Identify relevant threat actors**: Which APT groups or criminal organizations target
   this industry, geography, or technology stack?
2. **Extract TTPs**: From threat reports, extract specific techniques at the ATT&CK
   sub-technique level (e.g., T1566.001 Spearphishing Attachment, not just "phishing").
3. **Assess organizational exposure**: Does the target organization use the technologies
   and architectures that the identified adversaries exploit?
4. **Prioritize**: Not every TTP can be tested in a single engagement. Prioritize based on
   likelihood of attack, potential impact, and current detection coverage gaps.

---

## Adversary Emulation vs. Red Teaming vs. Penetration Testing

These terms are frequently conflated. A Lead must articulate the distinctions clearly:

| Dimension | Penetration Testing | Red Teaming | Adversary Emulation |
|-----------|-------------------|-------------|---------------------|
| **Objective** | Find vulnerabilities | Test detection and response | Validate defenses against specific threat actors |
| **Scope** | Defined system or application | Organization-wide | Mapped to specific actor's known TTPs |
| **Methodology** | Systematic vulnerability assessment | Goal-based with creative freedom | Intelligence-driven with constrained TTP set |
| **Stealth** | Often noisy, accepted | Stealth is a core requirement | Matches the actual tradecraft of the emulated actor |
| **Duration** | Days to weeks | Weeks to months | Weeks to months |
| **Output** | Vulnerability list with severity | Attack narrative with detection gaps | Detection coverage against specific threat profile |
| **Value** | Patch management input | Security program validation | Threat-specific defense validation |

### When to Use Each

- **Penetration testing**: Compliance requirements, new application assessments, or when
  the organization needs a vulnerability inventory.
- **Red teaming**: When leadership wants to understand "could an attacker reach our crown
  jewels?" without constraining the methodology.
- **Adversary emulation**: When the organization has identified specific threats and wants
  to validate whether their defenses would detect and respond to those exact actors.

A mature red team program uses all three, applied to different questions at different times.

---

## Creating Adversary Emulation Plans

### Step 1: Select Threat Actor Profile

Based on CTI analysis, select one or more threat actors relevant to the organization.
Consider:

- **Industry targeting**: FIN7 and FIN8 for retail and hospitality. APT41 for healthcare
  and technology. Lazarus Group for financial institutions and cryptocurrency.
- **Geographic targeting**: APT28 and APT29 for organizations in NATO countries. APT40
  for maritime and defense targets in the Asia-Pacific region.
- **Capability alignment**: Choose actors whose TTPs are achievable within the engagement
  timeline and operator skill set.

### Step 2: Map TTPs to MITRE ATT&CK

For each selected actor, build a comprehensive TTP profile using ATT&CK:

```
Example: APT29 Emulation Plan (Abbreviated)

Initial Access:     T1566.001 Spearphishing Attachment (ISO/LNK files)
Execution:          T1059.001 PowerShell, T1204.002 Malicious File
Persistence:        T1547.001 Registry Run Keys, T1053.005 Scheduled Task
Privilege Esc:      T1055.012 Process Hollowing, T1134 Access Token Manipulation
Defense Evasion:    T1027 Obfuscated Files, T1218.011 Rundll32
Credential Access:  T1003.001 LSASS Memory, T1558.003 Kerberoasting
Discovery:          T1087 Account Discovery, T1069 Permission Groups Discovery
Lateral Movement:   T1021.006 WinRM, T1021.001 RDP
Collection:         T1560.001 Archive via Utility
Exfiltration:       T1041 Exfil Over C2 Channel
```

### Step 3: Build Attack Flows

Sequence the TTPs into realistic attack flows that mirror how the actor actually operates.
This is not a checklist -- it is a narrative:

1. Deliver spearphishing email with ISO attachment containing LNK file.
2. LNK executes PowerShell loader that downloads and executes staged payload.
3. Payload establishes HTTPS C2 channel through domain-fronted infrastructure.
4. Enumerate local system, dump credentials from LSASS.
5. Use harvested credentials for lateral movement via WinRM.
6. Escalate to domain admin through Kerberoasting or delegation abuse.
7. Identify and stage sensitive data for exfiltration.
8. Exfiltrate data over the C2 channel.

Each step should have fallback options if the primary technique is detected or fails.

### Step 4: Define Success Criteria

Success is not binary. Define graduated success criteria:

- **Tier 1**: Initial access achieved and C2 established without detection.
- **Tier 2**: Lateral movement and privilege escalation achieved.
- **Tier 3**: Access to crown jewels demonstrated.
- **Tier 4**: Data exfiltration completed without triggering incident response.

---

## MITRE ATT&CK Navigator Usage

The ATT&CK Navigator is an indispensable planning and reporting tool:

### Planning Phase
- Create a layer showing the selected threat actor's known TTPs (colored by phase).
- Overlay the organization's current detection coverage (from SOC input or prior assessments).
- Identify gaps where the actor's TTPs are not covered by existing detections.
- Focus the engagement plan on those gaps -- this is where the highest value lies.

### Reporting Phase
- Create a results layer showing which techniques were executed and their detection status:
  - **Green**: Detected and alerted within acceptable timeframe.
  - **Yellow**: Logged but not alerted (detection opportunity exists).
  - **Red**: Not detected at all (critical gap).
- This visual becomes one of the most impactful elements of the executive report.

---

## Industry-Specific Threat Landscape

A Red Team Lead must tailor threat models to the organization's industry:

**Financial Services:**
- Threat actors: FIN7, Carbanak, Lazarus, Silence Group.
- Key concerns: SWIFT network access, ATM jackpotting, wire fraud, insider trading data.
- Regulatory context: PCI DSS, SOX, FFIEC guidance on penetration testing.

**Healthcare:**
- Threat actors: APT41, FIN12 (ransomware), state-sponsored actors targeting research.
- Key concerns: PHI exfiltration, ransomware impacting patient care, medical device security.
- Regulatory context: HIPAA, FDA guidance on medical device cybersecurity.

**Technology:**
- Threat actors: APT41, APT10, Nobelium, supply chain threat actors.
- Key concerns: Source code theft, supply chain compromise, cloud infrastructure abuse.
- Regulatory context: SOC 2, customer data protection obligations.

**Critical Infrastructure:**
- Threat actors: Sandworm, Volt Typhoon, Xenotime, Kamacite.
- Key concerns: ICS/SCADA compromise, safety system manipulation, operational disruption.
- Regulatory context: NERC CIP, TSA Security Directives, sector-specific frameworks.

---

## Attack Tree Methodology

Attack trees provide a structured way to model complex attack scenarios:

- **Root node**: The ultimate objective (e.g., "Exfiltrate customer database").
- **Child nodes**: Alternative paths to achieve the objective (phishing, external exploit,
  insider threat, physical access).
- **Leaf nodes**: Specific techniques required for each path.
- **Annotations**: Each node is annotated with estimated difficulty, likelihood of
  detection, and required capabilities.

Attack trees help the Lead prioritize engagement activities and communicate attack
complexity to stakeholders in visual, intuitive formats.

---

## Purple Team Exercise Design from Threat Models

Threat models directly inform purple team exercises. For each high-priority TTP:

1. Red team prepares the specific technique with realistic tooling.
2. Blue team documents their expected detection capability for that technique.
3. Red executes while blue observes in real-time.
4. Gap analysis: compare expected detection vs. actual detection.
5. Iterate: blue tunes detections, red re-executes to validate.

This approach is covered in detail in [Purple Team Integration](purple-team-integration.md).

---

## Measuring Coverage Gaps

Quantifying detection coverage against threat models is essential for program justification:

- **Coverage percentage**: Of the actor's known TTPs, what percentage can the SOC detect?
- **Coverage depth**: For detected TTPs, is detection at the behavioral level or only
  signature-based? Behavioral detections are more resilient to attacker adaptation.
- **Coverage trend**: Track coverage percentage over time across multiple engagements to
  demonstrate program value and security improvement.

---

## Tooling

| Tool | Purpose | Usage |
|------|---------|-------|
| MITRE ATT&CK Navigator | TTP mapping and visualization | Planning and reporting |
| Atomic Red Team | Unit tests for individual ATT&CK techniques | Validation and purple team |
| SCYTHE | Adversary emulation platform | Structured attack execution |
| AttackIQ | Breach and attack simulation | Continuous validation |
| Caldera | Automated adversary emulation | Scalable testing |
| Vectr | Purple team tracking and metrics | Engagement management |

---

## Cross-References

- [Engagement Lifecycle](engagement-lifecycle.md)
- [Purple Team Integration](purple-team-integration.md)
- [AD Attack Path Methodology](../12-active-directory-deep-dive/ad-attack-path-methodology.md)
