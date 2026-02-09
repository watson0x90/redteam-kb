# Business Impact Framing

> **Category**: Reporting & Communication
> **Audience**: Red Team Lead to Executive Stakeholders

---

## Strategic Overview

The ability to translate technical findings into business language is what separates
a senior operator from a Red Team Lead. Executives, board members, and risk committees
do not care about NTLM relay attacks or Kerberoasting. They care about:

- **Will we get breached?** (likelihood)
- **How bad will it be?** (impact)
- **How much will it cost us?** (financial exposure)
- **Are we compliant?** (regulatory risk)
- **What do we do about it?** (actionable remediation)

Every finding in a red team report must be framed in these terms.

---

## Technical-to-Business Translation Framework

### The CIA Triad in Business Language

#### 1. Confidentiality Impact

| Technical Finding | Business Translation |
|---|---|
| DCSync extracted all domain password hashes | An attacker could access every employee email, financial system, customer database, and executive communication. Under GDPR Art. 83, this exposure represents potential fines of up to 4% of global annual revenue. |
| SQL injection returned customer PII | Customer records including names, addresses, SSNs, and payment data are directly accessible. Mandatory breach notification to ~50K customers estimated at $150-200 per record (IBM CODB). |
| Cloud storage bucket publicly accessible | Intellectual property including source code, product roadmaps, and M&A documentation is exposed to the internet. Competitor access could materially impact market position. |
| Email compromise of CFO mailbox | Access to wire transfer approvals, financial forecasts, board communications, and insider information. SEC disclosure obligations triggered; potential for BEC-style financial fraud. |

#### 2. Integrity Impact

| Technical Finding | Business Translation |
|---|---|
| Golden Ticket provides indefinite domain access | An attacker maintains invisible, permanent access to modify financial records, alter audit trails, manipulate ERP transactions, and change compliance documentation -- all without triggering existing controls. |
| CI/CD pipeline compromise | Attacker can inject malicious code into software builds shipped to customers. Supply chain attack potential similar to SolarWinds (est. $100M+ in remediation costs across affected organizations). |
| Database write access achieved | Financial records, inventory systems, and customer account balances could be silently modified. Audit trail integrity cannot be guaranteed after compromise window. |

#### 3. Availability Impact

| Technical Finding | Business Translation |
|---|---|
| Backup systems accessible from compromised segment | A ransomware event could render all systems unrecoverable. Estimated recovery: 2-4 weeks minimum. Business losses at $X per day of downtime = $Y total exposure. |
| Single points of failure in AD architecture | One compromised domain controller could cascade to complete authentication failure across all business applications, affecting N thousand employees and M customer-facing services. |
| OT/IT network boundary weakness | Manufacturing systems accessible from corporate network. A destructive attack could halt production lines with estimated cost of $X per hour of downtime. |

---

## Quantification Methodologies

### FAIR (Factor Analysis of Information Risk)

The industry-standard model for quantifying cyber risk in financial terms.

```
Risk = Frequency x Magnitude

Loss Event Frequency (LEF):
  - Threat Event Frequency (TEF): How often does the threat actor attempt?
  - Vulnerability (Vuln): What percentage of attempts succeed?
  LEF = TEF x Vuln

Loss Magnitude (LM):
  - Primary Loss: Direct costs (response, remediation, replacement)
  - Secondary Loss: Fines, lawsuits, reputation, lost business
  LM = Primary + Secondary

Annualized Loss Expectancy (ALE) = LEF x LM
```

**Example Calculation for Red Team Finding:**

```
Finding: Domain Admin achievable from internet-facing application in 4 steps

TEF: 12/year (monthly targeting attempts for this industry)
Vuln: 0.7 (70% success rate given current controls)
LEF: 8.4 events/year

Primary Loss: $2M (IR, remediation, recovery)
Secondary Loss: $8M (regulatory fines, legal, reputation)
LM: $10M

ALE = 8.4 x $10M = $84M annualized risk exposure

Remediation cost: $500K (network segmentation + PAM + monitoring)
ROI: 168x return on security investment
```

### Industry Benchmarks

Reference these in reports and presentations:

- **IBM Cost of a Data Breach 2024**: $4.88M average total cost
- **Healthcare**: $9.77M average (highest industry)
- **Financial Services**: $6.08M average
- **Ransomware-specific**: $5.13M average (excluding ransom payment)
- **Mean time to identify breach**: 194 days
- **Mean time to contain**: 64 days
- **Breaches with AI/automation savings**: $2.22M less than without

### Regulatory Fine Frameworks

| Regulation | Maximum Fine | Trigger |
|---|---|---|
| GDPR | 4% global annual revenue or 20M EUR | PII of EU residents exposed |
| HIPAA | $2.13M per violation category per year | PHI exposure |
| PCI-DSS | $5K-100K per month until compliant | Cardholder data breach |
| SOX | $5M fine + 20 years imprisonment (officers) | Financial reporting integrity |
| NYDFS 23 NYCRR 500 | Variable, significant | Financial services cybersecurity |
| SEC Cyber Rules (2024) | Material incident disclosure within 4 days | Public company cyber incidents |

---

## Remediation Prioritization

### Risk-Based Priority Matrix

```
Priority = (Likelihood x Impact) / Remediation Effort

Quadrant Model:
  Q1 - High Impact, Low Effort   = "Quick Wins" (do immediately)
  Q2 - High Impact, High Effort  = "Strategic Projects" (plan and fund)
  Q3 - Low Impact, Low Effort    = "Housekeeping" (batch and schedule)
  Q4 - Low Impact, High Effort   = "Deprioritize" (accept or defer)
```

### Example Remediation Roadmap

```
Phase 1 (0-30 days) -- Quick Wins:
  [CRITICAL] Disable NTLM where possible, enforce SMB signing
  [CRITICAL] Deploy LAPS for local admin passwords
  [HIGH]     Patch the 3 internet-facing CVEs exploited during engagement
  [HIGH]     Restrict service account permissions (5 over-privileged accounts)
  Estimated cost: $50K | Risk reduction: 40%

Phase 2 (30-90 days) -- Core Improvements:
  [CRITICAL] Implement tiered administration model (Tier 0/1/2)
  [HIGH]     Deploy PAM solution for privileged access
  [HIGH]     Segment backup network from production
  [MEDIUM]   Enhance logging coverage (currently 60% blind spots)
  Estimated cost: $300K | Risk reduction: additional 30%

Phase 3 (90-180 days) -- Strategic Investments:
  [HIGH]     Implement network micro-segmentation
  [MEDIUM]   Deploy deception technology (honeytokens, honeypots)
  [MEDIUM]   Establish detection engineering program
  [MEDIUM]   Conduct AD forest recovery exercise
  Estimated cost: $500K | Risk reduction: additional 20%

Total investment: $850K | Total risk reduction: ~90%
Compared to ALE of $84M = 99x ROI
```

---

## Executive Presentation Framework

### Structure for a 30-Minute Board Presentation

```
1. Executive Summary (3 min)
   - Engagement objective in one sentence
   - Overall risk rating (Critical/High/Medium/Low)
   - Top 3 findings in business terms
   - Total financial exposure estimate

2. Attack Narrative (10 min)
   - Visual diagram: internet -> initial access -> DA -> business impact
   - "An attacker starting from [entry point] could reach [business system]
     in [N] steps over [X] days"
   - Compare to real-world breaches in same industry
   - Show what the SOC detected vs. what they missed

3. Risk Quantification (5 min)
   - Financial exposure per finding
   - Regulatory implications
   - Comparison to industry benchmarks
   - Insurance coverage gap analysis

4. Remediation Roadmap (7 min)
   - Phased approach with timelines and costs
   - Quick wins already identified
   - Strategic investments needed
   - Expected risk reduction per phase

5. Q&A and Next Steps (5 min)
   - Specific asks: budget, authority, timeline
   - Offer to brief technical teams separately
   - Schedule re-test to validate improvements
```

### Presentation Do's and Don'ts

**Do:**
- Lead with business impact, not technical details
- Use visual attack path diagrams (BloodHound graphs simplified for executives)
- Compare to real breaches the audience has heard of ("our exposure is similar to...")
- Provide specific, actionable recommendations with cost estimates
- Include a maturity score and benchmark against industry peers
- Show progress over time if this is a recurring engagement
- Know your audience: CISO vs CFO vs Board vs CEO need different messaging

**Don't:**
- Start with a list of CVEs or technical vulnerabilities
- Use jargon without explanation (assume zero technical knowledge)
- Present findings without remediation options
- Overwhelm with volume -- focus on the critical narrative
- Make it personal ("your team failed") -- frame as "opportunity to improve"
- Forget to acknowledge what IS working (defenders need wins too)

---

## Maturity Scoring Model

### Red Team Resilience Score (example framework)

| Domain | Level 1 | Level 3 | Level 5 |
|---|---|---|---|
| **Prevention** | Default configs, no hardening | Industry-standard hardening, patching | Zero trust, microsegmentation, PAM |
| **Detection** | Basic AV only | EDR + SIEM with correlation | Custom detection engineering, threat hunting |
| **Response** | No IR plan | Documented IR plan, annual test | Automated containment, regular exercises |
| **Recovery** | Untested backups | Tested quarterly, documented RTO | Immutable backups, automated recovery, <4hr RTO |
| **Governance** | Ad hoc security | Policy framework, annual assessments | Continuous assessment, risk quantification |

Score each domain 1-5 and present as a radar chart. Track improvement across engagements.

---

## Cross-References

- [Ransomware Simulation](ransomware-simulation.md)
- [Data Destruction Simulation](data-destruction.md)
- [Purple Team Integration](../00-methodology/purple-team-integration.md)
- [Engagement Methodology](../00-methodology/README.md)
