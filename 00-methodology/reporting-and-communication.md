# Reporting & Communication

> **Category**: Methodology
> **Audience**: Red Team Lead / Manager

---

## Strategic Overview

Reporting is where red team value is realized. The most technically brilliant engagement is worthless if findings are not communicated in a way that drives organizational change. A Red Team Lead must translate technical findings into business risk language, tailor messaging to diverse stakeholders, and ultimately drive remediation. Mastery of reporting and communication is the single clearest differentiator between a skilled operator and a true Lead.

---

## Executive Reporting

### Executive Summary Structure

Every executive report must open with a risk-focused summary free of technical jargon. The structure should follow:

1. **Engagement objective** - What was the red team asked to test?
2. **Overall risk rating** - A single, clear verdict (Critical / High / Moderate / Low).
3. **Key findings summary** - Three to five bullet points describing business impact, not technical detail.
4. **Strategic recommendations** - Prioritized actions the organization should take.

### Translating Technical Findings to Business Impact

Technical operators describe what happened. Leads describe what it means.

| Technical Finding | Business Impact Translation |
|---|---|
| Domain Admin compromised via Kerberoasting | Complete control of all business systems, including financial data, email, and intellectual property |
| SQL injection on customer portal | Potential exposure of all customer PII; regulatory notification obligations triggered |
| Phishing achieved 34% click rate | One in three employees will grant an attacker initial access; security awareness program is ineffective |
| Cloud IAM misconfiguration | Unrestricted access to production databases; potential for data exfiltration at scale |

### Risk Rating Framework

Use a likelihood-times-impact matrix. Likelihood should reflect attacker capability and exposure. Impact should reflect business consequence, not technical severity alone.

- **Critical**: Exploitation is trivial and leads to catastrophic business impact (data breach, regulatory action, operational shutdown).
- **High**: Exploitation requires moderate skill but leads to significant business impact.
- **Medium**: Exploitation requires chaining or insider context; impact is contained.
- **Low**: Theoretical or edge-case; minimal business consequence.

### Visual Attack Path Narratives

Include diagrams that show the progression from initial access to objective completion. These should be understandable by a non-technical board member. Use color-coded nodes (green for initial access, yellow for escalation, red for objective) and annotate each step with the business system affected.

### Benchmarking Against Industry Frameworks

Reference MITRE ATT&CK coverage, NIST CSF maturity, and industry-specific benchmarks to contextualize findings. This positions the red team as a strategic function, not just a penetration testing service.

---

## Technical Reporting

### Full Attack Narrative

The technical report should read as a chronological story of the engagement. It must answer: What did we try? What worked? What failed? What would a real adversary do next?

Structure each phase: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement, Collection, Exfiltration, and Impact.

### Finding Format

Each discrete finding should follow a consistent template:

1. **Title** - Clear, concise name for the vulnerability or weakness.
2. **Severity** - Critical / High / Medium / Low / Informational.
3. **Description** - What the issue is and why it exists.
4. **Impact** - What an attacker can achieve by exploiting it.
5. **Evidence** - Screenshots, command output, log entries with timestamps.
6. **MITRE ATT&CK Mapping** - Technique ID and tactic alignment.
7. **Remediation** - Specific, actionable steps to fix the issue.
8. **References** - Vendor advisories, CIS benchmarks, or other authoritative sources.

### Severity Scoring

Adapt CVSS for red team context. Pure CVSS scores often misrepresent red team findings because they do not account for chained attacks or environmental factors. Supplement with narrative justification for each rating and ensure consistency across engagements.

### Evidence Chain of Custody

Maintain timestamped logs, screenshots, and packet captures. Store evidence in encrypted, access-controlled repositories. This protects both the red team and the organization, especially if a real compromise is discovered during the engagement.

### Remediation Guidance with Prioritization

Group remediation into three tiers:

- **Immediate** (0-30 days): Critical findings that represent active exploitable risk.
- **Short-term** (30-90 days): High findings that require architectural changes.
- **Long-term** (90-180 days): Medium findings and strategic improvements.

---

## Communication During Engagement

### Status Update Cadence and Format

Provide structured updates at agreed intervals (daily for short engagements, weekly for extended operations). Each update should include: activities performed, findings to date, upcoming planned activities, and any blockers or risks.

### Escalation Procedures

Define escalation triggers before the engagement begins:

- **Critical vulnerability with active exploitation evidence**: Immediate phone call to engagement sponsor and CISO.
- **Evidence of real compromise by a third party**: Immediate escalation; pause red team activities in affected systems.
- **Potential for unintended business disruption**: Immediate notification to the trusted agent.

### Deconfliction Communication with SOC

Establish a deconfliction protocol with the SOC to distinguish red team activity from genuine threats. This typically involves a trusted agent within the SOC who can confirm or deny red team attribution without revealing the engagement to the broader analyst team. Use unique identifiers (engagement codes, specific IP ranges) to enable rapid deconfliction.

### Secure Communication Channels

All engagement communications must use encrypted channels. Use end-to-end encrypted messaging (Signal, Wickr) for real-time coordination. Transfer findings via encrypted file shares. Never send raw findings, credentials, or exploitation details over email or unencrypted chat.

---

## Stakeholder Management

### Tailoring Message to Audience

| Audience | Focus | Language | Detail Level |
|---|---|---|---|
| Board of Directors | Business risk, regulatory exposure, competitive impact | Non-technical, financial | Very high-level |
| CISO / Security Leadership | Risk posture, detection gaps, strategic remediation | Security-informed, strategic | Moderate |
| SOC / Detection Engineering | Detection gaps, alert tuning, log coverage | Technical, operational | High |
| Engineering / IT Operations | Specific vulnerabilities, misconfigurations, patching | Technical, actionable | Very detailed |

### Managing Expectations

Set clear expectations during scoping about what a red team engagement can and cannot prove. A single engagement is a snapshot, not a comprehensive assessment. Be explicit about limitations: time constraints, scope restrictions, and techniques not attempted.

### Handling Pushback on Findings

When stakeholders dispute findings, respond with evidence, not ego. Offer to demonstrate the exploit in a controlled setting. Emphasize that the goal is organizational improvement, not blame. Document all disputed findings and their resolution.

### Building Credibility Through Clear Communication

Credibility is earned through accuracy, consistency, and professionalism. Never overstate a finding. Never use fear, uncertainty, or doubt as a persuasion tactic. Present facts, provide context, and let the evidence speak.

---

## Metrics & Measurement

### Engagement Metrics

- **Time to initial access**: Measures perimeter and user awareness effectiveness.
- **Time to objective**: Measures overall defensive depth.
- **Detection rate**: Percentage of red team activities that triggered alerts.
- **Mean time to detect (MTTD)**: How long before the SOC identified red team activity.
- **Techniques attempted vs. successful**: Reveals specific defensive gaps.

### Program Metrics

- **Year-over-year improvement**: Track detection rate and time-to-detect across engagements.
- **Remediation rate**: Percentage of findings remediated within agreed timelines.
- **Repeat finding rate**: Findings that recur across engagements indicate systemic issues.
- **Coverage breadth**: Percentage of MITRE ATT&CK techniques tested over a rolling 12-month period.

### Maturity Model Scoring

Score the organization's defensive maturity against a defined model (e.g., a five-level scale from reactive to optimized). Track progression over time and use the score to justify continued red team investment.

### ROI Demonstration for Red Team Program

Quantify value by correlating red team findings with avoided breach costs, reduced insurance premiums, improved audit results, and faster incident response times. Present this data annually to justify budget and headcount.

---

## Cross-References

- [Engagement Lifecycle](engagement-lifecycle.md)
- [Team Management](team-management.md)
- [Business Impact Framing](../14-impact/business-impact-framing.md)
