# Engagement Lifecycle

> **Category**: Methodology
> **Audience**: Red Team Lead / Manager

---

## Strategic Overview

The engagement lifecycle is the backbone of professional red team operations. A Red Team
Lead must own every phase, from the earliest scoping conversations through final closeout
and retesting. Mastery here signals that a candidate can manage complex, multi-week
operations without dropping the ball on legal, operational, or interpersonal requirements.

---

## Phase 1: Scoping and Planning

### Stakeholder Alignment

Before a single packet is sent, the Lead must align with key stakeholders:

- **CISO / Security Leadership**: Confirm strategic objectives. Are we testing detection
  capability, incident response readiness, or validating a specific control investment?
- **Legal and Compliance**: Obtain written authorization. Clarify jurisdictional concerns,
  especially for multinational organizations with assets in regions governed by GDPR,
  PDPA, or other data protection frameworks.
- **SOC / DFIR Leadership**: Decide on deconfliction model. Will the SOC be informed
  (white-carded) or tested blind? A hybrid model is common -- SOC leadership knows, but
  analysts do not.
- **Business Unit Owners**: Identify critical systems with low tolerance for disruption.
  Production databases, payment processing systems, and safety-critical OT environments
  require explicit risk acceptance.

### Defining Objectives

Not all red team engagements are the same. The Lead must clarify the engagement model:

| Model | Description | When to Use |
|-------|-------------|-------------|
| Adversary Emulation | Replicate specific threat actor TTPs | Validate defenses against known threats |
| Goal-Based | Achieve defined objective (e.g., domain admin, data exfil) | Test end-to-end security posture |
| Assumed Breach | Start with internal access | Focus on post-compromise detection and response |
| Continuous | Ongoing operations over months | Mature organizations with established programs |

### Threat Intelligence-Driven Scoping

The Lead should consume CTI reports to determine which adversary profiles are relevant.
A financial institution faces different threats (FIN7, Carbanak) than a defense contractor
(APT29, APT41). This intelligence shapes the TTPs selected for emulation and ensures
the engagement delivers actionable results rather than generic findings.

### Timeline and Communication Cadence

- Define milestones: infrastructure ready, initial access achieved, objective completed.
- Establish check-in cadence: daily operator standups, weekly stakeholder updates.
- Set a hard stop date with criteria for extension requests.
- Build in buffer time -- engagements rarely go exactly as planned.

---

## Phase 2: Rules of Engagement

The ROE document is the legal and operational contract. See [Rules of Engagement](rules-of-engagement.md)
for detailed coverage. At the lifecycle level, the Lead must ensure:

- Written authorization is signed before any testing begins.
- Scope boundaries are unambiguous (IP ranges, domains, cloud accounts, physical locations).
- An authorized actions matrix defines what requires additional approval.
- Emergency contacts and abort procedures are documented and tested.
- Data handling requirements are explicit, especially for PII and regulated data.

---

## Phase 3: Infrastructure Setup

### C2 Architecture

Professional red teams deploy layered C2 infrastructure:

- **Long-haul C2**: Low-and-slow channels for persistent access (DNS, HTTPS with high
  jitter). These survive initial detection of short-haul channels.
- **Short-haul C2**: Interactive channels for active operations (HTTPS, SMB named pipes).
- **Redirectors**: Cloud-based redirectors that proxy traffic and can be burned without
  exposing core infrastructure.
- **Domain fronting or CDN abuse**: Where legally and contractually permitted, to test
  network monitoring capabilities against evasive channels.

### Operational Preparation

- Categorize domains through web filtering vendors (minimum 2 weeks lead time).
- Build and test payloads in an isolated lab that mirrors the target environment.
- Establish encrypted communication channels for the operator team (Signal, Keybase, or
  equivalent with disappearing messages).
- Prepare evidence collection templates and chain-of-custody procedures.

---

## Phase 4: Execution

### Kill Chain Progression

The Lead must maintain situational awareness across the full kill chain:

1. **Reconnaissance**: OSINT, passive DNS, LinkedIn harvesting, technology fingerprinting.
2. **Initial Access**: Phishing, external exploitation, physical access, supply chain.
3. **Execution and Persistence**: Payload delivery, persistence mechanisms, AV/EDR evasion.
4. **Privilege Escalation**: Local privesc, credential harvesting, Kerberoasting, delegation abuse.
5. **Lateral Movement**: RDP, WMI, PSExec, DCOM, SSH pivoting.
6. **Collection and Exfiltration**: Identify crown jewels, stage data, exfiltrate through C2.

### Operator Management During Execution

- **Daily standups**: Each operator reports progress, blockers, and OPSEC concerns.
- **Task delegation**: Assign operators based on specialization (one on AD, one on cloud,
  one on social engineering).
- **Go/no-go decisions**: The Lead decides when to escalate (risk louder actions for
  progress) versus persist quietly (maintain access for future phases).
- **OPSEC monitoring**: Continuously assess whether the blue team has detected activity.
  If indicators suggest detection, decide whether to burn the access and pivot or go quiet.

### Evidence Collection

Every action must be logged. Screenshots, command output, timestamps, and network captures
form the foundation of the final report. Sloppy evidence collection during execution
creates painful report-writing phases later.

---

## Phase 5: Reporting and Debrief

### Report Components

A Lead-quality report contains:

- **Executive Summary**: Business risk language, not technical jargon. "We achieved
  access to customer PII within 72 hours using techniques consistent with APT29" -- not
  "We ran Mimikatz and got DA."
- **Attack Narrative**: A chronological story of the engagement with decision points
  highlighted. This is the most valuable section for defenders.
- **Technical Findings**: Each finding with severity, evidence, affected systems, and
  remediation guidance.
- **Detection Gap Analysis**: What the SOC detected, what they missed, and recommendations
  for improvement.
- **ATT&CK Mapping**: Every technique used mapped to MITRE ATT&CK with detection status.

### Debrief Sessions

- **Technical debrief** with SOC/DFIR: Replay the attack, show what was visible in logs,
  identify detection opportunities.
- **Executive debrief** with CISO and leadership: Focus on business risk and strategic
  recommendations.
- **Purple team replay**: Walk through key attack phases with defenders in real-time.
  See [Purple Team Integration](purple-team-integration.md).

---

## Phase 6: Retesting and Continuous Improvement

### Remediation Verification

Schedule retesting 30-90 days after remediation. Verify that:

- Specific vulnerabilities are patched or mitigated.
- Detection rules are in place for the TTPs used.
- Process improvements (e.g., MFA enforcement, network segmentation) are operational.

### Program Maturity

After each engagement, update the organization's security maturity scorecard. Track trends
over multiple engagements to demonstrate program value and justify budget.

---

## Leading the Engagement: Decision Frameworks

### Scope Creep vs. Opportunity Exploitation

During execution, operators will discover paths outside the original scope. The Lead must
decide quickly:

- **Expand scope**: If the finding represents significant risk and stakeholders approve.
- **Document and defer**: If the finding is valuable but pursuing it risks the primary
  objective or violates ROE.
- **Ignore**: If it is a distraction from the engagement objectives.

### Stakeholder Communication During Active Operations

The Lead serves as the single point of contact. Stakeholders should never hear about
red team activity from the SOC first. Proactive communication builds trust and ensures
the program survives organizational politics.

---

## Cross-References

- [Rules of Engagement](rules-of-engagement.md)
- [Reporting and Communication](reporting-and-communication.md)
- [Lab Infrastructure](lab-infrastructure.md)
- [Team Management](team-management.md)
