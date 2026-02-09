# Impact

This section covers the techniques and frameworks used to demonstrate real-world business impact during red team engagements. Impact actions prove to stakeholders that identified attack paths translate into tangible organizational risk.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [13 - Cloud Security](../13-cloud-security/README.md) | **14 - Impact** | [Appendices](../appendices/README.md) |

**MITRE ATT&CK Tactic:** [TA0040 - Impact](https://attack.mitre.org/tactics/TA0040/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Ransomware Simulation | [ransomware-simulation.md](ransomware-simulation.md) | T1486 | Very High | Safe ransomware simulation methodology for testing detection and response capabilities |
| Data Destruction | [data-destruction.md](data-destruction.md) | T1485 | Very High | Demonstrating data destruction impact in controlled scenarios with full recoverability |
| Business Impact Framing | [business-impact-framing.md](business-impact-framing.md) | N/A | N/A | Translating technical findings into business risk language for executive and board communication |

---

## Section Overview

Impact is the culmination of the attack chain and the phase that translates technical compromise into business-relevant consequences. In real-world adversary operations, impact includes ransomware deployment, data destruction, data theft for extortion, and disruption of business operations. Red team engagements simulate these actions in controlled, reversible ways to test detection and response capabilities without causing actual harm. Ransomware simulation validates whether the organization can detect encryption activity, isolate affected systems, and execute recovery procedures. Data destruction scenarios test backup integrity and disaster recovery timelines. Beyond technical simulation, business impact framing is the critical skill that turns a list of vulnerabilities into a compelling risk narrative for executive leadership. This involves mapping attack paths to specific business processes, quantifying potential financial impact, and aligning findings with the organization's risk appetite framework. Every technical finding in the engagement report should connect to one of these impact scenarios to drive remediation prioritization.
