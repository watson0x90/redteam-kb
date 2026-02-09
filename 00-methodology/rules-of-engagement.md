# Rules of Engagement (ROE)

> **Category**: Methodology
> **Audience**: Red Team Lead / Manager

---

## Strategic Overview

The Rules of Engagement document is the single most important artifact in any red team
engagement. It protects the team legally, sets clear expectations with stakeholders, and
defines the boundaries within which operators work. A Lead who cannot articulate ROE
design principles is a liability, not an asset.

---

## ROE Document Components

A professional ROE document contains the following sections at minimum:

### 1. Authorization and Signatories

- **Authorizing executive**: Name, title, and signature of the individual with legal
  authority to approve testing. This is typically the CISO or CTO, but must be someone
  with actual authority over the systems in scope.
- **Engagement Lead**: Name and contact for the red team lead.
- **Date range**: Explicit start and end dates with timezone.
- **Document version**: ROE documents are living artifacts; version control matters.

### 2. Scope Definition

Scope must be defined with surgical precision. Ambiguity in scope creates legal risk.

| Scope Element | Include | Example |
|---------------|---------|---------|
| Network ranges | Explicit CIDR blocks | 10.0.0.0/8, 172.16.0.0/12 |
| Domains | Enumerated list | *.corp.example.com, mail.example.com |
| Cloud accounts | Account IDs and regions | AWS 123456789012 (us-east-1, eu-west-1) |
| Physical locations | Addresses and areas | HQ building floors 1-5, data center B |
| Personnel | Who can be targeted for SE | All employees except C-suite |
| Third-party systems | Explicit exclusions or inclusions | Shared hosting excluded, SaaS apps included |

### 3. Authorized Actions Matrix

Not all actions carry equal risk. The matrix categorizes actions by approval requirement:

**Pre-authorized (no additional approval needed):**
- Network scanning and enumeration
- Credential-based attacks (password spraying with lockout-aware thresholds)
- Phishing with pre-approved pretexts
- Exploitation of identified vulnerabilities in non-production systems

**Requires Lead approval:**
- Exploitation of production systems
- Privilege escalation beyond initial target segment
- Data exfiltration (even simulated)
- Lateral movement into sensitive network segments

**Requires stakeholder approval (written, within 4 hours):**
- Actions affecting availability of production services
- Social engineering of executives or board members
- Physical penetration of restricted areas
- Any action involving PII or regulated data

**Prohibited (never authorized):**
- Denial-of-service attacks against production systems
- Modification or destruction of production data
- Accessing systems outside defined scope
- Actions that could cause physical harm or safety incidents
- Attacking systems owned by third parties without their written consent

### 4. Emergency and Abort Procedures

Every ROE must define clear abort criteria and procedures:

**Immediate abort triggers:**
- Discovery of active, unauthorized compromise by a real threat actor.
- Unintended impact on production system availability.
- Request from authorized stakeholder to cease operations.
- Operator safety concern during physical engagement.

**Abort procedure:**
1. Cease all active operations immediately.
2. Notify the engagement Lead within 5 minutes.
3. Lead notifies the stakeholder emergency contact within 15 minutes.
4. Document the triggering event with timestamps and evidence.
5. Do not resume operations until written re-authorization is obtained.

**Emergency contacts (example structure):**

| Role | Name | Phone | Email | Availability |
|------|------|-------|-------|--------------|
| Primary stakeholder | [Name] | [Number] | [Email] | 24/7 |
| SOC Manager | [Name] | [Number] | [Email] | Business hours |
| Legal counsel | [Name] | [Number] | [Email] | Business hours |
| Red Team Lead | [Name] | [Number] | [Email] | 24/7 during engagement |

---

## Legal Considerations

### Relevant Legislation

A Red Team Lead must understand the legal landscape, even if they are not a lawyer:

- **CFAA (US)**: The Computer Fraud and Abuse Act criminalizes unauthorized access. Written
  authorization from the system owner is the primary defense. Ensure the authorizing party
  actually owns or controls the systems.
- **GDPR (EU)**: If testing involves EU citizen data, data handling procedures must comply
  with GDPR. Red team evidence containing PII must be encrypted, access-controlled, and
  deleted according to the data retention schedule.
- **Industry regulations**: PCI DSS, HIPAA, SOX, and NERC CIP all have implications for
  how testing is conducted in regulated environments.
- **Cross-border testing**: Testing systems in foreign jurisdictions may invoke local
  computer crime laws. Always obtain legal review for multinational engagements.

### Legal Safeguards

- Authorization letter must reference specific systems, not vague descriptions.
- Keep a copy of the signed authorization accessible to all operators during the engagement.
- If law enforcement contacts the team, cease operations and engage legal counsel immediately.
- Document everything. In a legal dispute, contemporaneous records are the strongest defense.

---

## Deconfliction Procedures

Deconfliction ensures red team activity can be distinguished from real threats. Without
deconfliction, the SOC may waste hours investigating simulated attacks while missing
actual incidents.

### Deconfliction Models

**Full deconfliction (white-carded SOC):**
- SOC leadership and select analysts are informed of the engagement.
- Red team provides daily summaries of source IPs, times, and techniques.
- SOC can quickly triage alerts as "known red team" vs. "potential real threat."
- Risk: SOC analysts may unconsciously ignore red team indicators, reducing realism.

**Partial deconfliction (trusted agent model):**
- A single trusted agent in the SOC knows about the engagement.
- The trusted agent can quietly deconflict alerts without informing the broader team.
- Preserves realism while maintaining a safety valve.
- This is the recommended model for most engagements.

**No deconfliction (full blind):**
- Nobody in the SOC knows about the engagement.
- Maximum realism but highest operational risk.
- Only appropriate for mature organizations with explicit executive sponsorship.
- Requires robust abort procedures and rapid escalation paths.

### Real Threat Discovery Protocol

One of the most critical scenarios a Red Team Lead will face:

> "During an engagement, your operator discovers indicators of an actual compromise --
> a webshell that your team did not deploy, or C2 traffic to a known threat actor domain."

**Response procedure:**
1. Immediately document the finding with screenshots, timestamps, and network captures.
2. Do not interact with the threat actor's infrastructure or tooling.
3. Notify the engagement stakeholder and SOC through the emergency contact chain.
4. Pause red team operations in the affected segment to avoid contaminating evidence.
5. Offer to support the incident response effort if requested.
6. Resume red team operations only after written re-authorization from the stakeholder.

---

## Scope Modification Process

Engagements rarely proceed exactly as planned. When operators discover paths that lead
outside the original scope, a formal modification process is required:

1. Operator identifies potential out-of-scope opportunity and notifies the Lead.
2. Lead evaluates the risk and potential value of the expanded scope.
3. Lead submits a written scope modification request to the stakeholder, including:
   - Description of the new target or technique.
   - Justification for the expansion.
   - Risk assessment for the additional activity.
   - Updated timeline if needed.
4. Stakeholder provides written approval or denial.
5. ROE document is updated with a new version number.
6. Operators are briefed on the expanded scope boundaries.

Never expand scope without written approval. "I thought it was in scope" is not a defense.

---

## Common ROE Pitfalls

### Pitfalls the Lead Must Avoid

- **Vague scope definitions**: "Test the corporate network" is insufficient. Specify CIDR
  ranges, domains, and cloud accounts explicitly.
- **Missing third-party exclusions**: Shared infrastructure, SaaS platforms, and CDN
  providers are common sources of scope confusion.
- **No data handling clause**: If operators capture credentials, PII, or sensitive business
  data during testing, the ROE must specify how it is stored, protected, and destroyed.
- **Verbal authorization**: If it is not in writing, it does not exist. Even for internal
  red teams, maintain a formal authorization trail.
- **Stale ROE**: If the engagement is extended or scope changes, update the document.
  Operating under an expired ROE is operating without authorization.
- **Assuming cloud provider consent**: Testing in AWS, Azure, or GCP requires compliance
  with the provider's penetration testing policy. Most major providers have pre-approval
  processes or acceptable use policies that must be followed.

---

## ROE Template Structure

A production-ready ROE document follows this structure:

```
1. Document Control (version, date, signatories)
2. Engagement Overview (objectives, type, duration)
3. Scope (in-scope systems, out-of-scope systems, third-party considerations)
4. Authorized Actions Matrix (pre-authorized, lead-approved, stakeholder-approved, prohibited)
5. Communication Plan (cadence, channels, escalation path)
6. Deconfliction Procedures (model, trusted agents, daily reporting)
7. Emergency and Abort Procedures (triggers, contacts, resumption criteria)
8. Data Handling (collection, storage, encryption, retention, destruction)
9. Legal Acknowledgments (authorization, liability, compliance)
10. Signatures (authorizing executive, legal counsel, red team lead)
```

---

## Cross-References

- [Engagement Lifecycle](engagement-lifecycle.md)
- [Threat Modeling](threat-modeling.md)
- [Reporting and Communication](reporting-and-communication.md)
