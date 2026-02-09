# Purple Team Integration

> **Category**: Methodology
> **Audience**: Red Team Lead

---

## Strategic Overview

Purple teaming is not a separate team. It is a methodology that combines red team offensive
expertise with blue team defensive capabilities to maximize the security return on
investment. A Red Team Lead who only values "winning" against defenders is optimizing for
the wrong metric. The right metric is organizational security improvement.

---

## Purple Team Philosophy

### The Fundamental Shift

Traditional red teaming operates on a confrontational model: red attacks, blue defends,
and a report is delivered weeks later. This model has significant limitations:

- **Delayed feedback**: Blue team learns about gaps weeks after the engagement ends.
- **Limited iterations**: If red bypasses a control, there is no opportunity to test
  whether a tuned control would have caught it.
- **Adversarial culture**: Red and blue teams may develop antagonistic relationships that
  undermine collaboration.

Purple teaming replaces this with a collaborative model:

- **Real-time feedback**: Blue team sees attack execution as it happens and can iterate
  on detections immediately.
- **Rapid iteration**: Red executes a technique, blue checks telemetry, blue tunes
  detection, red re-executes to validate. This cycle can repeat multiple times in a
  single session.
- **Shared ownership**: Both teams own the outcome. Security improvement is a joint
  achievement.

### When Purple Teaming Is Appropriate

Purple teaming is not always the right model. Understanding when to use it is a key
leadership decision:

| Scenario | Model | Rationale |
|----------|-------|-----------|
| Testing detection for specific TTPs | Purple | Real-time iteration maximizes detection tuning |
| Assessing overall security posture | Red (traditional) | Realism requires blue team to operate without advance notice |
| Validating incident response procedures | Red (blind) | Response procedures must be tested under realistic conditions |
| Building new detection capabilities | Purple | Collaborative development is more efficient |
| Regulatory compliance testing | Red or Pen Test | Compliance frameworks often specify methodology |
| Training junior SOC analysts | Purple | Educational value is highest with real-time coaching |

---

## Real-Time Collaboration Models

### Model 1: Shoulder-to-Shoulder

Red and blue team members sit together (physically or virtually). Red executes a technique
while blue watches telemetry in real-time.

**Process:**
1. Red team announces the technique they will execute (e.g., "We are going to perform
   a DCSync attack against the domain controller").
2. Blue team documents their expected detection capability before execution.
3. Red executes the technique.
4. Blue checks SIEM, EDR, and network monitoring tools for alerts and telemetry.
5. Both teams discuss what was visible, what was missed, and why.
6. Blue tunes or creates detections based on findings.
7. Red re-executes to validate the new detection.

### Model 2: Guided Exercise

Red team provides a structured exercise with pre-defined techniques, but blue team
operates independently during execution.

**Process:**
1. Red team distributes an exercise plan listing techniques to be tested (ATT&CK IDs).
2. Blue team prepares by reviewing their detection coverage for those techniques.
3. Red executes techniques on a schedule (e.g., one technique per hour).
4. Blue team attempts to detect each technique using existing tools and processes.
5. After the exercise, both teams review results together and identify gaps.

### Model 3: Autonomous with Debrief

Red team operates independently (traditional red team engagement) but conducts a
detailed purple team debrief after the engagement.

**Process:**
1. Red team conducts a standard engagement without blue team knowledge.
2. After the engagement, red team replays the attack step-by-step with the blue team.
3. Blue team reviews their logs and telemetry for each step to identify what they saw
   and what they missed.
4. Joint remediation planning session follows.

---

## Detection Gap Analysis

The primary deliverable of purple team exercises is a comprehensive detection gap analysis.

### Detection Status Categories

For each technique tested, categorize the detection status:

- **Detected and Alerted**: The SOC received an actionable alert within an acceptable
  timeframe. This is the target state.
- **Logged but Not Alerted**: Telemetry exists in logs (SIEM, EDR, network captures) but
  no alert was generated. This represents a detection engineering opportunity -- the data
  is available, the rule is missing.
- **Partially Logged**: Some telemetry exists but is insufficient for reliable detection.
  Data source configuration improvements are needed.
- **Not Logged**: No telemetry was captured at all. This requires new data sources,
  agent deployment, or architectural changes.
- **Not Applicable**: The technique is not relevant to the environment (e.g., macOS
  techniques in a Windows-only environment).

### Building Detection Improvement Roadmaps

Gap analysis feeds directly into a prioritized detection improvement roadmap:

1. **Quick wins**: Techniques where telemetry exists but alerting rules are missing.
   These can often be addressed within days.
2. **Configuration improvements**: Techniques where partial telemetry exists but logging
   needs to be enhanced (e.g., enabling PowerShell Script Block Logging, Sysmon deployment).
3. **Architecture changes**: Techniques where no telemetry exists and new data sources
   are needed (e.g., network tap deployment, cloud audit log integration).
4. **Long-term investments**: Techniques that require significant capability development
   (e.g., behavioral analytics, ML-based detection, deception technology deployment).

---

## Metrics for Purple Team Effectiveness

A Red Team Lead must quantify the value of purple team exercises. The following metrics
demonstrate program impact:

### Detection Metrics

- **Detection coverage**: Percentage of tested ATT&CK techniques that are detected.
  Track this across exercises to show improvement.
- **Mean Time to Detect (MTTD)**: Average time from technique execution to SOC alert.
  Purple team exercises provide controlled measurement of this metric.
- **Mean Time to Respond (MTTR)**: Average time from alert to containment action.
  Measures the full SOC response pipeline.
- **False positive rate**: Do new detections created during purple exercises generate
  excessive noise? Quality matters as much as quantity.

### Operational Metrics

- **Detection rules created per exercise**: Quantifies the tangible output of each session.
- **Coverage improvement rate**: Percentage point increase in detection coverage between
  exercises.
- **SOC analyst confidence**: Qualitative measure from post-exercise surveys. Analysts who
  participate in purple exercises report higher confidence in handling real incidents.

### Business Metrics

- **Cost per detection gap identified**: Compare the cost of purple team exercises vs.
  the cost of discovering gaps during a real incident.
- **Remediation velocity**: Time from gap identification to detection implementation.
  Purple team exercises with real-time iteration achieve faster remediation than
  traditional red team reports.

---

## Building Relationships with SOC and DFIR Teams

### Cultural Considerations

The Red Team Lead sets the tone for the red-blue relationship. Critical principles:

- **Never humiliate defenders publicly.** Present findings as opportunities, not failures.
  "We identified an opportunity to improve Kerberoasting detection" -- not "The SOC
  completely missed our Kerberoasting attack."
- **Share knowledge generously.** Teach blue team members how attacks work. When they
  understand the attacker's perspective, they write better detections.
- **Acknowledge good detection.** When the SOC catches red team activity, celebrate it.
  This reinforces that detection is the goal, not stealth.
- **Invite blue team input on red team planning.** Ask defenders what they want tested.
  This gives them ownership and ensures exercises address their real concerns.

### Knowledge Transfer Sessions

Regular knowledge transfer builds capability across both teams:

- **Technique deep-dives**: Red team presents a specific attack technique, demonstrates
  it in a lab, and shows what artifacts it generates for detection.
- **Tool familiarization**: Red team demonstrates offensive tools so blue team understands
  the artifacts they produce (Cobalt Strike malleable C2 profiles, Rubeus output formats,
  Impacket network signatures).
- **Detection engineering workshops**: Joint sessions where red and blue collaborate on
  writing detection rules. Red team provides ground truth; blue team provides platform
  expertise.
- **Incident response tabletops**: Red team designs realistic scenarios based on current
  threat intelligence. SOC and DFIR teams walk through their response procedures.

---

## Joint Attack Simulation Exercises

### Structured Exercise Format

A well-designed joint exercise follows this structure:

**Pre-exercise (1-2 days before):**
- Red team selects 10-15 ATT&CK techniques relevant to a specific threat actor.
- Blue team receives the list of techniques (but not the specific implementations).
- Both teams prepare independently.

**Exercise day (4-8 hours):**
- Morning session: Red executes techniques 1-5 while blue monitors and detects.
- Midday review: Both teams discuss results from the morning, blue tunes detections.
- Afternoon session: Red re-executes morning techniques and adds techniques 6-10.
- End-of-day review: Full gap analysis and initial remediation planning.

**Post-exercise (1-2 weeks):**
- Blue team implements detection improvements.
- Red team re-tests to validate new detections.
- Joint report documenting baseline, improvements, and remaining gaps.

---

## Purple Team Reporting

Purple team reports differ from traditional red team reports in structure and audience:

### Report Structure

1. **Exercise overview**: Objectives, participants, threat actor profile emulated.
2. **Technique-by-technique results**: For each technique tested:
   - ATT&CK ID and description.
   - Execution method and tooling used.
   - Detection status (detected, logged, not logged).
   - Relevant telemetry sources and log entries.
   - Detection rule created or recommended.
3. **Detection coverage summary**: Visual heat map (ATT&CK Navigator layer) showing
   coverage before and after the exercise.
4. **MTTD and MTTR measurements**: For each detected technique, time from execution
   to alert and time from alert to response action.
5. **Remediation roadmap**: Prioritized list of detection improvements with effort
   estimates and responsible parties.
6. **Next exercise recommendations**: Which threat actor or TTP set to test next.

---

## Tooling

| Tool | Purpose | Integration Point |
|------|---------|-------------------|
| Vectr | Purple team exercise tracking and metrics | Central platform for planning and results |
| AttackIQ | Automated breach and attack simulation | Continuous validation between manual exercises |
| Atomic Red Team | Individual ATT&CK technique unit tests | Rapid technique execution for purple sessions |
| MITRE ATT&CK Navigator | Coverage visualization | Planning and reporting |
| Prelude Operator | Lightweight adversary emulation | Quick TTP testing in purple sessions |
| Sigma | Detection rule format | Cross-platform detection rule sharing |

---

## Continuous Purple Team Programs vs. Point-in-Time Exercises

### Point-in-Time Exercises

Traditional model: conduct a purple team exercise quarterly or semi-annually. Provides
periodic snapshots of detection capability but allows drift between exercises.

### Continuous Purple Team Programs

Mature organizations implement continuous programs:

- Weekly or bi-weekly micro-exercises testing 2-3 techniques each.
- Automated testing using BAS (Breach and Attack Simulation) platforms between manual
  sessions.
- Ongoing detection engineering backlog fed by red team findings.
- Monthly metrics reporting to security leadership showing coverage trends.

The Lead should advocate for continuous programs as the organization matures. Point-in-time
exercises are a starting point, not the end state.

---

## Cross-References

- [Threat Modeling](threat-modeling.md)
- [Reporting and Communication](reporting-and-communication.md)
- [Detection Engineering Notes](../appendices/detection-engineering-notes.md)
