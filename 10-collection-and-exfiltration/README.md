# Collection & Exfiltration

This section covers the techniques used to identify, gather, stage, and extract target data from compromised environments. Collection and exfiltration represent the final objective-driven actions that deliver engagement value and demonstrate real-world business impact.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [09 - Lateral Movement](../09-lateral-movement/README.md) | **10 - Collection & Exfiltration** | [11 - Command & Control](../11-command-and-control/README.md) |

**MITRE ATT&CK Tactics:** [TA0009 - Collection](https://attack.mitre.org/tactics/TA0009/) / [TA0010 - Exfiltration](https://attack.mitre.org/tactics/TA0010/)

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Data Staging | [data-staging.md](data-staging.md) | T1074 | Medium | Identifying high-value data, staging locations, compression, and encryption before transfer |
| Exfiltration Channels | [exfiltration-channels.md](exfiltration-channels.md) | T1041, T1048 | High | HTTP/S, DNS, cloud storage, and alternative protocol exfiltration methods and tooling |
| Cloud Exfiltration | [cloud-exfiltration.md](cloud-exfiltration.md) | T1537 | Medium-High | Exfiltrating data through cloud service APIs, storage account sharing, and snapshot transfer |

---

## Section Overview

Collection and exfiltration are where the engagement delivers proof of impact. Data staging involves identifying crown jewel assets -- financial records, intellectual property, PII, source code, or other sensitive data defined in the engagement scope -- and preparing it for extraction. Proper staging includes compression and encryption to reduce transfer volume and protect client data in transit. Exfiltration channel selection depends on the target's egress controls: environments with strict web proxies may require DNS exfiltration or cloud storage channels, while less mature environments may allow direct HTTP/S transfers. Cloud exfiltration introduces unique vectors such as cross-account snapshot sharing, storage account SAS token generation, and API-based data transfer that bypass traditional network monitoring. In all cases, operators must carefully control the volume and sensitivity of exfiltrated data in accordance with the rules of engagement and ensure secure handling and deletion of any extracted material post-engagement.
