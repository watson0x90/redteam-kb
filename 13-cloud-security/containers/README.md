# Container & Kubernetes Security

This section covers container escape techniques and Kubernetes cluster attack vectors used in red team operations and adversary simulations. The material spans misconfiguration-based attacks (privileged containers, Docker socket exposure, RBAC abuse), runtime and kernel vulnerabilities (runc CVEs, Leaky Vessels, Dirty Pipe, nf_tables), and cloud-specific Kubernetes attack patterns (EKS IRSA abuse, GKE Workload Identity theft, AKS managed identity exploitation). All techniques are mapped to MITRE ATT&CK and include detection guidance for purple team exercises.

---

**Navigation:**
| Previous | Current | Next |
|----------|---------|------|
| [GCP Attack Techniques](../gcp/README.md) | **Container & Kubernetes Security** | - |

---

## Table of Contents

| Topic | File | MITRE ATT&CK ID | OPSEC Risk | Description |
|-------|------|------------------|------------|-------------|
| Container Escapes | [container-escapes.md](container-escapes.md) | T1611 | High | Privileged container escape, Docker socket abuse, cgroup release_agent escape, kernel exploits (Dirty Pipe, nf_tables), runc vulnerabilities (Leaky Vessels, CVE-2025 race conditions), capability abuse, host namespace attacks, core pattern escape, sensitive mount paths, runtime comparison |
| Kubernetes Attacks | [kubernetes-attacks.md](kubernetes-attacks.md) | T1609, T1610, T1613 | Medium-High | RBAC privilege escalation, service account token theft, etcd direct access, API server exploitation, pod security bypass, kubelet exploitation, secret extraction, admission controller bypass, supply chain attacks, network policy bypass, cloud-specific K8s attacks (EKS/GKE/AKS), lateral movement, IngressNightmare CVE-2025-1974 |

---

## Section Overview

Containers and Kubernetes represent the dominant deployment model for modern applications, and their security posture is a critical focus area for red team assessments. The container isolation model -- built on Linux namespaces, cgroups, seccomp, and AppArmor/SELinux -- provides a thinner isolation boundary than traditional virtual machines. When this boundary is weakened through misconfigurations (privileged mode, excessive capabilities, socket mounts) or runtime vulnerabilities (runc race conditions, kernel exploits), attackers can escape to the host and pivot across the infrastructure. The 2024-2025 period produced significant container escape research, including the Leaky Vessels disclosure (CVE-2024-21626), three runc race condition CVEs in November 2025, and the critical Docker Desktop escape CVE-2025-9074 (CVSS 9.3).

Kubernetes cluster attacks follow a different model, exploiting the orchestration layer rather than the container runtime. The Kubernetes attack surface includes RBAC misconfigurations that enable privilege escalation, service account tokens that provide API authentication, etcd databases that store all cluster secrets, and kubelet APIs that provide direct container management access. The IngressNightmare vulnerabilities (CVE-2025-1974, CVSS 9.8) demonstrated that unauthenticated RCE in a cluster component could lead to complete cluster takeover. Cloud-managed Kubernetes services (EKS, GKE, AKS) introduce additional attack vectors through their IAM integration mechanisms -- IRSA trust policy misconfigurations, Workload Identity abuse, and managed identity theft from the instance metadata service.

Together, these two attack categories form a comprehensive picture of the container and Kubernetes threat landscape. Red team operators should approach these environments with an attack graph mindset: initial access through a web application vulnerability leads to container compromise, which leads to token theft, which enables RBAC escalation, which provides cluster-wide secret access, which yields cloud IAM credentials, which unlocks the broader cloud environment. Understanding and exercising these chains is essential for accurately assessing the security of containerized deployments.

---

## Key Tools

| Tool | Purpose | Link |
|------|---------|------|
| CDK | Container penetration toolkit (escape detection and exploitation) | https://github.com/cdk-team/CDK |
| Deepce | Docker enumeration, escape detection, and privilege escalation | https://github.com/stealthcopter/deepce |
| PEIRATES | Kubernetes penetration testing tool | https://github.com/inguardians/peirates |
| KubeHound | Kubernetes attack graph modeling | https://github.com/DataDog/KubeHound |
| Stratus Red Team | Granular, atomic Kubernetes and cloud attack techniques | https://stratus-red-team.cloud/ |
| kubeletctl | Direct kubelet API interaction and exploitation | https://github.com/cyberark/kubeletctl |
| kube-hunter | Kubernetes security scanning from attacker perspective | https://github.com/aquasecurity/kube-hunter |
| Konstellation | RBAC analysis and privilege escalation path discovery | https://github.com/praetorian-inc/konstellation |
| BOtB | Break out the Box - container escape automation | https://github.com/brompwnie/botb |
| kubectl-who-can | RBAC permission enumeration | https://github.com/aquasecurity/kubectl-who-can |

---

## Critical CVEs (2024-2026)

| CVE | Component | CVSS | Impact |
|-----|-----------|------|--------|
| CVE-2025-1974 | Ingress-NGINX Controller | 9.8 | Unauthenticated RCE, cluster takeover |
| CVE-2025-9074 | Docker Desktop | 9.3 | Container escape via unauthenticated API |
| CVE-2025-31133 | runc | High | Masked path abuse via symlink race |
| CVE-2025-52565 | runc | High | /dev/console mount race condition |
| CVE-2025-52881 | runc | High | Procfs write redirect via shared mounts |
| CVE-2024-21626 | runc (Leaky Vessels) | 8.6 | Leaked file descriptor container breakout |
| CVE-2024-1086 | Linux kernel (nf_tables) | 7.8 | Use-after-free privilege escalation (active exploitation) |
| CVE-2025-1767 | Kubernetes gitRepo volume | 6.5 | Cross-pod data access |
| CVE-2022-0847 | Linux kernel (Dirty Pipe) | 7.8 | Arbitrary file overwrite, container escape |
