---
name: incident-response
description: Professional skills and methodology for security incident response
version: 1.0.0
---

# Security Incident Response

## Overview

Security incident response is the critical process for handling security incidents. This skill provides the methods, tools, and best practices for security incident response.

## Response Process

### 1. Preparation Phase

**Preparation work:**
- Establish a response team
- Develop a response plan
- Prepare tools and resources
- Establish communication channels

### 2. Identification Phase

**Identify incidents:**
- Monitor alerts
- Anomaly detection
- Log analysis
- User reports

### 3. Containment Phase

**Containment measures:**
- Isolate affected systems
- Disable accounts
- Block network connections
- Back up evidence

### 4. Eradication Phase

**Eradicate threats:**
- Remove malware
- Patch vulnerabilities
- Reset credentials
- Clean up backdoors

### 5. Recovery Phase

**Recover systems:**
- Restore backups
- Verify system integrity
- Monitor systems
- Gradually restore services

### 6. Lessons Learned Phase

**Summarize lessons:**
- Incident report
- Lessons learned
- Improvement measures
- Update processes

## Tool Usage

### Log Analysis

**Using Splunk:**
```bash
# Search logs
index=security event_type="failed_login"

# Statistical analysis
index=security | stats count by src_ip

# Time series analysis
index=security | timechart count by event_type
```

**Using ELK:**
```bash
# Elasticsearch query
GET /logs/_search
{
  "query": {
    "match": {
      "event_type": "malware"
    }
  }
}
```

### Forensic Tools

**Using Volatility:**
```bash
# Analyze memory image
volatility -f memory.dump imageinfo

# List processes
volatility -f memory.dump --profile=Win7SP1x64 pslist

# Dump process memory
volatility -f memory.dump --profile=Win7SP1x64 memdump -p 1234 -D output/
```

**Using Autopsy:**
```bash
# Launch Autopsy
# Create a case
# Add evidence
# Analyze data
```

### Network Analysis

**Using Wireshark:**
```bash
# Capture traffic
wireshark -i eth0

# Analyze PCAP file
wireshark -r capture.pcap

# Filter traffic
# Display filter: ip.addr == 192.168.1.100
# Capture filter: host 192.168.1.100
```

**Using tcpdump:**
```bash
# Capture traffic
tcpdump -i eth0 -w capture.pcap

# Analyze traffic
tcpdump -r capture.pcap -A
```

## Incident Types

### Malware

**Response steps:**
1. Isolate affected systems
2. Collect samples
3. Analyze the malware
4. Eradicate the threat
5. Patch vulnerabilities

**Tools:**
- VirusTotal
- Cuckoo Sandbox
- YARA rules

### Data Breach

**Response steps:**
1. Confirm the scope of the breach
2. Contain the breach
3. Assess the impact
4. Notify relevant parties
5. Patch vulnerabilities

**Checklist items:**
- Volume of breached data
- Affected users
- Breach channel
- Data sensitivity

### Denial of Service

**Response steps:**
1. Confirm the attack type
2. Enable protective measures
3. Filter malicious traffic
4. Monitor system status
5. Restore normal service

**Protective measures:**
- DDoS protection service
- Traffic scrubbing
- Rate limiting
- CDN protection

### Unauthorized Access

**Response steps:**
1. Disable affected accounts
2. Reset credentials
3. Review access logs
4. Assess data access
5. Patch vulnerabilities

**Checklist items:**
- Access time
- Accessed content
- Access source
- Data modifications

## Response Checklist

### Preparation Phase
- [ ] Establish a response team
- [ ] Develop a response plan
- [ ] Prepare tools
- [ ] Establish communication channels

### Identification Phase
- [ ] Confirm the incident
- [ ] Collect information
- [ ] Assess impact
- [ ] Record the timeline

### Containment Phase
- [ ] Isolate systems
- [ ] Disable accounts
- [ ] Block connections
- [ ] Back up evidence

### Eradication Phase
- [ ] Remove threats
- [ ] Patch vulnerabilities
- [ ] Reset credentials
- [ ] Verify eradication

### Recovery Phase
- [ ] Restore systems
- [ ] Verify integrity
- [ ] Monitor systems
- [ ] Restore services

### Lessons Learned Phase
- [ ] Write the report
- [ ] Summarize lessons
- [ ] Improvement measures
- [ ] Update processes

## Best Practices

### 1. Preparation

- Establish a response team
- Develop a response plan
- Conduct regular drills
- Prepare tools

### 2. Response

- Respond quickly
- Handle systematically
- Record all actions
- Protect evidence

### 3. Communication

- Internal communication
- External notification
- Status updates
- Post-incident report

### 4. Improvement

- Incident analysis
- Process improvement
- Tool updates
- Training enhancement

## Notes

- Respond quickly
- Protect evidence
- Record actions
- Comply with laws and regulations
