---
name: api-security-testing
description: Professional skills and methodology for API security testing
version: 1.0.0
---

# API Security Testing

## Overview

API security testing is a critical step in ensuring the security of API interfaces. This skill provides methods, tools, and best practices for API security testing.

## Testing Scope

### 1. Authentication and Authorization

**Test items:**
- Token validity verification
- Token expiration handling
- Access control
- Role-based permission verification

### 2. Input Validation

**Test items:**
- Parameter type validation
- Data length limits
- Special character handling
- SQL injection protection
- XSS protection

### 3. Business Logic

**Test items:**
- Workflow validation
- State transitions
- Concurrency control
- Business rules

### 4. Error Handling

**Test items:**
- Error message disclosure
- Stack traces
- Sensitive information exposure

## Testing Methods

### 1. API Discovery

**Identify API endpoints:**
```bash
# Directory scan
gobuster dir -u https://target.com -w api-wordlist.txt

# Burp Suite passive scan
# Browse the app and observe API calls

# Analyze JavaScript files
# Look for API endpoint definitions
```

### 2. Authentication Testing

**Token testing:**
```http
# Test invalid token
GET /api/user
Authorization: Bearer invalid_token

# Test expired token
GET /api/user
Authorization: Bearer expired_token

# Test with no token
GET /api/user
```

**JWT testing:**
```bash
# Use jwt_tool
python jwt_tool.py <JWT_TOKEN>

# Test algorithm confusion
python jwt_tool.py <JWT_TOKEN> -X a

# Test key brute force
python jwt_tool.py <JWT_TOKEN> -C -d wordlist.txt
```

### 3. Authorization Testing

**Horizontal privilege:**
```http
# User A accesses User B's resource
GET /api/user/123
Authorization: Bearer user_a_token

# Should return 403
```

**Vertical privilege:**
```http
# Regular user accesses an admin endpoint
GET /api/admin/users
Authorization: Bearer user_token

# Should return 403
```

### 4. Input Validation Testing

**SQL injection:**
```http
POST /api/search
{
  "query": "test' OR '1'='1"
}
```

**Command injection:**
```http
POST /api/execute
{
  "command": "ping; id"
}
```

**XXE:**
```http
POST /api/parse
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

### 5. Rate Limiting Testing

**Test rate limiting:**
```python
import requests

for i in range(1000):
    response = requests.get('https://target.com/api/endpoint')
    print(f"Request {i}: {response.status_code}")
```

## Tool Usage

### Postman

**Create test collection:**
1. Import API documentation
2. Set up authentication
3. Create test cases
4. Run automated tests

### Burp Suite

**API scanning:**
1. Configure API endpoints
2. Set up authentication
3. Run active scan
4. Analyze results

### OWASP ZAP

```bash
# API scan
zap-cli quick-scan --self-contained \
  --start-options '-config api.disablekey=true' \
  http://target.com/api
```

### REST-Attacker

```bash
# Scan the OpenAPI spec
rest-attacker scan openapi.yaml
```

## Common Vulnerabilities

### 1. Authentication Bypass

**Token verification flaws:**
- Weak token generation
- Predictable tokens
- Tokens not validating signatures

### 2. Privilege Escalation

**IDOR:**
- Insecure direct object references
- Unverified resource ownership

### 3. Information Disclosure

**Error messages:**
- Verbose error messages
- Stack traces
- Sensitive data

### 4. Injection Vulnerabilities

**Common injections:**
- SQL injection
- NoSQL injection
- Command injection
- XXE

### 5. Business Logic

**Logic flaws:**
- Price manipulation
- Quantity limit bypass
- State modification

## Testing Checklist

### Authentication Testing
- [ ] Token validity verification
- [ ] Token expiration handling
- [ ] Weak token detection
- [ ] Token replay attack

### Authorization Testing
- [ ] Horizontal privilege testing
- [ ] Vertical privilege testing
- [ ] Role-based permission verification
- [ ] Resource access control

### Input Validation
- [ ] SQL injection testing
- [ ] XSS testing
- [ ] Command injection testing
- [ ] XXE testing
- [ ] Parameter pollution

### Business Logic
- [ ] Workflow validation
- [ ] State transitions
- [ ] Concurrency control
- [ ] Business rules

### Error Handling
- [ ] Error message disclosure
- [ ] Stack traces
- [ ] Sensitive information exposure

## Protective Measures

### Recommended Solutions

1. **Authentication**
   - Use strong tokens
   - Implement token refresh
   - Verify token signatures

2. **Authorization**
   - Role-based access control
   - Resource ownership verification
   - Principle of least privilege

3. **Input Validation**
   - Parameter type validation
   - Data length limits
   - Whitelist validation

4. **Error Handling**
   - Unified error responses
   - Do not disclose detailed information
   - Log errors

5. **Rate Limiting**
   - Implement API throttling
   - Prevent brute force
   - Monitor abnormal requests

## Notes

- Only perform testing in authorized environments
- Avoid impacting the API
- Be aware of differences between API versions
- Watch request frequency during testing
