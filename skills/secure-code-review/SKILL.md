---
name: secure-code-review
description: Professional skills and methodology for secure code review
version: 1.0.0
---

# Secure Code Review

## Overview

Secure code review is an essential method for identifying security vulnerabilities in code. This skill provides methods, tools, and best practices for secure code review.

## Review Scope

### 1. Input Validation

**Checklist items:**
- User input validation
- Parameter validation
- Data filtering
- Boundary checks

### 2. Output Encoding

**Checklist items:**
- XSS protection
- Output encoding
- Content Security Policy
- Response header settings

### 3. Authentication and Authorization

**Checklist items:**
- Authentication mechanisms
- Session management
- Access control
- Password handling

### 4. Encryption and Keys

**Checklist items:**
- Data encryption
- Key management
- Hash algorithms
- Random number generation

## Review Methods

### 1. Static Analysis

**Using SAST tools:**
```bash
# SonarQube
sonar-scanner

# Checkmarx
# Use the web interface

# Fortify
sourceanalyzer -b project build.sh
sourceanalyzer -b project -scan

# Semgrep
semgrep --config=auto .
```

### 2. Manual Review

**Review checklist:**
- [ ] Input validation
- [ ] Output encoding
- [ ] SQL injection
- [ ] XSS vulnerabilities
- [ ] Authentication and authorization
- [ ] Use of encryption
- [ ] Error handling
- [ ] Logging

### 3. Code Pattern Recognition

**Dangerous functions:**
```python
# Python dangerous functions
eval()
exec()
pickle.loads()
os.system()
subprocess.call()
```

```java
// Java dangerous functions
Runtime.exec()
ProcessBuilder()
Class.forName()
```

```php
// PHP dangerous functions
eval()
exec()
system()
passthru()
```

## Common Vulnerability Patterns

### SQL Injection

**Dangerous code:**
```java
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

**Secure code:**
```java
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = connection.prepareStatement(query);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
```

### XSS Vulnerabilities

**Dangerous code:**
```javascript
document.innerHTML = userInput;
element.innerHTML = "<div>" + userInput + "</div>";
```

**Secure code:**
```javascript
element.textContent = userInput;
element.setAttribute("data-value", userInput);
// Or use an encoding library
element.innerHTML = escapeHtml(userInput);
```

### Command Injection

**Dangerous code:**
```python
import os
os.system("ping " + user_input)
```

**Secure code:**
```python
import subprocess
subprocess.run(["ping", "-c", "1", validated_input])
```

### Path Traversal

**Dangerous code:**
```java
String filePath = "/uploads/" + fileName;
File file = new File(filePath);
```

**Secure code:**
```java
String basePath = "/uploads/";
String fileName = Paths.get(fileName).getFileName().toString();
String filePath = basePath + fileName;
File file = new File(filePath);
if (!file.getCanonicalPath().startsWith(basePath)) {
    throw new SecurityException("Invalid path");
}
```

### Hardcoded Secrets

**Dangerous code:**
```java
String apiKey = "1234567890abcdef";
String password = "admin123";
```

**Secure code:**
```java
String apiKey = System.getenv("API_KEY");
String password = keyStore.getPassword("db_password");
```

## Tool Usage

### SonarQube

```bash
# Start SonarQube
docker run -d -p 9000:9000 sonarqube

# Run a scan
sonar-scanner \
  -Dsonar.projectKey=myproject \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000
```

### Semgrep

```bash
# Install
pip install semgrep

# Run a scan
semgrep --config=auto .

# Use a ruleset
semgrep --config=p/security-audit .
```

### CodeQL

```bash
# Create a database
codeql database create database --language=java --source-root=.

# Run a query
codeql database analyze database security-and-quality.qls --format=sarif-latest
```

## Review Checklist

### Input Validation
- [ ] All user input is validated
- [ ] Use allowlist validation
- [ ] Validate data type and range
- [ ] Handle special characters

### Output Encoding
- [ ] HTML output encoding
- [ ] URL encoding
- [ ] JavaScript encoding
- [ ] SQL parameterization

### Authentication and Authorization
- [ ] Strong password policy
- [ ] Secure session management
- [ ] Permission validation
- [ ] Multi-factor authentication

### Encryption
- [ ] Use strong encryption algorithms
- [ ] Secure key storage
- [ ] Encryption in transit
- [ ] Encryption at rest

### Error Handling
- [ ] Do not leak sensitive information
- [ ] Consistent error responses
- [ ] Log errors
- [ ] Exception handling

## Best Practices

### 1. Secure Coding Standards

- Follow the OWASP Top 10
- Use secure coding guidelines
- Code review process
- Security training

### 2. Automation Tools

- Integrate SAST tools
- CI/CD security checks
- Automated scanning
- Result analysis

### 3. Code Review Process

- Peer review
- Security expert review
- Periodic review
- Document issues

## Notes

- Combine tooling with manual review
- Pay attention to business logic flaws
- Regularly update tool rules
- Build a secure coding culture
