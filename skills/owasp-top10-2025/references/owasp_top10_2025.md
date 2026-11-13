# OWASP Top 10 2025 — Framework Skill

> Version: 2025 Edition  
> ใช้สำหรับ mapping findings ใน ai-report platform ของ Garux

---

## Framework Overview

**Name**: OWASP Top 10 2025  
**Type**: Web Application Security Risk Framework  
**Code Prefix**: `A0X:2025`  
**Use case**: Map pentest findings → OWASP category → report classification

---

## Categories Reference

| Code | Title | Short Tag |
|------|-------|-----------|
| A01:2025 | Broken Access Control | `BAC` |
| A02:2025 | Security Misconfiguration | `MISCONFIG` |
| A03:2025 | Software Supply Chain Failures | `SUPPLY_CHAIN` |
| A04:2025 | Cryptographic Failures | `CRYPTO` |
| A05:2025 | Injection | `INJECTION` |
| A06:2025 | Insecure Design | `INSECURE_DESIGN` |
| A07:2025 | Authentication Failures | `AUTH` |
| A08:2025 | Software or Data Integrity Failures | `INTEGRITY` |
| A09:2025 | Security Logging and Alerting Failures | `LOGGING` |
| A10:2025 | Mishandling of Exceptional Conditions | `EXCEPTION` |

---

## Detailed Category Descriptions

### A01:2025 — Broken Access Control
Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits.

**Common findings to map here:**
- IDOR (Insecure Direct Object Reference)
- Missing function-level access control
- Privilege escalation (horizontal/vertical)
- CORS misconfiguration allowing unauthorized API access
- Force browsing to authenticated pages
- JWT without proper authorization checks

---

### A02:2025 — Security Misconfiguration
Security misconfiguration across the application stack, including network services, platform, web server, application server, database, frameworks, custom code, and pre-installed virtual machines, containers, or storage.

**Common findings to map here:**
- Default credentials
- Unnecessary features/services enabled
- Verbose error messages exposing stack traces
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Exposed admin panels / debug endpoints
- Cloud storage publicly accessible (S3, Azure Blob)

---

### A03:2025 — Software Supply Chain Failures
Vulnerabilities arising from the software supply chain, including third-party components and dependencies. Covers both open-source and commercial software components.

**Common findings to map here:**
- Outdated/vulnerable npm / pip / Maven packages
- Dependency confusion attacks
- Typosquatting packages
- Compromised build pipeline
- Third-party SDK with known CVEs
- SCA (Software Composition Analysis) findings

---

### A04:2025 — Cryptographic Failures
Failures related to cryptography (or lack thereof) leading to sensitive data exposure. Previously known as "Sensitive Data Exposure" — now focused on root cause.

**Common findings to map here:**
- Sensitive data transmitted over HTTP (no TLS)
- Weak cipher suites (RC4, DES, MD5, SHA1)
- Hardcoded secrets / API keys in source code
- Improper certificate validation
- Insecure password storage (plaintext / weak hash)
- Predictable random number generation

---

### A05:2025 — Injection
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Covers SQL, NoSQL, OS command, LDAP, SSTI, and more.

**Common findings to map here:**
- SQL Injection (classic, blind, time-based)
- NoSQL Injection (MongoDB operator injection)
- OS Command Injection
- LDAP Injection
- SSTI (Server-Side Template Injection)
- XPath / XML Injection
- Stored / Reflected / DOM-based XSS *(cross-reference A01 for stored)*

---

### A06:2025 — Insecure Design
Risks related to design and architectural flaws. Distinct from implementation bugs — these are missing or ineffective control designs.

**Common findings to map here:**
- Business logic flaws
- Missing rate limiting (brute force exposure)
- Insecure password recovery flows
- Mass Assignment vulnerabilities
- Lack of defense-in-depth design
- Missing input validation at design level

---

### A07:2025 — Authentication Failures
Failures in confirming the user's identity, authentication, and session management. Allows attackers to compromise passwords, keys, or session tokens.

**Common findings to map here:**
- Weak password policy
- No account lockout / brute force protection
- Broken session management (predictable tokens)
- JWT algorithm confusion (none / RS256 → HS256)
- Credential stuffing exposure
- Missing MFA on critical functions
- Token exposure in URL / localStorage

---

### A08:2025 — Software or Data Integrity Failures
Focuses on assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. Includes insecure deserialization.

**Common findings to map here:**
- Insecure deserialization (Java, PHP, Python pickle)
- Auto-update without integrity verification
- Malicious packages in CI/CD pipeline
- Unsigned code/package deployment
- XML External Entity (XXE) injection
- Prototype pollution

---

### A09:2025 — Security Logging and Alerting Failures
Failures in detecting, escalating, and responding to active breaches. Without logging and monitoring, breaches cannot be detected.

**Common findings to map here:**
- Login failures not logged
- No alerting on suspicious activity
- Logs not protected from tampering
- Log injection vulnerabilities
- Missing audit trail for sensitive operations
- SIEM not covering critical endpoints

---

### A10:2025 — Mishandling of Exceptional Conditions
Mishandling of errors and exceptions that can lead to information disclosure, denial of service, or unexpected behaviors.

**Common findings to map here:**
- Verbose error messages (stack traces, DB errors)
- Application crash revealing sensitive info
- Unhandled exceptions leading to bypass
- Error-based information disclosure
- Improper null/exception handling in auth logic

---

## Mapping Quick Reference (for ai-report)

```
Finding Type                    → OWASP Code
─────────────────────────────────────────────
IDOR                            → A01:2025
Privilege Escalation            → A01:2025
SQL Injection                   → A05:2025
XSS (Stored/Reflected/DOM)      → A05:2025
Command Injection               → A05:2025
SSTI                            → A05:2025
Broken Auth / Session           → A07:2025
JWT Vuln                        → A07:2025
Token in localStorage           → A07:2025
Hardcoded Secret / API Key      → A04:2025
Missing TLS                     → A04:2025
Weak Hash / Plaintext Password  → A04:2025
Default Credentials             → A02:2025
Missing Security Headers        → A02:2025
Exposed Admin Panel             → A02:2025
Mass Assignment                 → A06:2025
Business Logic Flaw             → A06:2025
No Rate Limiting                → A06:2025
Outdated Dependency (CVE)       → A03:2025
XXE                             → A08:2025
Insecure Deserialization        → A08:2025
Verbose Error / Stack Trace     → A10:2025
No Audit Logging                → A09:2025
```

---

## Notes for Garux

- **A03:2025 (Supply Chain)** เป็น entry ใหม่ใน 2025 — เคยไม่มีใน Top 10 — relevant กับงาน OWASP dep-scan / cdxgen ที่ทำอยู่
- **A10:2025 (Exception Handling)** ก็เป็น entry ใหม่ — map พวก verbose error disclosure ที่เจอบ่อยๆ มาที่นี่ได้เลย
- **XSS** → ใน 2025 จัด sub-category ใน A05 (Injection) ไม่ได้แยก entry — singburi.mitrphol.com Stored XSS → `A05:2025`
- **Mass Assignment** (เจอใน uat-mpcontract) → `A06:2025` Insecure Design
- **Token exposure / localStorage privilege escalation** (uat-mpcontract) → `A07:2025`
