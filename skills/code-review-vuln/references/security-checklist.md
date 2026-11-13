# Security & Pentest Review Checklist

Reference สำหรับ skill `code-review-vuln` — ใช้ตรวจ code ตามหมวดหมู่นี้

---

## A. Injection

| Check | CWE | MITRE |
|-------|-----|-------|
| SQL query ต่อ string โดยตรง (f-string, concatenation) | CWE-89 | T1190 |
| OS command จาก user input (`subprocess`, `exec`, `system`) | CWE-78 | T1059 |
| LDAP filter ไม่ escape | CWE-90 | T1190 |
| NoSQL operator injection (`$where`, `$gt` จาก input) | CWE-943 | T1190 |
| Template injection (Jinja2, Twig, Pebble, EJS) | CWE-94 | T1190 |
| XSS — output ไม่ encode, `innerHTML` รับ user input | CWE-79 | T1190 |
| XXE — XML parser ไม่ disable external entity | CWE-611 | T1190 |
| SSTI — server-side template รับ untrusted input | CWE-94 | T1190 |
| Header injection (CRLF injection ใน HTTP response) | CWE-113 | T1190 |

---

## B. Authentication & Authorization

| Check | CWE | MITRE |
|-------|-----|-------|
| Missing authentication บน endpoint ที่ควร auth | CWE-306 | T1078 |
| JWT ไม่ verify signature หรือ accept `alg: none` | CWE-347 | T1078 |
| Password เก็บ plaintext หรือ hash อ่อน (MD5/SHA1) | CWE-916 | T1552 |
| Missing authorization check (IDOR, privilege escalation) | CWE-285 | T1548 |
| Session fixation / session ไม่ regenerate หลัง login | CWE-384 | T1078 |
| Insecure direct object reference — ID ใน URL ไม่ verify ownership | CWE-639 | T1548 |
| CSRF — ไม่มี token / SameSite cookie | CWE-352 | T1185 |
| Mass assignment — bind model โดยตรงจาก request body | CWE-915 | T1548 |
| Insecure password reset (predictable token, no expiry) | CWE-640 | T1078 |

---

## C. Sensitive Data Exposure

| Check | CWE | MITRE |
|-------|-----|-------|
| Hardcoded secret/API key/password ใน source code | CWE-798 | T1552.001 |
| Debug info / stack trace expose ไปยัง user | CWE-209 | T1082 |
| PII หรือ token ใน log file | CWE-532 | T1552 |
| Sensitive data ส่งผ่าน HTTP (ไม่ใช่ HTTPS) | CWE-319 | T1557 |
| Cookie ไม่มี `Secure` / `HttpOnly` flag | CWE-614 | T1185 |
| เก็บ sensitive data ใน localStorage / URL parameter | CWE-922 | T1552 |
| Sensitive data ใน Git history / comment | CWE-615 | T1552.001 |

---

## D. Cryptography

| Check | CWE | MITRE |
|-------|-----|-------|
| ใช้ MD5/SHA1 สำหรับ password hashing | CWE-916 | T1552 |
| Weak random (`Math.random()`, `rand()`) สำหรับ security token | CWE-338 | T1078 |
| Hardcoded IV หรือ symmetric key | CWE-321 | T1552 |
| ECB mode สำหรับ block cipher | CWE-327 | T1552 |
| RSA key size < 2048 หรือ EC curve ที่ไม่ปลอดภัย | CWE-326 | T1552 |
| Missing certificate validation (SSL verify=False) | CWE-295 | T1557 |

---

## E. Deserialization

| Check | CWE | MITRE |
|-------|-----|-------|
| `pickle.loads()` / `yaml.load()` รับ untrusted data | CWE-502 | T1059 |
| Java `ObjectInputStream` โดยไม่มี filter | CWE-502 | T1059 |
| PHP `unserialize()` จาก user input | CWE-502 | T1059 |
| JSON.parse ไม่มี schema validation บน critical data | CWE-20 | T1059 |

---

## F. SSRF

| Check | CWE | MITRE |
|-------|-----|-------|
| URL จาก user input ส่งไป HTTP request โดยตรง | CWE-918 | T1090 |
| ไม่ validate scheme (แค่ http/https เท่านั้น) | CWE-918 | T1090 |
| ไม่ block internal IP range (169.254.x.x, 10.x.x.x, 192.168.x.x) | CWE-918 | T1090 |
| DNS rebinding — ไม่ validate IP หลัง resolution | CWE-918 | T1090 |

---

## G. Race Condition & Concurrency

| Check | CWE | MITRE |
|-------|-----|-------|
| TOCTOU — check แล้ว use โดยไม่มี lock | CWE-367 | T1548 |
| Shared mutable state โดยไม่มี mutex/lock | CWE-362 | - |
| Double-spend / balance check ก่อน deduct โดยไม่ atomic | CWE-362 | T1548 |

---

## H. Path Traversal & File Operations

| Check | CWE | MITRE |
|-------|-----|-------|
| File path จาก user input ไม่ normalize/validate (`../`) | CWE-22 | T1083 |
| Zip slip — extract archive โดยไม่ check path | CWE-22 | T1083 |
| Arbitrary file read/write ผ่าน filename parameter | CWE-73 | T1083 |
| Server-side file inclusion | CWE-98 | T1190 |

---

## I. Dependency & Supply Chain

| Check | CWE | MITRE |
|-------|-----|-------|
| Library version ที่รู้ว่ามี CVE | CWE-1104 | T1195.001 |
| `requirements.txt` / `package.json` ไม่ pin version | CWE-1104 | T1195.001 |
| ดึง package จาก untrusted source | CWE-829 | T1195.002 |
| Typosquatting risk — ชื่อ package คล้าย popular package | CWE-829 | T1195.002 |

---

## J. Infrastructure / IaC (Terraform / Dockerfile / K8s / CI-CD)

| Check | CWE | MITRE |
|-------|-----|-------|
| Container run as root | CWE-250 | T1548.002 |
| Privileged container / `--privileged` flag | CWE-250 | T1548.002 |
| Secret ใน environment variable ของ Dockerfile | CWE-798 | T1552.004 |
| S3 bucket / Storage account เปิด public | CWE-284 | T1530 |
| Security group เปิด 0.0.0.0/0 บน port sensitive | CWE-284 | T1190 |
| Terraform state ไม่ encrypt / เก็บ local | CWE-312 | T1552 |
| CI/CD pipeline รัน untrusted code โดยตรง | CWE-829 | T1195.002 |
| Secret ใน GitHub Actions env หรือ log output | CWE-798 | T1552.001 |

---

## K. Business Logic Vulnerabilities

| Check | MITRE |
|-------|-------|
| Price/quantity manipulation (ค่า negative หรือ float precision) | T1548 |
| Workflow bypass (ข้าม step ที่ควร sequential) | T1548 |
| Rate limiting missing บน sensitive endpoint | T1110 |
| Account enumeration ผ่าน error message ที่ต่างกัน | T1589 |
| Insecure pagination (ข้าม authorization เมื่อ page เปลี่ยน) | T1548 |

---

## Pentest Context Guide

### CVSS v3.1 Quick Reference

**Attack Vector (AV):**
- N = Network (accessible remotely)
- A = Adjacent (same network segment)
- L = Local (requires local access)
- P = Physical

**Attack Complexity (AC):** L = Low, H = High

**Privileges Required (PR):** N = None, L = Low, H = High

**User Interaction (UI):** N = None, R = Required

**Scope (S):** U = Unchanged, C = Changed

**Impact (C/I/A):** N = None, L = Low, H = High

ตัวอย่าง Critical: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8

### Common PoC Patterns

```
# SQL Injection basic test
' OR '1'='1
' OR 1=1--
'; DROP TABLE users--

# XSS basic test
<script>alert(1)</script>
"><img src=x onerror=alert(1)>

# Path traversal
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd

# SSRF
http://169.254.169.254/latest/meta-data/
http://localhost:8080/admin

# SSTI (Jinja2)
{{7*7}}
{{config.items()}}
```

---

## Severity Rating Guide

| Severity | CVSS Range | เกณฑ์ |
|----------|-----------|--------|
| **Critical** | 9.0 – 10.0 | Exploit ได้ทันที, ไม่ต้อง auth, RCE / full data breach |
| **High** | 7.0 – 8.9 | Exploit ยากนิดนึง หรือต้อง auth แต่ impact สูง |
| **Medium** | 4.0 – 6.9 | ต้องมี condition เพิ่ม หรือ impact จำกัด |
| **Low** | 0.1 – 3.9 | Defense-in-depth, best practice, impact ต่ำมาก |
| **Info** | - | Observation, ไม่ใช่ vulnerability แต่ควรรู้ |
