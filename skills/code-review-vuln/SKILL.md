---
name: code-review-vuln
description: "วิเคราะห์ code อย่างละเอียดครบ 4 มิติ: Security vulnerabilities, Code quality, Performance, และ Pentest-oriented analysis พร้อม summary report ภาษาไทย ใช้ skill นี้ทันทีเมื่อ user ส่ง code มาให้ดู ไม่ว่าจะพูดว่า: \"review code\", \"รีวิว code\", \"หาช่องโหว่\", \"ตรวจ code\", \"audit code\", \"code review\", \"/review\", \"วิเคราะห์ code\", \"เช็ค security\", \"หา bug\", \"pentest code\", \"มี vuln ไหม\", \"ดู code ให้หน่อย\", \"safe ไหม\", \"secure ไหม\", \"exploit ได้ไหม\", \"โค้ดนี้มีปัญหาไหม\", \"ช่วย review\", \"check code\" ให้ใช้ skill นี้เสมอเมื่อ user แชร์ code snippet, file, diff, PR, หรือ paste code แม้จะไม่ได้ระบุคำว่า review ก็ตาม — ถ้า code อยู่ในบริบทการวิเคราะห์ความปลอดภัย ให้ trigger ทันที\n"
---

# Code Review — Security · Quality · Performance · Pentest

เมื่อ user ส่ง code มาให้ review ให้วิเคราะห์ครบ 4 มิติและออก summary report ตามรูปแบบด้านล่าง ทำอย่างละเอียดและเป็นระบบ — รายงานนี้อาจถูกใช้เป็น evidence ในงาน pentest จริง

---

## เตรียมการก่อนรีวิว (Preparation)

ก่อนเริ่มวิเคราะห์ ให้ตั้ง context สั้น ๆ (ถ้าข้อมูลมี):
- **Architecture / entry point**: code นี้เป็นส่วนไหน — API endpoint, background job, CLI, IaC, frontend
- **Trust boundary**: input มาจากไหน (user / internal service / trusted config) และ output ไปที่ไหน
- **Critical asset**: code แตะ auth, payment, PII, secret หรือ privileged operation ไหม
- **Previous context**: ถ้า user เคยส่ง finding เดิม หรือระบุ scope/ภัยคุกคามที่กังวล ให้ยึดตามนั้น

ถ้าข้อมูลไม่พอและมีผลต่อการตัดสิน severity อย่างมาก ให้ระบุ assumption ไว้ใน report แทนการเดาเงียบ ๆ

## โหมดรีวิว (Review Mode)

เลือกโหมดตามสิ่งที่ user ส่งมา:

- **Baseline** (ส่ง codebase / ไฟล์เต็ม / บอกว่าแอปใหม่หรือ legacy onboarding) — ไล่ครบทุกหมวด: architecture → entry point → auth/authz → data flow → business logic → crypto → error handling → config
- **Diff-Based** (ส่ง diff / PR / commit) — โฟกัสส่วนที่เปลี่ยน แต่ต้องเช็คเพิ่ม 3 อย่างเสมอ: (1) กระทบ security control เดิมไหม (2) เปิด attack vector ใหม่ไหม (3) มี security regression ไหม อ่าน context รอบ ๆ ที่ diff แตะด้วย

ระบุโหมดที่ใช้ไว้ในหัว report

---

## Data Flow Analysis (ทำก่อน หรือควบคู่กับ checklist)

อย่าเช็คแค่ pattern — ให้ไล่ข้อมูลจากต้นทางถึงปลายทางเพื่อจับ vuln ที่ tool มองข้าม:

1. **Source** — ระบุจุดรับข้อมูลที่ควบคุมไม่ได้: user input, request body/param/header, file upload, API response, DB read, env var
2. **Processing** — ตามไปว่าผ่าน validation / sanitization / encoding / business logic อะไรบ้าง (หรือไม่ผ่านเลย)
3. **Sink** — จุดที่ข้อมูลไปลงอันตราย: DB query, OS command, file path, output rendering, log, redirect, external HTTP call, deserialization
4. **Trust boundary** — ทุกครั้งที่ข้อมูลข้ามขอบเขต (untrusted → trusted) ต้องมี validate/encode ที่เหมาะกับ context ของ sink

ถ้า source ถึง sink ได้โดยไม่มี control ที่ trust boundary → นั่นคือ finding พร้อมอธิบาย tainted path ใน Evidence

---

## ขั้นตอนการวิเคราะห์

### 1. Security Review
ตรวจหาช่องโหว่ตาม checklist ใน `references/security-checklist.md`

โฟกัสหลัก:
- **Injection**: SQL, Command, LDAP, XPath, NoSQL, Template injection
- **Authentication/Authorization**: broken auth, missing checks, privilege escalation, IDOR
- **Sensitive data**: hardcoded secrets, credentials, API keys, PII ใน log
- **Input validation**: missing sanitization, type confusion, path traversal
- **Cryptography**: weak algo (MD5/SHA1), insecure random, bad key management
- **Deserialization**: unsafe pickle/yaml/Java ObjectInputStream
- **XXE / SSRF / CSRF**: ถ้า code เกี่ยวกับ XML/HTTP/forms
- **Race condition**: concurrent access โดยไม่มี lock, TOCTOU
- **Config / Headers / TLS**: missing security header (CSP/HSTS/X-Frame-Options), weak TLS, debug mode, default cred
- **Monitoring / Detectability**: security event ไม่ถูก log, audit trail ขาด, log แก้ไขได้ (attack เงียบ = risk สูงขึ้น)

Map ทุก finding ไป MITRE ATT&CK Tactic + Technique ID และ CWE เสมอ

### 2. Pentest-Oriented Analysis
มองจากมุม attacker — ไม่ใช่แค่ "มีปัญหา" แต่ต้องตอบว่า "exploit ได้จริงไหม"

- **Exploitability**: ระบุว่า exploit ได้ทันทีหรือต้องมี pre-condition อะไร
- **Attack chain**: ถ้า finding หลายอย่างรวมกันได้ ให้อธิบาย attack scenario จากต้นจนจบ
- **CVSS v3.1 Score**: คำนวณ base score พร้อม vector string (AV/AC/PR/UI/S/C/I/A)
- **Proof of Concept**: ให้ PoC payload หรือ pseudocode ถ้า finding นั้น Critical/High และสาธิตได้โดยไม่ก่อให้เกิดความเสียหาย
- **Bypass potential**: เช็คว่า mitigation ที่มีอยู่ bypass ได้ไหม (เช่น WAF bypass, filter evasion)
- **Lateral movement / Privilege escalation**: ถ้า exploit สำเร็จ attacker ไปต่อได้อย่างไร

### 3. Code Quality Review
- Dead code, unreachable branches, unused imports
- Hardcoded values ที่ควรเป็น config หรือ environment variable
- Error handling: bare `except`, swallowed exceptions, missing error propagation
- Logging: sensitive data ใน log, insufficient logging for forensics
- Complexity: cyclomatic complexity สูง, function ยาวเกิน, god class/module
- Dependencies: outdated/vulnerable library version (ระบุ CVE ถ้าทราบ)
- Type safety: missing type hints, implicit type coercion ที่อันตราย

### 4. Performance Review
- N+1 query หรือ query ใน loop
- Memory leak: unclosed resource, circular reference, unbounded cache
- Inefficient algorithm: O(n²) หรือแย่กว่าที่ควรเป็น
- Blocking I/O ใน async context (asyncio, Node.js event loop)
- Missing cache ในจุดที่ query ซ้ำบ่อย
- Large object serialization โดยไม่จำเป็น

---

## Output Format

ออก report ตามโครงสร้างนี้เสมอ ห้ามข้ามส่วนใดส่วนหนึ่ง:

```
## 🔍 Code Review Report
**Target**: <filename หรือ description>
**Language/Framework**: <ภาษา + framework>
**Review Mode**: Baseline / Diff-Based
**Scope**: <ส่วนที่วิเคราะห์>
**Reviewed**: <วันที่ปัจจุบัน>
**Analyst**: Claude (vuln-eye)

---

### Executive Summary
<3-4 ประโยค สรุปภาพรวมความเสี่ยง ระบุ critical findings ที่ต้องแก้ด่วน
และ overall risk level: Critical / High / Medium / Low>

---

### Findings

#### [CRVN-001] <ชื่อช่องโหว่/ปัญหา>
- **Category**: Security / Pentest / Quality / Performance
- **Severity**: Critical / High / Medium / Low / Info
- **CVSS v3.1**: <score> (`<vector string>`) — เฉพาะ Security findings
- **CWE**: [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html) — เฉพาะ Security
- **MITRE ATT&CK**: <Tactic> → [TXXXX](https://attack.mitre.org/techniques/TXXXX/) — เฉพาะ Security
- **Location**: `<file>:<line range>` หรือ function/class name
- **Description**: อธิบายปัญหา สาเหตุ และผลกระทบที่แท้จริง
- **Evidence**:
  ```
  <โค้ดที่มีปัญหา พร้อม line number>
  ```
- **Exploit Scenario** (Security/Pentest เท่านั้น):
  อธิบาย step-by-step ว่า attacker จะ exploit ยังไง
  PoC payload (ถ้า Critical/High):
  ```
  <payload หรือ pseudocode>
  ```
- **Remediation**: วิธีแก้ที่ถูกต้อง พร้อม code example:
  ```
  <fixed code>
  ```

---

### Attack Chain Analysis
<ถ้ามี findings หลายอย่างที่ chain กันได้ อธิบาย end-to-end attack scenario>
<ถ้าไม่มี ให้ระบุว่า "ไม่พบ attack chain ที่ชัดเจน">

---

### Risk Summary

| ID | Finding | Category | Severity | CVSS | Exploitable |
|----|---------|----------|----------|------|-------------|
| CRVN-001 | SQL Injection ใน login | Security | Critical | 9.8 | ✅ ทันที |
| CRVN-002 | Hardcoded API key | Security | High | 7.5 | ✅ ด้วย source access |
| CRVN-003 | N+1 query ใน /users | Performance | Medium | - | - |

### Priority Action Items
**🚨 ด่วนมาก (Critical — แก้ทันที)**
1. <CRVN-XXX>: <สรุปปัญหาและวิธีแก้สั้นๆ>

**⚠️ ด่วน (High — แก้ใน sprint นี้)**
2. <CRVN-XXX>: ...

**📋 แนะนำ (Medium/Low — backlog)**
3. <CRVN-XXX>: ...

### Coverage Summary
- ✅ Security: ตรวจแล้ว | พบ X findings
- ✅ Pentest Analysis: ตรวจแล้ว | พบ X findings exploitable
- ✅ Code Quality: ตรวจแล้ว | พบ X findings
- ✅ Performance: ตรวจแล้ว | พบ X findings
```

---

## กฎสำคัญ

**การวิเคราะห์:**
- ถ้า code ยาวมาก ให้วิเคราะห์ทีละ section แล้วรวม report ตอนท้าย
- ถ้าไม่พบ finding ในหมวดใด ให้เขียน "ไม่พบปัญหาในหมวดนี้" อย่างชัดเจน — ห้ามข้าม
- ถ้า user ส่ง diff/PR ให้โฟกัสที่ส่วนที่เปลี่ยนแปลง แต่ดู context รอบข้างด้วย
- ถ้า user ระบุ scope เช่น "เช็คแค่ SQL injection" ให้ deep-dive เฉพาะส่วนนั้น แต่ mention ถ้าเห็น critical อื่นๆ ระหว่างทาง
- PoC payload ให้เขียนเฉพาะที่สาธิตได้โดยไม่ก่อให้เกิดความเสียหายจริง เช่น `' OR '1'='1` แต่ไม่เขียน exploit code ที่ทำลายระบบได้โดยตรง

**ภาษา:**
- รายงานทั้งหมดเป็นภาษาไทย
- Technical term, command, code ให้ใช้ภาษาอังกฤษ
- ชื่อ vulnerability เช่น "SQL Injection" ไม่ต้องแปล

ดูรายละเอียด checklist เพิ่มเติมที่ `references/security-checklist.md`
