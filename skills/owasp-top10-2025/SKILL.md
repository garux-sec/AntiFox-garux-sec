---
name: owasp-top10-2025
description: ใช้ OWASP Top 10 2025 framework สำหรับ map และจัดหมวดหมู่ pentest findings/vulnerabilities เป็น OWASP category (A01:2025 - A10:2025) ให้ใช้ skill นี้ทันทีเมื่อ user ขอให้ classify, categorize, หรือ map ช่องโหว่/finding เข้ากับ OWASP Top 10, ขอ OWASP code, หรือกำลังเขียน/รีวิว pentest report ที่ต้องอ้างอิง OWASP categories แม้ user จะไม่ได้พิมพ์คำว่า "OWASP" ตรงๆ ก็ตาม เช่น พูดถึง IDOR, SQLi, XSS, JWT vuln, hardcoded secret, mass assignment, default credentials, XXE, insecure deserialization, missing rate limiting, verbose error message ฯลฯ ในบริบทของ security finding ก็ควร trigger skill นี้เพื่อ map ไปยัง A0X:2025 ที่ถูกต้อง
---

# OWASP Top 10 2025 Mapping

ใช้ skill นี้เพื่อ map security findings เข้ากับหมวดหมู่ OWASP Top 10 2025 (A01:2025–A10:2025) สำหรับงาน pentest report ของ Garux และ ai-report platform

## วิธีใช้

1. อ่าน finding ที่ user ให้มา (ชื่อช่องโหว่, คำอธิบาย, หรือ CVE)
2. เปิด `references/owasp_top10_2025.md` เพื่อดูรายละเอียดแต่ละ category, common findings, และ quick mapping table
3. เลือก OWASP code (A0X:2025) ที่ตรงที่สุด พร้อม short tag (เช่น `INJECTION`, `BAC`)
4. หากมีหลาย finding ให้จัดเป็นตารางสรุป: Finding → OWASP Code → เหตุผลสั้นๆ ที่เลือก

## จุดสำคัญที่ต้องระวัง

- **A03:2025 (Software Supply Chain)** และ **A10:2025 (Mishandling of Exceptional Conditions)** เป็น category ใหม่ของปี 2025 — อย่าลืมพิจารณาเมื่อเจอ vulnerable dependency หรือ verbose error
- **XSS** (stored/reflected/DOM) ทุกแบบ → จัดเข้า **A05:2025 Injection** ไม่มี category แยกแล้ว
- **Mass Assignment** และ business logic flaws → **A06:2025 Insecure Design**
- **Token exposure ผ่าน localStorage** → **A07:2025 Authentication Failures**

ดูรายละเอียดเต็มและ quick reference table ได้ที่ `references/owasp_top10_2025.md`
