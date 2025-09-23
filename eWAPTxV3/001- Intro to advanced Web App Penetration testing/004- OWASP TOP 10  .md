
<img width="100%" height="400" alt="mapping" src="https://github.com/user-attachments/assets/3385fa65-5ec1-4cd4-96f6-51d0bf7848db" />


## What is the OWASP Top 10?

* The **OWASP Top 10** is a regularly updated list of the **most critical web application security risks**.
* It is maintained by the **Open Web Application Security Project (OWASP)**, a nonprofit organization focused on improving web application security.
* The OWASP Top 10 serves as a **valuable guide for developers, web app pentesters, and organizations** to understand and prioritize common security risks in web applications.

In simple terms: it’s the “must-know” list for anyone working with web apps, whether they’re writing code, securing it, or testing it.

---

## OWASP Top 10 Releases

* The OWASP Top 10 is a **well-known list** that highlights the ten most critical web application risks.
* It undergoes **periodic updates** to reflect the current threat landscape and evolving security challenges faced by web applications.
* The **first version (2003)** aimed to raise awareness and help developers prioritize security efforts. It already included major risks like:

  * **Cross-Site Scripting (XSS)**
  * **SQL Injection**
  * **Session Management issues**
* Each release since then has built on the previous version, making it more accurate, relevant, and practical for modern applications.

---

## Why is it Important?

1. **For Developers**
   Helps avoid common coding mistakes that lead to critical vulnerabilities.
   Example: Knowing that **XSS** is a top risk teaches developers to properly sanitize and encode user input.

2. **For Pentesters**
   Provides a baseline for testing. If an app fails against the OWASP Top 10, it’s already exposed to major risks.
   Example: A tester can quickly check for **SQL Injection** to see if attackers could steal data from the database.

3. **For Organizations**
   Helps prioritize which security issues should be fixed first, where to train staff, and how to align with compliance frameworks.

---

## Evolution of the OWASP Top 10

OWASP doesn’t just list vulnerabilities — it updates them based on **real-world data, industry input, and actual breaches**. Let’s compare the two most recent major releases:

### OWASP Top 10 – 2017

1. **A1 – Injection** (SQL, NoSQL, OS Command Injection, LDAP, etc.)
2. **A2 – Broken Authentication**
3. **A3 – Sensitive Data Exposure**
4. **A4 – XML External Entities (XXE)**
5. **A5 – Broken Access Control**
6. **A6 – Security Misconfiguration**
7. **A7 – Cross-Site Scripting (XSS)**
8. **A8 – Insecure Deserialization**
9. **A9 – Using Components with Known Vulnerabilities**
10. **A10 – Insufficient Logging & Monitoring**

🔹 *Why it mattered:* This version reflected the rise of serialization attacks (A8) and continued the focus on XSS, injection, and broken auth.

---

### OWASP Top 10 – 2021

1. **A01: Broken Access Control** (moved up from #5 → now #1 due to prevalence)
2. **A02: Cryptographic Failures** (renamed from Sensitive Data Exposure to emphasize crypto issues)
3. **A03: Injection** (SQLi, OS, LDAP — still critical, but ranked lower due to awareness)
4. **A04: Insecure Design** (new category, stressing the importance of secure architecture)
5. **A05: Security Misconfiguration**
6. **A06: Vulnerable and Outdated Components** (expanded from “Known Vulnerabilities”)
7. **A07: Identification and Authentication Failures** (merged Broken Auth & Session Management)
8. **A08: Software and Data Integrity Failures** (new, covers CI/CD attacks, supply chain risks, deserialization)
9. **A09: Security Logging and Monitoring Failures** (renamed from Insufficient Logging & Monitoring)
10. **A10: Server-Side Request Forgery (SSRF)** (new, due to its growing exploitation in real-world breaches)

🔹 *Why it mattered:* The 2021 list reflects modern threats like **supply-chain compromises** and **SSRF** (e.g., Capital One breach). It also emphasizes **insecure design** — pushing teams to think security-first, not just patch later.

---

## Comparing 2017 vs 2021

* **XSS (2017 A7)** → no longer standalone in 2021. It’s treated as part of **Injection** and **Insecure Design**.
* **Broken Authentication** + **Session Management** → merged into **Identification & Authentication Failures (2021 A07)**.
* **XXE (2017 A4)** → absorbed into **Security Misconfiguration** and **Insecure Design** in 2021.
* **New in 2021**:

  * **Insecure Design**
  * **Software and Data Integrity Failures**
  * **SSRF**

---

## Real-World Example

* In 2019, **Capital One** suffered a massive breach through **SSRF (Server-Side Request Forgery)**, where an attacker tricked a web app into making internal requests and exposing sensitive data.

  * In 2017’s list, SSRF wasn’t explicitly mentioned.
  * By 2021, it became a **Top 10 risk (A10)** because of incidents like this.

---

## Summary

* The **OWASP Top 10** is the industry baseline for web app security risks.
* First released in **2003**, it continues to evolve with the threat landscape.
* **2017** emphasized classic risks like XSS, Injection, and XXE.
* **2021** shifted toward modern issues: Insecure Design, Supply Chain Attacks, and SSRF.
* Every pentest and secure development lifecycle should align with the OWASP Top 10 — it’s the minimum, not the maximum.
