![image](https://github.com/user-attachments/assets/80841d6e-37a5-4644-8263-3748bab5542b)

### What Is the OWASP Top 10?

The **OWASP Top 10** is a **regularly updated list** of the **most critical web application security risks**. It’s maintained by the **Open Web Application Security Project (OWASP)**—a nonprofit organization focused on improving software security.

This list serves as a **foundation and awareness document** for:

* Developers
* Penetration testers
* Security teams
* Organizations building or using web apps

The OWASP Top 10 helps everyone involved in web development understand **common vulnerabilities**, how attackers exploit them, and how to **prevent** them.

---

### Why It’s Important

* Recognized globally as a **standard for web application security**.
* Used in **compliance, training, security assessments**, and audits.
* Helps teams **prioritize their defenses** and **patch known weaknesses**.
* Promotes **secure-by-design thinking** in the development lifecycle.

---

### History of OWASP Top 10 Releases

| Year          | Notable Points                                                                                                                                                              |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **2003**      | First release. Covered core risks like SQLi, XSS, session issues. Focused on awareness.                                                                                     |
| **2010–2017** | Expanded on modern threats. Introduced clear categories and risk-ranking models.                                                                                            |
| **2021**      | Latest update (as of now). Included newer concepts like **Insecure Design**, **Software/Data Integrity Failures**, and **SSRF**. More aligned with real-world exploit data. |

Each update improves **relevance, clarity, and applicability** to current development practices and technologies.

---

### OWASP Top 10 (2021 Version)

| Code | Name                                         | Description                                                                                 |
| ---- | -------------------------------------------- | ------------------------------------------------------------------------------------------- |
| A01  | **Broken Access Control**                    | Users can perform actions or access data they’re not supposed to.                           |
| A02  | **Cryptographic Failures**                   | Data not properly protected in transit or at rest. Often due to weak/missing encryption.    |
| A03  | **Injection**                                | User input interpreted as code (SQLi, Command Injection, etc).                              |
| A04  | **Insecure Design**                          | Application design lacks proper security controls (e.g., threat modeling, secure patterns). |
| A05  | **Security Misconfiguration**                | Misconfigured servers, frameworks, or headers. Default accounts or verbose errors.          |
| A06  | **Vulnerable and Outdated Components**       | Using software with known bugs or unpatched CVEs.                                           |
| A07  | **Identification & Authentication Failures** | Weak login flows, poor password hygiene, broken session handling.                           |
| A08  | **Software and Data Integrity Failures**     | Relying on code or plugins from untrusted sources, missing integrity checks.                |
| A09  | **Security Logging and Monitoring Failures** | No alerts or detection mechanisms for suspicious behavior.                                  |
| A10  | **Server-Side Request Forgery (SSRF)**       | The server is tricked into making requests to internal systems.                             |

---

##  OWASP Web Security Testing Guide (WSTG)

### What Is It?

The **OWASP WSTG** (Web Security Testing Guide) is a **detailed manual** that provides a structured, step-by-step methodology for **testing web application security**.

It is:

* **Community-driven** and continuously updated
* Used by security professionals, auditors, and penetration testers
* Designed to ensure full **coverage of common and uncommon vulnerabilities**

---

### What Does It Include?

* Over **60 detailed test cases**
* Covers everything from **input validation to session management**
* Helps testers **plan, execute, and document** their work clearly
* Links directly to OWASP Top 10 risks and real-world attack patterns

---

### Main Testing Categories in WSTG

| Category                     | Purpose                                                             |
| ---------------------------- | ------------------------------------------------------------------- |
| **Information Gathering**    | Discover what the app is built with and how it behaves              |
| **Configuration Management** | Look for dangerous default settings or exposed services             |
| **Authentication Testing**   | Assess login processes, password policies, 2FA, etc.                |
| **Authorization Testing**    | Ensure users can only access what they’re allowed to                |
| **Session Management**       | Test for session fixation, hijacking, and proper timeout            |
| **Input Validation**         | Identify SQLi, XSS, command injection, etc.                         |
| **Error Handling**           | Check if error messages leak sensitive info                         |
| **Business Logic Testing**   | Test workflow flaws that can’t be spotted by scanners               |
| **Client-Side Testing**      | Analyze JavaScript and browser-side issues (DOM XSS, storage, etc.) |

---

##  OWASP WSTG Checklist

### What Is It?

The **WSTG Checklist** is a **spreadsheet version** of the WSTG methodology, used to **track progress** and **ensure nothing is missed** during a web app pentest.

---

### Key Features:

* Includes **all test cases from WSTG**, categorized and explained
* Has columns for:

  * Test status (Pass/Fail/Not Tested)
  * Notes and PoCs
  * Affected components
* Supports **risk assessment scoring** using OWASP or CVSS methods
* Includes templates for:

  * **Risk Assessment Calculator**
  * **Summary of Findings**

---

### Sample Checklist Entries:

| Test ID      | Description                       | Status    |
| ------------ | --------------------------------- | --------- |
| WSTG-ATHN-03 | Test for bypassing authentication | ❌ Failed  |
| WSTG-SESS-05 | Check for session expiration      | ✅ Passed  |
| WSTG-INPV-02 | Reflected XSS via query parameter | ⏳ Pending |

---

### How to Use the Checklist:

1. Start your pentest with a **copy of the checklist**.
2. Go through each test item and update its status.
3. Add notes, screenshots, and request/response samples as you go.
4. Use it to guide your **reporting phase** and **justify test coverage**.

---

##  Summary

| Topic              | Purpose                                                         |
| ------------------ | --------------------------------------------------------------- |
| **OWASP Top 10**   | Helps you understand **what the most common risks are**.        |
| **OWASP WSTG**     | Tells you **how to test** for those risks, in a structured way. |
| **WSTG Checklist** | Helps you **track your testing** and build strong reports.      |


## OWASP Top 10

- [OWASP Top 10 Official Page (2021)](https://owasp.org/www-project-top-ten/)
- [OWASP Top 10 2021 Full PDF Report](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2021.pdf)
- [OWASP Top 10 Comparison & Details (All Languages)](https://owasp.org/Top10/)

---

## OWASP Web Security Testing Guide (WSTG)

- [Official OWASP WSTG Project Page](https://owasp.org/www-project-web-security-testing-guide/)
- [WSTG GitHub Repository (Full Methodology)](https://github.com/OWASP/wstg)
- [WSTG Full PDF Download (v4)](https://owasp.org/www-pdf-archive/OWASP_Testing_Guide_v4.pdf)

---

## OWASP WSTG Checklist

- [Checklist (.xlsx) Direct Download](https://github.com/OWASP/wstg/raw/master/checklist/WSTG-Checklist.xlsx)
- [Checklist Folder on GitHub](https://github.com/OWASP/wstg/tree/master/checklist)

---

## OWASP Risk Rating Methodology

- [OWASP Risk Rating Calculator & Explanation](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)

---

## Other Testing Methodologies

### PTES – Penetration Testing Execution Standard
- [Official PTES Website](http://www.pentest-standard.org/index.php/Main_Page)

### NIST SP 800-115 – Technical Guide to Information Security Testing
- [NIST SP 800-115 PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf)

### OSSTMM – Open Source Security Testing Methodology Manual
- [OSSTMM v3 PDF (ISECOM)](https://www.isecom.org/OSSTMM.3.pdf)

---
