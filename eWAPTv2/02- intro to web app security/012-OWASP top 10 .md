![image](https://github.com/user-attachments/assets/80841d6e-37a5-4644-8263-3748bab5542b)


---

##  **OWASP Top 10**

###  What is OWASP?

**OWASP** (Open Web Application Security Project) is a **non-profit organization** focused on **improving the security of software applications**, especially web applications.
It offers **free, open-source projects** like testing guides, tools, documentation, and community support that are widely used by developers and security professionals around the world.

OWASP is:

* **Community-driven**
* **Vendor-neutral**
* **Respected in both private and government sectors**

---

###  What is the OWASP Top 10?

The **OWASP Top 10** is a list of the **ten most critical web application security risks**. It is widely used as:

* A **training tool** for developers
* A **testing baseline** for penetration testers
* A **compliance reference** for organizations

It is updated every few years based on:

* Real-world vulnerability data
* Industry trends
* Feedback from security experts globally

---

###  Why Is It Important?

* Focuses attention on **the most impactful and common vulnerabilities**
* Helps organizations **prioritize remediation**
* Forms the basis for **secure software development practices**
* Referenced in **regulatory and compliance standards**

---

###  How Is It Built?

The list is created based on:

* **Data from thousands of real-world applications**
* Expert analysis of exploitability, prevalence, detectability, and business impact
* Real attack scenarios and consequences

---

###  2021 OWASP Top 10 Categories Explained

| Risk # | Category                                   | Description                                                              |
| ------ | ------------------------------------------ | ------------------------------------------------------------------------ |
| A01    | Broken Access Control                      | Users gain unauthorized access to data or functions                      |
| A02    | Cryptographic Failures                     | Sensitive data exposed due to weak encryption or poor key management     |
| A03    | Injection                                  | Malicious input causing command or query execution (e.g., SQL Injection) |
| A04    | Insecure Design                            | Flaws in the application’s architecture or logic                         |
| A05    | Security Misconfiguration                  | Misconfigured servers, error messages, or unsafe defaults                |
| A06    | Vulnerable and Outdated Components         | Usage of insecure versions of libraries and frameworks                   |
| A07    | Identification and Authentication Failures | Poor login logic allowing unauthorized access                            |
| A08    | Software and Data Integrity Failures       | Use of untrusted software updates or CI/CD pipelines                     |
| A09    | Security Logging and Monitoring Failures   | Insufficient monitoring to detect and respond to attacks                 |
| A10    | Server-Side Request Forgery (SSRF)         | Server makes unauthorized requests to internal systems                   |

Each risk includes:

* Practical examples
* Testing methods
* Real-life consequences
* Mitigation guidance

---

###  OWASP Top 10 Resources

* [OWASP Top 10 Official Page (2021)](https://owasp.org/www-project-top-ten/)
* [OWASP Top 10 2021 Full PDF Report](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2021.pdf)
* [OWASP Top 10 Comparison (All Languages)](https://owasp.org/Top10/)

---

##  **OWASP Web Security Testing Guide (WSTG)**

###  What Is WSTG?

The **OWASP Web Security Testing Guide (WSTG)** is a **comprehensive manual** for performing **web application penetration testing**.

It provides:

* A **complete methodology** for security assessments
* Clear explanations of **what to test, why, and how**
* Coverage of **common vulnerabilities, misconfigurations, and attack vectors**

The guide is maintained by the OWASP community and is suitable for:

* Penetration testers
* Secure code reviewers
* QA/security teams

---

###  WSTG Sections and Testing Categories

The guide is organized into logical testing areas such as:

* **Information Gathering**
* **Authentication Testing**
* **Session Management Testing**
* **Input Validation Testing**
* **Business Logic Testing**
* **API Testing**
* **Configuration and Deployment Testing**

Each section provides:

* An explanation of the risk
* Test objectives
* Test techniques and tools
* Expected results
* Remediation advice

---

###  WSTG Resources

* [Official OWASP WSTG Project Page](https://owasp.org/www-project-web-security-testing-guide/)
* [WSTG GitHub Repository](https://github.com/OWASP/wstg)
* [WSTG Full PDF Download (v4)](https://owasp.org/www-pdf-archive/OWASP_Testing_Guide_v4.pdf)

---

##  **OWASP WSTG Checklist**

###  What Is It?

The **WSTG Checklist** is an **Excel spreadsheet** designed to help testers:

* Track test coverage
* Record test results
* Organize findings

It follows the structure of the WSTG and is ideal for:

* Solo pentesters
* Teams managing shared assessments
* Creating custom testing workflows

---

###  What Does It Include?

* A list of all WSTG test cases grouped by category
* **Status tracking** (Not Started, In Progress, Completed)
* A **Summary Findings Template**
* The **OWASP Risk Assessment Calculator**

---

###  Checklist Resources

* [Direct Checklist Download (.xlsx)](https://github.com/OWASP/wstg/raw/master/checklist/WSTG-Checklist.xlsx)
* [Checklist GitHub Folder](https://github.com/OWASP/wstg/tree/master/checklist)

---

##  **OWASP Risk Rating Methodology**

###  What Is It?

This methodology helps you **evaluate and prioritize** vulnerabilities by assigning a **risk score** based on:

* **Likelihood** of the vulnerability being exploited
* **Impact** it would have on the application and organization

Each factor is broken down into sub-categories, including:

* **Ease of exploit**
* **Awareness and detection**
* **Technical and business impact**

It results in a **Low, Medium, High, or Critical** risk level.

---

###  Why It’s Important

* Allows **consistent and objective** risk evaluation
* Helps organizations **focus on the most dangerous issues first**
* Used widely in **professional penetration testing reports**

---

###  Risk Rating Resource

* [OWASP Risk Rating Calculator & Explanation](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)

---
![S](https://github.com/user-attachments/assets/bf59aae7-d4c5-414c-81e8-563918fe5340)

##  **Pre-Engagement Steps for Pentesting**

Before a penetration test begins, certain **pre-engagement tasks** must be completed to:

* Define the **rules**
* Set the **scope**
* Avoid legal and ethical problems

---

###  1. Rules of Engagement (RoE)

This document outlines:

* What systems can be tested
* When testing is allowed (days/hours)
* What tools can be used
* Escalation and emergency procedures

---

###  2. Communication and Coordination

* Assign points of contact from both sides
* Ensure smooth coordination with developers, sysadmins, and managers
* Plan to avoid testing during peak business hours

---

###  3. Contracts and NDAs

* Sign a **legal agreement** covering the scope and goals
* Sign a **Non-Disclosure Agreement (NDA)** to protect sensitive information

---

###  4. Scoping Meeting

* Discuss **objectives, limitations, and assumptions**
* Define the environment (production, staging)
* Identify special concerns (e.g., legacy systems, APIs)

---

###  5. Preparing Tools and Resources

* Prepare testing environments (VMs, lab systems)
* Set up tools like Burp Suite, Nmap, SQLMap, etc.
* Confirm all licenses and accounts are working

---

###  6. Risk Assessment and Acceptance

* Evaluate possible negative effects of testing
* Get **written approval** from stakeholders to proceed

---

###  7. Engagement Kick-off

* Final confirmation of start and end dates
* Share RoE and final documentation with the full team

---

##  **Web Application Penetration Testing Report**

###  Importance of Reporting

The **final report** is the most important deliverable in any penetration test.
It documents:

* What was tested
* What vulnerabilities were found
* What their impact is
* How they can be fixed

---

###  Key Sections of a Report

* **Executive Summary**: written for non-technical stakeholders
* **Technical Details**: vulnerability descriptions, PoCs, and affected endpoints
* **Risk Ratings**: using OWASP or CVSS methodology
* **Remediation Advice**: detailed fix instructions
* **Appendices**: tools used, test methodology, raw results

---

###  Best Practices

* Document everything **during testing**, not just at the end
* Use **mind maps**, **spreadsheets**, and **markdown notes**
* Maintain clarity, structure, and professionalism

---

##  **Tools for Documentation**

Two of the most efficient tools for storing and organizing your findings:

* **Mind Maps**: to visualize relationships and attack paths
* **Spreadsheets**: for tabular tracking of test cases, risk scores, and results

By keeping organized notes throughout the engagement, the final report becomes easier to assemble and more reliable.

---

##  **Other Testing Methodologies**

While OWASP is the most popular, there are other widely recognized frameworks for security assessments.

---

###  PTES – Penetration Testing Execution Standard

* Covers the entire lifecycle of a pentest
* Sections include: Pre-engagement, Intelligence Gathering, Threat Modeling, Exploitation, Reporting
* [PTES Official Site](http://www.pentest-standard.org/index.php/Main_Page)

---

###  NIST SP 800-115 – Technical Guide to Security Testing

* Published by the **U.S. National Institute of Standards and Technology**
* Focuses on structured and regulated testing methodologies
* [NIST SP 800-115 PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf)

---

###  OSSTMM – Open Source Security Testing Methodology Manual

* Developed by **ISECOM**
* Covers network, wireless, and operational security
* Includes trust analysis and control mapping
* [OSSTMM v3 PDF](https://www.isecom.org/OSSTMM.3.pdf)

---
> All of the materials and frameworks above are **open source and free to use**. 
---

