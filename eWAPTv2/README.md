# INE / eLearnSecurity — eWPTv2 Notes


<p align="center">
  <img width="279" height="369" alt="eWAPT" src="https://github.com/user-attachments/assets/1947cacf-fba7-4f04-bce1-fcd12a1caeac" />
</p>




[**Official course (learning path)**](https://my.ine.com/CyberSecurity/learning-paths/8c322180-1499-40c7-af8f-a877554fca3d/web-application-penetration-testing-professional-ewptv2)

[**Certification / Exam page**](https://ine.com/security/certifications/ewpt-certification)

---

## Overview

This repository contains a comprehensive and structured set of notes for preparing the **INE / eLearnSecurity Web Application Penetration Tester (eWPTv2)** certification. The goal is to provide a study-ready `README.md` that you can keep in your GitHub repo as a single source of truth while preparing for the exam and practicing in labs.

The eWPTv2 cert focuses on hands-on, practical web application penetration testing skills. It is a milestone for testers who want to demonstrate ability to work in real engagements: from reconnaissance and mapping, to manual exploitation and reporting.

---

## Who this is for

* Security practitioners with foundational web app testing experience.
* Anyone preparing to take the eWPTv2 certification exam.
* Engineers wanting a methodical, lab-based path to learn real-world web application exploitation and reporting.

---

## Exam format & logistics

* **Type:** Lab-based multiple-choice / practical questions delivered via INE lab environment.
* **Duration:** 10 hours.
* **Certificate validity:** 3 years.
* **Focus:** Practical exploitation and reasoning, not only theory.

**Important:** Read INE's exam and lab guidelines on the certification page before booking the exam.

---

## Course structure & estimated hours

Total curriculum delivered by INE: **\~106 hours**. The breakdown below mirrors the official learning path modules and recommended practice time.

* Introduction to Web App Security Testing (WAPT) — \~11 hours
* Web Fingerprinting & Enumeration — \~10 hours
* Web Proxies (Burp) — \~12 hours
* Cross-Site Scripting (XSS) — \~9 hours
* SQL Injection (SQLi) — \~17 hours
* Common Attacks — \~12 hours
* File & Resource Attacks — \~11 hours
* Web Service Security Testing — \~5 hours
* CMS Pentesting — \~9 hours
* Encoding, Filtering & Evasion — \~8 hours

---

## Detailed Exam Objectives

Below are the objective domains and the specific skills you must demonstrate.

### 1. Web App Penetration Testing Processes & Methodologies (10%)

* Follow an industry standard methodology (OWASP WSTG) and map tests to objectives.
* Produce reproducible, concise findings and prioritize issues by impact.

### 2. Information Gathering & Reconnaissance (10%)

* Passive & active enumeration of domains/subdomains/IPs.
* Extract metadata or configuration leaks from web files.
* Use OSINT and code search to gather useful context.

### 3. Web Application Analysis & Inspection (10%)

* Fingerprint server/technology stacks and identify endpoint structure.
* Locate hidden endpoints, parameters, and test unsupported HTTP methods.

### 4. Web Application Vulnerability Assessment (15%)

* Identify misconfigurations, default creds, authentication weaknesses.
* Test session management and information disclosure.

### 5. Web Application Security Testing (25%)

* Exploit directory traversal, file upload chains, LFI/RFI, session weaknesses, command injection, and vulnerable components.
* Perform targeted brute-force attacks when applicable.

### 6. Manual Exploitation of Common Web Vulnerabilities (20%)

* Exploit Reflected/Stored/DOM XSS and SQL Injection variants.
* Extract useful data from backend systems.

### 7. Web Service Security Testing (10%)

* Test REST/SOAP APIs for authentication, parameter tampering, and flawed logic.

---

## Practical labs & recommended vulnerable apps

Practice in local and isolated lab environments. Recommended applications for hands-on practice:

* **Mutillidae II** — intentionally vulnerable web app. (OWASP project)
* **Damn Vulnerable Web App (DVWA)** — classic lab app for SQLi/XSS/file upload.
* **OWASP Juice Shop** — modern vulnerable app covering many CWE categories.

Use XAMPP or Docker to host these apps locally, or practice on intentionally vulnerable cloud labs.

---

## Essential tools

* **Burp Suite** — Proxy, Repeater, Intruder, Decoder, Extender. (Pro recommended but Community works for manual testing)
* **nmap** — host discovery and port scanning.
* **amass / subfinder / assetfinder** — subdomain and footprint enumeration.
* **ffuf / gobuster** — content discovery & fuzzing.
* **sqlmap** — automated SQLi verification (use after manual confirmation).
* **curl / httpie / Postman** — API testing.
* **Python (requests, BeautifulSoup)** — quick scripts and automations.

---

## 12-week Study Plan (suggested)

A practical weekly plan to cover theory, tools, and labs.

* **Weeks 1–2 — Foundations & Recon**

  * Finish introduction and fingerprinting modules.
  * Practice passive recon, subdomain enumeration, and `nmap` scans.

* **Weeks 3–4 — Proxies & Manual Testing**

  * Master Burp Suite core features (Proxy, Repeater, Intruder).
  * Intercept and modify requests; build a payload library.

* **Weeks 5–6 — XSS & SQLi**

  * Learn reflected/stored/DOM XSS and SQLi variants.
  * Practice chains leading to data extraction and impact.

* **Weeks 7–8 — File & Resource Attacks**

  * Practice file upload RCE chains, directory traversal and LFI/RFI.

* **Weeks 9–10 — Web Services & CMS**

  * Focus on REST/SOAP testing, JWT/Token handling, and CMS (e.g., WordPress) common flaws.

* **Weeks 11–12 — Evasion & Full-lab Practice**

  * Encoding/evasion techniques and take full-length 10-hour simulated lab exams.

---

## Exam tactics & tips

* **Plan your time.** Start with quick surface-mapping and prioritize high-severity avenues (RCE / SQLi / auth bypass).
* **Keep concise evidence.** Take short screenshots and copy key request/response snippets.
* **Confirm findings manually** before relying on automated output.
* **If stuck, pivot.** Try another area (API endpoints, upload handling, components) — many high-value issues can be discovered off the main flow.

---

## Pre-exam checklist

* [ ] Confirm access to a stable internet connection and clean lab environment.
* [ ] Prepare a local note template to capture steps, commands, and PoC snippets.
* [ ] Ensure Burp and any local tools are ready and tested.
* [ ] Review RCE, SQLi, XSS methodology and common exploitation chains.
* [ ] Do at least one full 10-hour practice exam/lab to simulate pacing.

---

## Quick setup: XAMPP + Mutillidae II (high-level)

1. Download and install XAMPP for your platform: [https://www.apachefriends.org/](https://www.apachefriends.org/)
2. Start Apache and MySQL from the XAMPP control panel.
3. Clone Mutillidae II into your web root (e.g., `htdocs`): follow instructions on the Mutillidae project page.
4. Configure database (import if required) and visit `http://localhost/mutillidae`.

---

## Resources & links

* [**INE — eWPTv2 learning path (course content)**](https://my.ine.com/CyberSecurity/learning-paths/8c322180-1499-40c7-af8f-a877554fca3d/web-application-penetration-testing-professional-ewptv2)
* [**INE — eWPT certification / exam**](https://ine.com/security/certifications/ewpt-certification)
* [**OWASP Web Security Testing Guide (WSTG)**](https://owasp.org/www-project-web-security-testing-guide/)
* [**Mutillidae II:**](https://owasp.org/www-project-mutillidae-ii/)
* [**DVWA (GitHub)**](https://github.com/digininja/DVWA)
* [**OWASP Juice Shop**](https://owasp.org/www-project-juice-shop/)
* [**Burp Suite**](https://portswigger.net/burp)
* [**XAMPP**](https://www.apachefriends.org/)
* [**OWASP SQL Injection Prevention Cheat Sheet**](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [**ffuf**](https://github.com/ffuf/ffuf)

---

## How to contribute / use this repo

* Fork this repo and submit pull requests with improvements to the study plan, additional lab writeups, or notes.
* Add `labs/` folders with step-by-step exploitation writeups (screenshots, requests, payloads, mitigation suggestions).
* Keep content practical and reproducible — include exact commands and expected outputs when possible.

---

## License

This document is provided for educational purposes. Use these notes for personal study and lab practice only. Do not use any skills learned here against systems without explicit authorization.

