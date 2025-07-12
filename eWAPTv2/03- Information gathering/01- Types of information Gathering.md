<div align="center">
  <img src="https://github.com/user-attachments/assets/45641d2e-3890-4452-b7ba-ad29aca440a6" alt="image">
</div>

### What is Information Gathering?

Information gathering — also known as **Reconnaissance** — is the **first and one of the most critical phases** in any penetration test or security assessment.

It involves collecting data about your target, which could be an individual, a company, a website, or a system. The goal is to understand the target’s digital footprint, infrastructure, and potential weaknesses **before attempting any form of exploitation**.

The more detailed and accurate the information you gather during this phase, the higher your chances of successfully identifying and exploiting security flaws later on.

---

### Why is Information Gathering Important?

* It lays the **foundation** for all subsequent steps in a penetration test.
* Helps in **mapping the attack surface** and understanding what you're dealing with.
* Supports better **decision-making** during vulnerability scanning and exploitation.
* Helps identify **potential entry points** or misconfigurations early.

> In web application penetration testing, information gathered in this phase becomes especially valuable when analyzing the app’s logic, technologies used, and infrastructure dependencies during the exploitation phase.

---

### Types of Information Gathering

Information gathering can be classified into two categories:

#### 1. **Passive Information Gathering**

Passive recon involves collecting information **without directly interacting** with the target. This means you're gathering data in a way that doesn’t alert the target or leave noticeable traces.

* **Doesn’t require authorization.**
* Ideal for stealth operations or open-source intelligence (OSINT).
* Mostly done using public resources and third-party services.

#### 2. **Active Information Gathering (Enumeration)**

Active recon involves **interacting directly** with the target systems to extract detailed information.

* **Requires explicit authorization**, especially in real-world assessments.
* Typically leaves traces/logs on the target systems.
* More intrusive, but provides deeper insights.

---

### What Kind of Information Are We Looking For?

During recon, you aim to collect various types of technical and contextual information:

| Type                           | Examples                                                           |
| ------------------------------ | ------------------------------------------------------------------ |
| **Domain & Ownership**         | WHOIS data, registrar info, DNS records                            |
| **IP Address Details**         | Hosting providers, geolocation                                     |
| **Subdomains**                 | `dev.example.com`, `admin.example.com`                             |
| **Hidden Files & Directories** | `/admin/`, `/backup/`, `.git/`                                     |
| **Server Infrastructure**      | Web server type (Apache, Nginx), CMS (WordPress), database (MySQL) |
| **Web Technologies**           | Frameworks (React, Django), libraries, plugins                     |
| **Security Mechanisms**        | Presence of Web Application Firewalls (WAF), rate-limiting         |
| **Website Structure**          | Page hierarchy, exposed endpoints, URL patterns                    |

---

###  Passive Information Gathering – Techniques & Goals

Passive recon focuses on **external observation**. Common activities include:

* Identifying **domain names** and ownership using WHOIS tools.
* Enumerating **subdomains** via public DNS records and search engines.
* Gathering **DNS information**, such as A, MX, and TXT records.
* Detecting **technologies** used on the website via services like [Wappalyzer](https://www.wappalyzer.com) or [BuiltWith](https://builtwith.com).
* Finding **robots.txt** and sitemap files that may expose disallowed/hidden paths.
* Searching for **leaked credentials** or sensitive data using Google Dorking or breach databases.
* Identifying **WAFs** or CDN usage (like Cloudflare).

---

###  Active Information Gathering (Enumeration) – Techniques & Goals

Active recon dives deeper by **interacting with the target** system. Examples include:

* **Downloading and analyzing source code** of the web application (static files like JavaScript, HTML).
* **Port scanning** using tools like `nmap` to find open ports and services.
* **Service fingerprinting** to identify versions and potential vulnerabilities.
* **Web vulnerability scanning** using tools like `Nikto`, `Dirb`, `Burp Suite Scanner`.
* Performing **DNS Zone Transfers** (if misconfigured) to get full DNS structure.
* **Brute-force subdomain enumeration** using wordlists and tools like `Sublist3r`, `Amass`, `DNSRecon`.

---

