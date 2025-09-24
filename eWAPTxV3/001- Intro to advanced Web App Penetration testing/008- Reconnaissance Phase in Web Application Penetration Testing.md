
## What is Reconnaissance :

The **Reconnaissance Phase (Recon)** is the first hands-on stage of a web application penetration test after the **Pre-Engagement Phase**. It sets the foundation for all later activities by collecting as much information as possible about the target. The quality and depth of reconnaissance directly impact the effectiveness of later testing.

Recon can be divided into two main categories:

1. **Passive Reconnaissance** – Information gathering without directly interacting with the target system.
2. **Active Reconnaissance** – Directly interacting with the target system to discover technical details.

---

## 1. Objectives of Reconnaissance

* Build an understanding of the target application, environment, and infrastructure.
* Identify potential attack surfaces (subdomains, technologies, entry points).
* Gather information about the organization that might help in exploitation.
* Reduce guesswork later by mapping out the ecosystem in advance.

**Example:** If you discover during recon that the app uses `WordPress 5.5`, you can immediately note potential known vulnerabilities instead of wasting time fuzzing irrelevant endpoints.

---

## 2. Passive Reconnaissance

This involves gathering information **without sending direct requests to the target system**. It’s stealthy and avoids detection but can still reveal a lot.

### Common Passive Recon Techniques:

* **WHOIS Lookups**

  * Reveal domain registration details, owner, contact emails, and DNS servers.
  * Example: Running `whois example.com` might reveal the registrar, technical contact email, and creation date.

* **DNS Enumeration (Public Sources)**

  * Using services like `crt.sh` (Certificate Transparency logs) or `VirusTotal` to discover subdomains.
  * Example: Searching `site:example.com` on Google or viewing certificate logs may reveal hidden subdomains like `dev.example.com` or `test.api.example.com`.

* **Search Engine Dorking (Google Dorks)**

  * Using advanced search queries to find exposed files, directories, or error messages.
  * Example: `site:example.com ext:sql` might show accidentally exposed SQL backup files.

* **Leaked Credentials / Breach Databases**

  * Searching repositories like `HaveIBeenPwned` or GitHub for leaked credentials.
  * Example: A developer accidentally commits AWS keys to GitHub — you find them via recon.

* **Social Media & Open Source Intelligence (OSINT)**

  * Gathering data about employees, technologies, and naming conventions from LinkedIn, Twitter, or job postings.
  * Example: A job post mentioning “We’re hiring Node.js developers with AWS experience” hints at the stack used.

### Tools for Passive Recon:

* `whois`, `dig`, `host` (basic DNS info)
* `crt.sh`, `Sublist3r`, `Amass` (subdomain enumeration)
* `theHarvester` (collecting emails, subdomains, IPs)
* Search engines with dorks

---

## 3. Active Reconnaissance

This involves **direct interaction with the target system** (sending requests, scanning, probing). It’s noisier and might trigger detection but gives more detailed technical insights.

### Common Active Recon Techniques:

* **Port Scanning**

  * Identify open ports and running services.
  * Example: `nmap -sV example.com` reveals that port 443 is running Nginx 1.18.0.

* **Service and Banner Grabbing**

  * Extract software versions and configurations from services.
  * Example: Curling `https://example.com` might show a `Server: Apache/2.4.49` header (known for vulnerabilities).

* **Subdomain Brute-forcing**

  * Using wordlists to brute force possible subdomains.
  * Example: `ffuf -u https://FUZZ.example.com -w subdomains.txt` discovers `admin.example.com`.

* **Directory and File Enumeration**

  * Discover hidden directories and files on the web server.
  * Example: `gobuster dir -u https://example.com -w common.txt` reveals `/backup/`.

* **Technology Fingerprinting**

  * Detect frameworks, libraries, and CMS in use.
  * Example: Tools like `Wappalyzer` or `BuiltWith` might detect Django, AngularJS, or PHP versions.

* **API Discovery**

  * Identifying hidden or undocumented APIs.
  * Example: Looking at `robots.txt` or intercepting traffic with Burp Suite might reveal `/api/v1/private/`.

### Tools for Active Recon:

* `nmap`, `masscan` (network scans)
* `ffuf`, `dirsearch`, `gobuster` (directory/file brute-forcing)
* `Burp Suite` (interception, analyzing requests)
* `Wappalyzer`, `whatweb` (tech detection)
* `Amass`, `Subfinder` (advanced subdomain enumeration)

---

## 4. Recon Deliverables

At the end of the Recon phase, the pentester should have:

* A **list of domains and subdomains** (including hidden ones).
* A **map of open ports and running services**.
* A **list of technologies and frameworks used** (frontend & backend).
* Identified **potentially interesting files, directories, and APIs**.
* A collection of **OSINT data** that might help in social engineering or further exploitation.

---

## 5. Recon Example

Let’s say the target is **`example.com`**.

**Passive Recon Findings:**

* From `crt.sh`, you discover subdomains: `mail.example.com`, `dev.example.com`, `vpn.example.com`.
* A Google dork reveals a PDF file with internal email addresses.
* A LinkedIn job ad shows the company uses Django and PostgreSQL.

**Active Recon Findings:**

* Nmap shows `dev.example.com` has port `22 (SSH)` and `443 (HTTPS)` open.
* Directory brute-forcing on `dev.example.com` reveals `/staging/` and `/debug/`.
* Banner grabbing shows `Apache/2.4.49` (a vulnerable version).
* Using Wappalyzer, you identify ReactJS on the frontend and Django backend.

**Result:** You now know there’s a staging environment running outdated Apache with debug endpoints. This becomes a **high-priority target** in later exploitation.

