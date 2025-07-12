**WHOIS** and **Netcraft**

<img width="1042" height="217" alt="image" src="https://github.com/user-attachments/assets/6cd0b5ec-ad15-4c3d-8c8b-74996c151b8e" />

##  WHOIS – Domain Registration & Ownership Lookup

###  What is WHOIS?

**WHOIS** is a **protocol and service** used to query databases that store registration and ownership information about Internet resources, especially **domain names** and **IP address allocations**.

It allows attackers, researchers, and security professionals to gather **open-source intelligence (OSINT)** about who owns a domain, how long it’s been active, what registrar was used, and which name servers or hosting providers are being used.

---

###  Why Use WHOIS During Recon?

WHOIS is a **non-intrusive, passive recon method** that can reveal:

| Insight                           | Example Usage                                               |
| --------------------------------- | ----------------------------------------------------------- |
| Domain owner name or organization | For identifying company ownership or links to other domains |
| Email addresses                   | For social engineering or credential leak searches          |
| Registrar info                    | To find hosting providers or spot patterns across domains   |
| Name servers                      | May expose third-party DNS providers or internal subdomains |
| IP address ranges                 | Useful for network mapping                                  |
| Creation and expiry dates         | To estimate domain age or detect abandoned domains          |

---

###  Typical WHOIS Output (Simplified Example)

```text
Domain Name: example.com
Registrar: NameCheap Inc.
Registrant Organization: Example Corp
Registrant Email: admin@example.com
Creation Date: 2021-05-03T15:00:00Z
Registry Expiry Date: 2026-05-03T15:00:00Z
Name Server: ns1.exampledns.com
Name Server: ns2.exampledns.com
Status: clientTransferProhibited
```

> In many cases, **WHOIS privacy services** (like WhoisGuard) may mask sensitive fields, replacing them with generic info. In such cases, additional techniques like historical WHOIS or certificate transparency logs may help.

---

###  How to Perform a WHOIS Lookup

####  CLI (Linux/macOS):

```bash
whois example.com
```

If `whois` isn’t installed:

```bash
sudo apt install whois  # Debian/Ubuntu
```

####  Windows (using PowerShell):

```powershell
(Invoke-RestMethod -Uri "https://api.hackertarget.com/whois/?q=example.com")
```

####  Web-Based WHOIS Tools:

| Tool         | URL                                                            |
| ------------ | -------------------------------------------------------------- |
| DomainTools  | [https://whois.domaintools.com](https://whois.domaintools.com) |
| Whois.com    | [https://www.whois.com/whois/](https://www.whois.com/whois/)   |
| ICANN Lookup | [https://lookup.icann.org](https://lookup.icann.org)           |
| ViewDNS      | [https://viewdns.info/whois/](https://viewdns.info/whois/)     |

These platforms may also show:

* **Historical WHOIS records**
* **Linked domains using same email**
* **Domain age & timeline graphs**

---

###  Real-World Use Cases of WHOIS in Pentesting

* Discovering the **organization behind a domain** to assist with social engineering.
* Finding **expired or abandoned domains** linked to a target company (which can be taken over).
* Matching domains with **common registrants** to discover new targets.
* Mapping **registrar patterns** across multiple domains owned by a company.

---

<img width="1144" height="418" alt="image" src="https://github.com/user-attachments/assets/408321c0-925a-48c7-b8a1-579b0236385b" />

##  Netcraft – Advanced Passive Reconnaissance Platform

###  What is Netcraft?

[**Netcraft**](https://www.netcraft.com/) is a comprehensive internet data and cybersecurity platform that provides a wide range of intelligence on websites and infrastructure. It’s commonly used by attackers and defenders for **passive reconnaissance**, **technology fingerprinting**, and **infrastructure mapping**.

---

###  What Can Netcraft Reveal?

| Feature                  | Description                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- |
| **Hosting History**      | Shows which companies have hosted the domain over time (useful to identify historical IPs or pre-CDN setup) |
| **Web Server Info**      | Detects technologies like Apache, Nginx, IIS, etc.                                                          |
| **SSL Certificates**     | Lists current and historical SSL certs, including issuing CA and validity periods                           |
| **DNS Records**          | Displays name servers, mail servers, and more                                                               |
| **Site Technologies**    | Identifies CMS (WordPress, Joomla), JS libraries, and more                                                  |
| **Neighboring Sites**    | Lists other domains hosted on the same IP or server                                                         |
| **Site Reputation**      | Flags phishing, fake stores, malicious behavior                                                             |
| **Redirection Chains**   | Shows HTTP/HTTPS redirect behavior                                                                          |
| **Uptime Monitoring**    | Shows response trends and server performance history                                                        |
| **OSINT for Subdomains** | Can sometimes reveal subdomains used in the past                                                            |

---

###  How Netcraft Helps in Web App Pentesting

* **Bypassing CDNs/WAFs**: If a site uses Cloudflare today, Netcraft may still show its **real IP address** from the past before protection was added.
* **Uncovering Hidden Infrastructure**: Netcraft may show **old subdomains**, **test environments**, or **internal panels** that are no longer indexed.
* **Correlating Sites**: If you’re assessing a company with multiple brands, Netcraft can show **which sites share hosting**, indicating shared infrastructure.
* **Detecting Tech Stack Changes**: If the server recently switched from Apache to Nginx, it may affect attack surface (e.g., `.htaccess` not supported in Nginx).

---

###  How to Use Netcraft

1. Go to: [https://sitereport.netcraft.com](https://sitereport.netcraft.com)
2. Enter the domain you want to analyze (e.g., `example.com`)
3. Browse through sections like:

   * Hosting History
   * Web Technologies
   * IP History
   * Risk Ratings
   * SSL Certificates
4. Use this information to pivot to other tools like:

   * `crt.sh` for SSL certs
   * `Shodan` for exposed services
   * `ViewDNS` for passive DNS

---

<img width="777" height="405" alt="image" src="https://github.com/user-attachments/assets/3e826b4e-c934-49ad-8e4b-24d899a6db71" />

##  Cloudflare – CDN and WAF Protection 

###  What is Cloudflare? 

**Cloudflare** is a globally distributed **Content Delivery Network (CDN)** and **Web Application Firewall (WAF)** platform. It sits **between clients and the origin server**, offering services like:

* Load balancing and caching
* DDoS protection
* IP masking (origin protection)
* TLS/SSL termination
* Rate limiting
* Bot and abuse protection

---

###  How Cloudflare Affects Recon 

When a website is behind Cloudflare:

| Effect                       | Description                                                                 |
| ---------------------------- | --------------------------------------------------------------------------- |
| Real IP Hidden               | All A/AAAA DNS records point to Cloudflare IPs (e.g., 104.21.x.x)           |
| DNS Obfuscation              | WHOIS & DNS data often point to Cloudflare infrastructure only              |
| SSL Proxies                  | SSL certs are issued by Cloudflare, not the origin                          |
| WAF Detection/Evasion        | Tools like Burp Suite may trigger bot detection, CAPTCHAs, or 403 responses |
| Rate Limiting & Blacklisting | Recon tools like `ffuf`, `dirb`, or scanners may be blocked or throttled    |

---

###  How to Detect Cloudflare

####  Indicators:

* WHOIS output shows nameservers like:

  ```text
  Name Server: MAXINE.NS.CLOUDFLARE.COM
  Name Server: JAKE.NS.CLOUDFLARE.COM
  ```
* DNS A records resolve to Cloudflare ranges (104.x.x.x, 172.x.x.x)
* HTTP response headers:

  ```http
  server: cloudflare
  cf-ray: 7ce2b1f2de01999e-FRA
  ```

---

###  How to Bypass or Work Around Cloudflare (Ethically and Legally)

>  These techniques should **only be used in authorized penetration tests**.

| Technique                             | Description                                                                      |
| ------------------------------------- | -------------------------------------------------------------------------------- |
| **Netcraft**                          | View historical IP data to find the origin server before Cloudflare was applied  |
| **crt.sh (Certificate Transparency)** | Inspect older SSL certificates that include internal hostnames                   |
| **Shodan / Censys / ZoomEye**         | Search for matching SSL certs, server banners, or HTTP titles                    |
| **DNS misconfigurations**             | Identify unprotected subdomains (e.g., dev.example.com)                          |
| **IP leakage via Email Servers**      | MX records may point to origin server IPs                                        |
| **Wayback Machine or Github**         | Old configuration files might leak real IP addresses                             |
| **Reverse CDN Enumeration**           | Using tools like `crimeflare`, `cloudfail`, or custom scripts to probe CDN leaks |

---

##  Summary 

| Tool           | Purpose                                                                           | Recon Type         |
| -------------- | --------------------------------------------------------------------------------- | ------------------ |
| **WHOIS**      | Identify domain owner, registrar, contact, DNS servers                            | Passive            |
| **Netcraft**   | Discover hosting history, old IPs, technologies, SSL certs, and subdomains        | Passive            |
| **Cloudflare** | Provides defense and masking; real IP and server info must be uncovered via OSINT | Defensive (Target) |

---
