
## 1. Wappalyzer – Web Technology Profiler

### What Is It?

Wappalyzer identifies technologies used by websites such as:

* **Web servers:** Apache, Nginx, IIS
* **Languages/Frameworks:** PHP, Python, Ruby on Rails, Node.js
* **CMS:** WordPress, Joomla, Drupal
* **JS Libraries:** jQuery, React, Angular
* **Security Tools:** Cloudflare, HSTS
* **CDNs, Analytics, Tracking Tools**

### Use Cases

* Find vulnerable tech (e.g., outdated WordPress or Magento)
* Know if a WAF or CDN is active (like Cloudflare)
* Understand the web app structure

### How To Use

* **Online:** [https://www.wappalyzer.com](https://www.wappalyzer.com)
* **Chrome Extension:** [Wappalyzer for Chrome](https://chrome.google.com/webstore/detail/wappalyzer-technology-profi/gppongmhjkpfnbhagpmjfkannfbllamg)
* **Firefox Add-on:** [Wappalyzer for Firefox](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/)
* **CLI:**

  ```bash
  npm install -g wappalyzer
  wappalyzer https://example.com
  ```

---

## 2. BuiltWith – Deep Tech Profiling

### What Is It?

[BuiltWith](https://builtwith.com) offers a comprehensive view of all tech used on a website.

### Features

* Hosting providers & DNS records
* SSL/TLS Cert authorities
* Web servers & programming languages
* Advertising/analytics trackers
* Technology **history tracking**

### Use Cases

* Track tech stack changes over time
* Discover common DNS/CDN across multiple assets
* Identify similar websites (hosted on same infrastructure)

---

## 3. Cloudflare – CDN & WAF

### What Is Cloudflare?

Cloudflare is a reverse proxy service that provides:

* Web Application Firewall (WAF)
* Content Delivery Network (CDN)
* Rate limiting, bot protection, and caching
* IP masking (hides origin IP)
* DDoS protection

### Why It Matters in Recon?

* You often interact with **Cloudflare servers**, not the real origin.
* Cloudflare **obfuscates true IPs**, making it hard to reach the real backend.
* Fingerprinting Cloudflare is easy: look for headers like:

  ```
  server: cloudflare
  cf-ray: <unique ID>
  ```

### Bypassing Cloudflare

* Use historical tools to find **origin IP**:

  * Netcraft
  * CrimeFlare archive
  * Censys/Shodan historical scans
  * DNS history (e.g., [SecurityTrails](https://securitytrails.com))
* Check misconfigured subdomains pointing directly to origin IP
* Find other assets (e.g., dev/test domains) not behind Cloudflare

---

## 4. WAF Detection

### What Is a WAF?

A Web Application Firewall filters HTTP requests and blocks attacks like:

* SQLi
* XSS
* LFI/RFI
* Command Injection
* Brute-force

### Common WAF Providers

| Vendor     | Notes                           |
| ---------- | ------------------------------- |
| Cloudflare | Popular, free-tier CDN/WAF      |
| AWS WAF    | Part of AWS infrastructure      |
| Akamai     | Often used by large enterprises |
| Imperva    | SaaS-based WAF provider         |
| F5 BIG-IP  | Hardware-based enterprise WAF   |
| Sucuri     | Popular with WordPress sites    |

---

### 4.1 WAFW00F – WAF Fingerprinting Tool

* GitHub: [https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f)
* Detects 50+ WAFs
* Supports custom request behavior

**Installation:**

```bash
pip install wafw00f
```

**Usage:**

```bash
wafw00f https://target.com
```

**Example Output:**

```
Is behind a WAF? Yes
WAF Detected: Cloudflare
```

---

### 4.2 Manual WAF Detection Techniques

| Method             | Indicators                                                 |
| ------------------ | ---------------------------------------------------------- |
| Status Codes       | `403`, `406`, `503` when sending attack payloads           |
| Response Headers   | `server: cloudflare`, `x-sucuri-id`, `x-akamai-request-id` |
| CAPTCHA or JS Test | Browser challenge on first visit                           |
| Rate Limiting      | 429 Too Many Requests                                      |
| Redirect Behavior  | Redirects through a CDN or proxy                           |

**Test Example:**

```bash
curl -I "https://target.com/?q=<script>alert(1)</script>"
```

---

## 5. Netcraft – Passive Recon Platform

* Website: [https://sitereport.netcraft.com](https://sitereport.netcraft.com)
* View:

  * Hosting history
  * SSL certificate details
  * Site technology stack
  * Site redirection chains
  * Past IPs (pre-WAF)

**Use Case:**

* Find **pre-Cloudflare origin IP**
* Detect legacy or vulnerable infra
* Link similar assets

---

## 6. OSINT & DNS-Based Recon Tools

| Tool           | Purpose                               | URL                                                      |
| -------------- | ------------------------------------- | -------------------------------------------------------- |
| crt.sh         | SSL cert transparency logs            | [https://crt.sh](https://crt.sh)                         |
| SecurityTrails | Passive DNS, subdomains, IP history   | [https://securitytrails.com](https://securitytrails.com) |
| Shodan         | Search for open services & ports      | [https://shodan.io](https://shodan.io)                   |
| Censys         | Infrastructure enumeration            | [https://censys.io](https://censys.io)                   |
| ViewDNS        | Multiple DNS/OSINT tools in one place | [https://viewdns.info](https://viewdns.info)             |

---

## 7. Summary 

| Tool             | Purpose                                       |
| ---------------- | --------------------------------------------- |
| Wappalyzer       | Fast technology fingerprinting (client-side)  |
| BuiltWith        | Full infrastructure and 3rd-party analysis    |
| Cloudflare       | Common CDN/WAF – understand its behavior      |
| WAFW00F          | Fingerprint WAF vendors automatically         |
| Manual Detection | Confirm WAF presence through crafted payloads |
| Netcraft         | Historical IPs, hosting, SSL, tech data       |
| SecurityTrails   | Passive DNS, subdomains, IP ownership         |
| crt.sh           | Discover domains via SSL certs                |

---

