
## 1. Crawling

### What Is Crawling?

**Crawling** is the process of **navigating through a web application** by automatically following links, submitting forms, and optionally logging in (if possible) with the goal of **mapping out the application structure** and cataloging its public-facing components.

It helps uncover:

* All reachable pages
* Input fields
* Public resources (images, scripts, etc.)
* Navigation logic of the application

### Characteristics

* **Typically passive** — since it only touches publicly accessible paths
* Useful for **creating a site map** for further exploration or attack
* Common step in **recon**, **automated scanning**, and **manual mapping**

### Tools and Examples

#### ✅ Burp Suite (Passive Crawler)

* When browsing a site through Burp’s proxy, the crawler passively indexes every visited page and link.
* You can view this under `Target` → `Site map`.

#### ✅ Other Crawling Tools

| Tool       | Purpose                          |
| ---------- | -------------------------------- |
| GoSpider   | Fast recursive crawler in Go     |
| Dirsearch  | Brute-forces directories/files   |
| FFUF       | Wordlist-based content discovery |
| Burp Suite | Integrated passive crawler       |

#### Example:

```bash
gospider -s https://example.com -o output/
```

---

## 2. Spidering

### What Is Spidering?

**Spidering** is a more **aggressive and recursive method** of discovering content on a web application. It starts with a set of **seed URLs**, follows all hyperlinks found within them, and recursively continues to visit newly discovered pages.

### Key Features

* Often considered an **active** information-gathering technique
* Can discover **deeply nested URLs** and **unlinked internal pages**
* Used to **map** web apps comprehensively
* May **trigger security defenses or WAFs** due to volume and behavior

### Use Case:

* Automatically discover:

  * URLs
  * Parameters
  * Forms
  * JavaScript-generated paths

### Tools:

#### ✅ OWASP ZAP Spider

* Visit `URL to Spider`
* ZAP follows links and maps resources
* Also integrates with its active scanner

#### ✅ Other Tools

| Tool           | Description                        |
| -------------- | ---------------------------------- |
| Hakrawler      | Spider that understands JS         |
| LinkFinder     | Discovers URLs in JavaScript files |
| Burp Suite Pro | Has enhanced crawling + JS support |

#### Example (ZAP CLI):

```bash
zap-cli spider https://target.com
```

---

## 3. Web Server Fingerprinting

### What Is It?

**Web server fingerprinting** is the process of identifying the **type**, **version**, and possibly the **OS or configuration** of the web server running a website.

This helps attackers:

* Match known vulnerabilities to specific server versions
* Understand behavior (e.g., .htaccess only on Apache)
* Spot outdated, misconfigured, or uncommon technologies

### How It’s Done

#### 1. Inspect HTTP Response Headers:

```bash
curl -I https://example.com
```

Look for:

```http
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
```

#### 2. Use Fingerprinting Tools

| Tool         | Function                                        |
| ------------ | ----------------------------------------------- |
| WhatWeb      | Detects server, CMS, frameworks                 |
| httpx        | Probes and fingerprint web servers efficiently  |
| httprint     | Uses response signatures to detect server types |
| Netcraft     | Online tool for tech stack and host info        |
| Nmap (`-sV`) | Detects services and versions on open ports     |

#### Example with WhatWeb:

```bash
whatweb https://target.com
```

---


