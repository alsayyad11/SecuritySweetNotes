<div align="center">
  <img src="https://github.com/user-attachments/assets/7f07f8c2-f7bc-426a-a0c7-05ee2a6cc1d3" alt="image">
</div>

## 1. `robots.txt` – Directives for Search Engine Crawlers

### What is `robots.txt`?

`robots.txt` is a plain text file located at the root of a website (`example.com/robots.txt`) that tells **search engine crawlers** which pages or directories they are allowed or disallowed from indexing.

While it's intended to protect sensitive or irrelevant pages from being indexed, attackers often review it to discover **hidden directories or functionalities** not directly linked on the website.

### Structure Example:

```
User-agent: *
Disallow: /admin/
Disallow: /backup/
Allow: /public/
```

This tells all crawlers (`User-agent: *`) not to index the `/admin/` and `/backup/` directories.

### Why Is It Useful in Recon?

* It may expose **restricted areas**, **staging panels**, **API endpoints**, or **development files**.
* These paths might not be visible via the front-end, but are accessible if manually visited.

### Real Example:

Visit:

```
https://www.linkedin.com/robots.txt
```

You’ll see entries like:

```
Disallow: /login
Disallow: /m/login
Disallow: /signup
```

These entries may reveal important endpoints worth noting.

---

<img width="825" height="382" alt="image" src="https://github.com/user-attachments/assets/66715812-42e2-4247-b19d-3929dc51cd69" />


## 2. `sitemap.xml` – Structured List of All Website Pages

### What is `sitemap.xml`?

`sitemap.xml` is an XML-formatted file submitted to search engines that lists **all URLs** a website wants indexed. It often includes **page update timestamps**, **priority**, and **change frequency**.

It’s usually located at:

```
https://example.com/sitemap.xml
```

### Why Is It Useful in Recon?

* It provides a **complete list of URLs**, including pages not linked on the homepage.
* You might discover **forgotten login pages**, **testing environments**, **old blogs**, or **restricted paths**.

### Example:

Visit:

```
https://www.w3schools.com/sitemap.xml
```

Or:

```
https://www.mozilla.org/sitemap.xml
```

These will show you structured lists like:

```xml
<url>
  <loc>https://www.mozilla.org/en-US/firefox/new/</loc>
  <lastmod>2024-05-20</lastmod>
  <changefreq>weekly</changefreq>
  <priority>1.0</priority>
</url>
```

---

<img width="672" height="418" alt="image" src="https://github.com/user-attachments/assets/087879d0-25d5-4d0d-8e01-216be07f22e2" />


## 3. Google Dorks – Advanced Search Operators for Recon

### What are Google Dorks?

**Google Dorking** is a technique that uses **advanced Google search operators** to extract sensitive information exposed online. It’s extremely useful in **passive reconnaissance**.

### Why It Matters?

Google indexes tons of data by default. Many organizations mistakenly expose:

* Login portals
* Database dumps
* Admin panels
* Backup files
* Error messages
* Configuration files
* Internal documentation

### Key Operators:

| Operator    | Purpose                                |
| ----------- | -------------------------------------- |
| `site:`     | Limit results to a specific domain     |
| `inurl:`    | Search for keywords in the URL         |
| `intitle:`  | Search for keywords in the page title  |
| `filetype:` | Look for specific file extensions      |
| `ext:`      | Same as `filetype:`                    |
| `cache:`    | View Google's cached version of a page |
| `intext:`   | Search for keywords in the body text   |

### Practical Examples:

* Find login pages:

  ```
  inurl:login site:example.com
  ```

* Find exposed `.env` files:

  ```
  site:example.com ext:env
  ```

* Discover open directories:

  ```
  intitle:"index of" "parent directory"
  ```

* Look for exposed SQL backups:

  ```
  filetype:sql "database dump"
  ```

* Identify public documents:

  ```
  site:gov.in filetype:pdf budget
  ```

---

<img width="802" height="392" alt="image" src="https://github.com/user-attachments/assets/faa28718-eeeb-4b1a-a1cc-57b8c3ece628" />

## 4. Google Hacking Database (GHDB)

### What is GHDB?

The **Google Hacking Database** is a public repository of **prebuilt Google Dork queries**, maintained by the **Exploit Database (Offensive Security)**. It contains categorized and curated queries that can reveal:

* Login panels
* Devices connected to the internet (e.g., webcams, printers)
* Exposed passwords or credentials
* Vulnerable software
* Directory listings
* Configuration files
* Financial records

### Use Cases:

* Quickly find vulnerable or exposed systems
* Discover sensitive data exposed accidentally
* Combine queries with a specific target

### Access GHDB:

* Official site:
  [https://www.exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)

* Categories include:

  * Files containing passwords
  * Login pages
  * Vulnerable servers
  * Online devices
  * SQL errors
  * Directory listings

### Example from GHDB:

```text
intitle:"Index of /" "backup.zip"
```

Or:

```text
filetype:log inurl:"/logs/" site:example.com
```

These examples may help find backup or log files accidentally left on a public server.

---

<div align="center">
  <img src="https://github.com/user-attachments/assets/6e6aafd2-27fe-4f22-b8ce-ccce09675652" alt="image">
</div>

## 5. Exploit Database (Exploit-DB)

### What is Exploit-DB?

**Exploit-DB** is a **community-maintained archive** of **exploits, proof-of-concept code, Google Dorks, and vulnerable software documentation**.

It’s operated by Offensive Security (the creators of Kali Linux), and it’s widely used by red-teamers, bug bounty hunters, and penetration testers.

### Why It’s Important:

* Check if a known exploit exists for the **software, CMS, or plugin** used by your target.
* Learn how vulnerabilities are exploited in real-world scenarios.
* Use Dorks from Exploit-DB to find exposed vulnerable systems.

### How to Use:

* Visit:
  [https://www.exploit-db.com](https://www.exploit-db.com)

* Search by:

  * Software version (e.g., `WordPress 5.6`)
  * Exploit type (e.g., `Remote Code Execution`)
  * CVE ID (e.g., `CVE-2024-12345`)

### Real Example:

Searching for:

```
apache struts rce
```

You may find exploits like:

* `Apache Struts 2 REST Plugin - Remote Code Execution (CVE-2017-9805)`

Each exploit page contains:

* Description
* Proof of Concept (code)
* Author
* References

---

