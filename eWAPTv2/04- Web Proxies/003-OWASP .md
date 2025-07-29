<img src="https://github.com/user-attachments/assets/54c98374-9e1f-49d4-b956-1f22eee447ba" style="width: 100%; height: auto;" alt="image" />

**OWASP ZAP (Zed Attack Proxy)** is the world’s most popular open-source web application security scanner. It is developed in Java by the OWASP community and is widely used by security professionals, penetration testers, developers, and QA testers to find vulnerabilities in web applications.

ZAP acts as a **man-in-the-middle proxy**, intercepting and modifying traffic between the browser and the web server. It supports both **automated** and **manual testing** methods.

---

## Key Features of OWASP ZAP

* Intercepting Proxy: Capture and modify requests/responses between client and server.
* Automated Scanning: Active and Passive scanners to find vulnerabilities.
* Web Spider and AJAX Spider: Discover all reachable endpoints.
* Fuzzer: Send payloads to parameters for input validation testing.
* Context & Scope: Define which parts of the application to test.
* Scripting Engine: Add custom scripts for advanced use.
* Add-ons Marketplace: Enhance ZAP’s functionality with community-supported extensions.

---

## Installation

### On Kali Linux (Pre-installed)

```bash
zaproxy
```

### On Other Operating Systems

* Download from: [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/)
* Available as:

  * Cross-platform GUI
  * Docker container
  * Command-line daemon (headless)

---

## ZAP Interface Overview

### HUD (Heads Up Display)

ZAP HUD is a browser overlay that lets you interact with ZAP directly from the target website interface.

* Visualize alerts and request info inline.
* Highlight attack points directly on the page.
* Launch scanners, fuzzers, and more without switching to the ZAP GUI.

### Main Dashboard Sections:

* **Site Tree:** Shows the structure of all discovered content.
* **Request/Response Tabs:** View and edit raw HTTP traffic.
* **Alerts Tab:** Lists identified vulnerabilities.
* **Scripts Tab:** Manage and run scripts (e.g. active scan rules).
* **History Tab:** Shows all traffic ZAP has seen.

---

## Setting Up ZAP as a Proxy

1. Configure browser to use ZAP as an HTTP proxy:

   * Default: `127.0.0.1:8080`

2. Import ZAP’s Root CA Certificate to your browser (to intercept HTTPS traffic):

   * Tools → Options → Dynamic SSL Certificates → Save...
   * Import the certificate into browser settings (as a trusted CA).

---

## Spidering with OWASP ZAP

ZAP Spider is used to **crawl** the web application and discover all reachable pages and inputs.

### Types:

1. **Traditional Spider:** Parses static HTML and JavaScript to find URLs.
2. **AJAX Spider:** Uses browser automation to render JavaScript-heavy apps (e.g. React, Angular).

### How It Works:

* Starts from a list of URLs (called seeds).
* Visits each URL and extracts links.
* Adds new URLs to the queue and continues recursively.

### Use Case:

* Good for **initial site mapping**.
* Helps in identifying **hidden or unlinked endpoints** that directory brute-force tools might miss.

---

## Scanning

### Passive Scanning

* Happens in the background as traffic passes through ZAP.
* Does not modify the requests.
* Detects vulnerabilities like:

  * Missing security headers
  * Information disclosure (e.g. email addresses)

### Active Scanning

* Actively sends test payloads to detect exploitable vulnerabilities.
* Should **only** be used on authorized targets.
* Detects:

  * SQL Injection
  * XSS (Cross-Site Scripting)
  * Command Injection
  * Path Traversal

### Example: Running a Scan

1. Right-click on the target in the Site Tree.
2. Select: **Attack → Active Scan**.
3. Configure options (context, scanner rules, etc.).
4. Run and monitor alerts.

---

## Fuzzing

The Fuzzer in ZAP allows you to test input fields with a wide range of payloads to identify how the application handles unexpected or malicious input.

### How to Use:

1. Right-click a request → Fuzz.
2. Select the parameter to fuzz.
3. Choose or import a payload list (e.g., SQLi payloads).
4. Start fuzzing and monitor responses for anomalies.

### Use Cases:

* Input validation
* Buffer overflow
* Authorization testing

---

## Contexts & Scope

Contexts help define the application boundaries that ZAP should focus on.

### Features:

* Include/Exclude URLs.
* Define authentication (login requests, session handling).
* Set users and roles.

### Example:

* Define a login POST request.
* Add authentication tokens as context-based session management.
* Scan only in-scope URLs.

---

## Directory Enumeration with ZAP

While ZAP is not primarily a directory brute-forcer like **Dirb** or **Gobuster**, you can:

* Use the spider to discover hidden paths.
* Import wordlists through add-ons or use the Fuzzer for endpoint guessing.

### Example:

Use the Fuzzer to send a list of common directory names to a vulnerable endpoint and check for `200 OK` or `403 Forbidden` responses.

---

## Scripting and Automation

ZAP supports scripting in:

* JavaScript
* Python (Jython)
* Zest (ZAP's own format)

### Use Cases:

* Custom scan rules
* Automated login scripts
* Post-processing of alerts

### Example:

```javascript
function scanNode(sas, msg) {
  if (msg.getRequestHeader().getURI().toString().contains("test")) {
    sas.raiseAlert(1, 1, "Test Alert", "Test description", msg.getRequestHeader().getURI().toString(), "", "", "", "", "", msg);
  }
}
```

---

## Comparing OWASP ZAP vs Burp Suite

| Feature          | OWASP ZAP           | Burp Suite Pro     |
| ---------------- | ------------------- | ------------------ |
| Site Map         | Site Tree           | Site Map           |
| HTTP History     | HTTP History        | HTTP History       |
| Scope Definition | Context             | Target & Scope     |
| Proxy            | Intercepting Proxy  | Intercepting Proxy |
| Replay Requests  | Request Editor      | Repeater           |
| Fuzzing          | Fuzzer              | Intruder           |
| Spidering        | Spider, AJAX Spider | Spider (Pro)       |
| Active Scanning  | Active Scanner      | Scanner (Pro)      |
| Extensions       | Add-on Marketplace  | BApp Store         |

---

## Add-ons Marketplace

OWASP ZAP has a large collection of add-ons developed and maintained by the community.

### Examples:

* Retire.js Scanner (detects vulnerable JS libraries)
* SAML/JSON/XML support
* Docker scripts

Install via: **Manage Add-ons** under the Tools menu.

---

## Automation & CI/CD Integration

ZAP can run in headless mode for automation:

```bash
zap.sh -daemon -port 8080 -config api.disablekey=true
```

You can:

* Run scans via API.
* Use GitHub Actions with ZAP baseline scan.
* Integrate with Jenkins or GitLab CI.

---

## Best Practices

* Always test on **authorized targets**.
* Define clear context & authentication before scanning.
* Start with **passive scan** to understand the site.
* Use **fuzzing** carefully to avoid unintended actions.

---


 
* [Official ZAP Site](https://www.zaproxy.org/) 
* [ZAP GitHub Repository](https://github.com/zaproxy/zaproxy) 
* [ZAP Scripting Guide](https://www.zaproxy.org/docs/desktop/addons/script-console/) 
* [TryHackMe: OWASP ZAP Room](https://tryhackme.com/room/learnowaspzap) 
