
## 1. Overview

**HTTrack** is an **open-source website copier** or **offline browser tool** that allows you to **download websites to your local machine** while maintaining the original structure of pages, links, scripts, images, and other resources.

In web application penetration testing (pentesting), HTTrack is primarily used during **reconnaissance** to:

* Analyze the **structure of a web application** offline.
* Examine **HTML, CSS, and JavaScript** for potential vulnerabilities.
* Identify **hidden files and directories** that are not directly linked.
* Prepare for **manual testing or automated scanning** without stressing the live server.

It is important to note that **HTTrack is not an exploit tool**; it is used for gathering and organizing information safely.

---

## 2. Key Features

1. **Website Mirroring:** HTTrack can mirror entire websites or a subset of them.
2. **Preserves Structure:** Maintains the directory hierarchy, ensuring offline browsing mirrors the live website.
3. **Link Conversion:** Converts absolute and relative links to work offline.
4. **File Filtering:** Allows inclusion/exclusion of specific files, directories, or extensions.
5. **Resume Capability:** Downloads can be paused and resumed without losing progress.
6. **Supports Multiple Protocols:** Works with HTTP and HTTPS sites, including those with SSL/TLS certificates.
7. **Cross-Platform:** Available on **Linux, Windows, and macOS**, with both command-line and GUI options.
8. **Flexible Input:** Can use URLs, list of URLs, or outputs from other reconnaissance tools like Nmap.

---

## 3. How HTTrack Works

HTTrack works by:

1. **Starting from a target URL**.
2. **Recursively following internal links** within the website.
3. **Downloading resources** such as HTML pages, CSS, JavaScript files, and images.
4. **Adjusting links** to function offline while maintaining the website’s structure.
5. **Creating a local copy** that can be browsed offline for analysis and testing.

---

## 4. Installation

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install httrack
```

### Windows

1. Download **WinHTTrack** from [httrack.com](https://www.httrack.com/page/2/en/index.html).
2. Run the installer and launch the GUI version.

### macOS

```bash
brew install httrack
```

---

## 5. Basic Usage

### 5.1 Mirror a Website

```bash
httrack http://example.com -O ~/websites/example
```

* `-O ~/websites/example` specifies the local output directory.

### 5.2 Limit Recursion Depth

```bash
httrack http://example.com -O ~/websites/example -r2
```

* `-r2` sets a recursion depth of 2, limiting how deep links are followed.

### 5.3 Include Only Specific File Types

```bash
httrack http://example.com -O ~/websites/example "+*.php" "+*.html" "-*"
```

* `+*.php` and `+*.html` include only PHP and HTML files.
* `-*` excludes all other files.

### 5.4 Use a Proxy for Download

```bash
httrack http://example.com -O ~/websites/example -x --proxy 127.0.0.1:8080
```

* Useful for routing through Burp Suite or OWASP ZAP for offline analysis.

### 5.5 Resume Interrupted Downloads

```bash
httrack --continue
```

* Resumes a previously paused or interrupted download session.

---

## 6. Advanced Options

| Option               | Description                                               |
| -------------------- | --------------------------------------------------------- |
| `--mirror`           | Mirror the site recursively                               |
| `--depth=NUMBER`     | Set recursion depth for internal links                    |
| `--ext-depth=NUMBER` | Set recursion depth for external links                    |
| `--robots=0`         | Ignore robots.txt restrictions (use ethically)            |
| `--filters`          | Include/exclude specific URLs, directories, or file types |
| `--keep-alive`       | Maintain HTTP connections to speed up downloads           |
| `--update`           | Update an existing mirrored site                          |
| `--quiet`            | Suppress console output                                   |

---

## 7. Integration in Pentesting Workflow

HTTrack is typically used during the **information gathering / reconnaissance phase**:

1. **Subdomain Discovery:** Find subdomains with tools like **Amass** or **Sublist3r**.
2. **Live Host Detection:** Confirm active domains using **httprobe** or **Nmap**.
3. **Website Mirroring:** Download the web application locally with HTTrack.
4. **Offline Analysis:** Review:

   * Hidden admin panels
   * Backup files (`config.php`, `backup.zip`)
   * JavaScript for API endpoints, tokens, or sensitive logic
5. **Preparation for Scanning:** Feed the offline copy into tools like **OWASP ZAP** or **Burp Suite** for safe automated scanning.

**Benefits of Using HTTrack in Pentesting:**

* Reduces traffic to the live server.
* Avoids triggering alerts on production systems.
* Allows safe analysis of hidden endpoints and sensitive resources.
* Provides full offline site structure for organized testing.

---

## 8. Limitations

1. **Dynamic Content:** Single-page apps (React, Angular, Vue) may not fully mirror.
2. **Rate-Limiting / WAF:** Aggressive downloads may trigger WAF/IDS alerts.
3. **Server-Side Logic:** HTTrack cannot access server-side scripts, databases, or dynamic responses.
4. **External Links:** May unintentionally download other domains if not limited.
5. **Legal / Ethical Constraints:** Always obtain **written authorization** before downloading a site.

---

## 9. Practical Example

**Scenario:** You are tasked with safely analyzing `http://testsite.local` before pentesting.

**Step 1: Mirror the Website**

```bash
httrack http://testsite.local -O ~/pentest/testsite -r2
```

* Downloads all pages up to 2 link levels deep.

**Step 2: Offline Analysis**

* Open `~/pentest/testsite/index.html` in a browser.
* Inspect:

  * Login pages and admin portals
  * Hidden files and directories (`backup.zip`, `config.php`)
  * JavaScript for API endpoints, tokens, or sensitive logic

**Step 3: Feed into Security Tools**

```bash
zap.sh -dir ~/pentest/testsite
```

* Scan the mirrored site offline with **OWASP ZAP** for security flaws.

**Outcome:** You now have a **fully offline copy** of the site, ready for analysis and testing without impacting the live server.

---

## 10. Summary

HTTrack is a **powerful reconnaissance tool** that allows pentesters and bug bounty hunters to:

* **Safely explore a website offline**
* **Identify hidden resources and sensitive files**
* **Prepare structured testing and scanning workflows**

It is a **foundational tool** in the **pre-engagement / reconnaissance phase** of web application penetration testing.

