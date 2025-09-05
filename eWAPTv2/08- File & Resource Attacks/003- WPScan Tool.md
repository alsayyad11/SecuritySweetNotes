
![a](https://github.com/user-attachments/assets/5df119b5-67a8-4df1-9a66-8a5de054e002)

## 1. What is WPScan?

**WPScan** is an **open-source WordPress security scanner**. It was created specifically to test WordPress websites for security issues.

* WordPress is the **most popular CMS (Content Management System)**, powering more than **40% of all websites worldwide**.
* Because it is so widely used, attackers constantly target it.
* WPScan automates the process of **finding weak points in WordPress websites**.

### WPScan Can Do:

* Detect the **WordPress core version** (and whether it’s vulnerable).
* Enumerate **plugins** and **themes** (and their known vulnerabilities).
* Find **usernames**.
* Check for **weak or common passwords** (brute force).
* Identify **sensitive files** or **misconfigurations**.

So, WPScan is a **specialized scanner**: instead of testing any random web app like `nikto` or `dirb`, it focuses only on **WordPress** and knows its structure deeply.

---

## 2. Why WPScan is Useful

WordPress is often insecure because of:

* **Outdated WordPress core** (old versions with public exploits).
* **Vulnerable plugins** (many plugins are created by small devs and not maintained).
* **Vulnerable themes** (themes often include insecure code).
* **Exposed usernames** (easier for brute-force attacks).
* **Weak passwords** (common issue in WordPress sites).

An attacker can chain these issues:

* Find a vulnerable plugin → upload a shell → get Remote Code Execution (RCE).
* Enumerate users → brute force weak passwords → login as admin.

WPScan makes finding these entry points much faster.

---

## 3. How WPScan Works

WPScan has three main parts:

1. **Fingerprints WordPress**

   * Detects version, themes, and plugins.
   * Example: `https://target.com/readme.html` often leaks version info.

2. **Checks Against WPVulnDB**

   * WPScan connects to the **WordPress Vulnerability Database** ([https://wpscan.com/](https://wpscan.com/)).
   * This database is updated daily with vulnerabilities in plugins, themes, and core.

3. **Tests for Weaknesses**

   * User enumeration.
   * Brute-force login attempts.
   * Misconfigurations (debug mode, directory listing).

---

## 4. Installation

### On Kali Linux (usually preinstalled)

```bash
sudo apt update
sudo apt install wpscan
```

### On Ubuntu / Debian

```bash
sudo apt install ruby-full
sudo gem install wpscan
```

### Using Docker (no need to install locally)

```bash
docker run -it --rm wpscanteam/wpscan --url https://target.com
```

---

## 5. WPScan API Token

* To get detailed vulnerability info, WPScan needs an **API token** from WPVulnDB.
* Free tokens allow \~50 requests/day.
* Register at [https://wpscan.com/register](https://wpscan.com/register).

Example:

```bash
wpscan --url https://target.com --api-token YOUR_TOKEN
```

---

## 6. WPScan Usage – Detailed Examples

### 6.1 Basic Site Scan

```bash
wpscan --url https://target.com
```

* Detects WordPress version.
* Identifies plugins, themes.
* Lists potential vulnerabilities.

**Example Output:**

```
[+] WordPress version 5.4.2 identified (Insecure, multiple vulnerabilities)
[+] Plugin found: contact-form-7  (Vulnerable to File Upload Exploit)
[+] Theme found: twentytwenty
```

---

### 6.2 Enumerating Users

```bash
wpscan --url https://target.com -e u
```

* `-e u` means **enumerate users**.
* WPScan tries methods like `/author/` pages, REST API leaks, etc.

**Example Output:**

```
[+] Identified User: admin
[+] Identified User: editor
```

---

### 6.3 Enumerating Plugins

```bash
wpscan --url https://target.com -e vp
```

* `vp` = vulnerable plugins.
* Checks WPVulnDB for known exploits.

Or enumerate **all plugins**:

```bash
wpscan --url https://target.com -e ap
```

---

### 6.4 Enumerating Themes

```bash
wpscan --url https://target.com -e vt
```

* Finds the active theme.
* Checks if it has known vulnerabilities.

---

### 6.5 Brute-Force Login

```bash
wpscan --url https://target.com -U users.txt -P passwords.txt
```

* `-U users.txt` = list of usernames.
* `-P passwords.txt` = list of passwords.
* WPScan will try every combination.

**Important:** Always have permission before brute forcing.

---

### 6.6 Aggressive Detection

By default, WPScan uses **passive detection** (noisy scanning can break sites).
To make it aggressive:

```bash
wpscan --url https://target.com --plugins-detection aggressive
```

---

### 6.7 Saving Results

```bash
wpscan --url https://target.com -o result.txt
```

Saves scan results to `result.txt`.

---

## 7. Real Attack Example with WPScan

1. **Scan target**

```bash
wpscan --url https://victim.com
```

Finds WordPress version 5.4.2 (outdated).

2. **Enumerate plugins**

```bash
wpscan --url https://victim.com -e vp
```

Finds `contact-form-7` plugin vulnerable to Arbitrary File Upload.

3. **Exploit vulnerability**
   Upload a malicious `.php` file disguised as an image.

4. **Execute payload**

```
https://victim.com/wp-content/uploads/shell.php?cmd=whoami
```

Output:

```
www-data
```

Now the attacker has **RCE (Remote Code Execution)**.

---

## 8. Limitations of WPScan

* **False positives/negatives**: Sometimes vulnerabilities are misdetected.
* **No exploitation**: WPScan only scans, it does not exploit automatically.
* **Needs API token** for full database access.
* **Can be noisy**: Aggressive scans may trigger security systems.

---

## 9. Defense Against WPScan

If you’re a WordPress admin:

1. **Update core, plugins, themes** regularly.
2. **Delete unused plugins/themes**.
3. **Disable user enumeration** (`/author/`).
4. **Limit login attempts** to stop brute force.
5. **Use strong passwords + 2FA**.
6. **Restrict access to sensitive files** (wp-config.php, debug.log).
7. Use a **Web Application Firewall (WAF)** like Cloudflare or ModSecurity.

---

## 10. WPScan vs Other Tools

| Tool                | Focus                 | Use Case                                       |
| ------------------- | --------------------- | ---------------------------------------------- |
| **WPScan**          | WordPress-specific    | Find WordPress core, plugin, theme, user vulns |
| **Nikto**           | General web scanner   | Detects common misconfigurations, headers      |
| **Dirb / Gobuster** | Directory brute-force | Find hidden files & directories                |
| **Nmap**            | Network scanner       | Find open ports, services                      |

WPScan is **specialized**, while others are **general-purpose**.

---

## 11. Checklist 

* [ ] Run passive scan (`wpscan --url target.com`).
* [ ] Enumerate users (`-e u`).
* [ ] Check vulnerable plugins (`-e vp`).
* [ ] Check themes (`-e vt`).
* [ ] Try brute force (`-U users.txt -P passwords.txt`).
* [ ] Verify findings manually in WPVulnDB.
* [ ] Look for upload paths and sensitive files.

