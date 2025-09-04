

## 1. What Is a Web Shell?

A **web shell** is a malicious script uploaded to a vulnerable web server that allows attackers to interact with the server through a web browser.

* It acts like a **remote terminal** inside the web environment.
* It gives attackers the ability to run arbitrary commands, manage files, or pivot deeper into the network.
* Common programming languages used: **PHP, ASP, JSP, Python, Perl** — basically, any language supported by the web server.

**Key point**: Unlike normal malware that requires remote desktop or SSH, a web shell works entirely through HTTP/S requests, making it easy to use in stealth attacks.

**Example (minimal PHP shell):**

```php
<?php system($_GET['cmd']); ?>
```

Visiting:

```
http://victim.com/shell.php?cmd=whoami
```

would return the username under which the web server process runs.

---

## 2. How Web Shells Are Planted

Attackers need a way to get their script onto the target server. Common methods include:

1. **File Upload Vulnerabilities**

   * Applications with weak validation let users upload `.php`, `.asp`, or `.jsp` files instead of images.
   * Example: Upload form only checks MIME type or extension but not content.

2. **Local File Inclusion (LFI) → Remote Code Execution**

   * Attackers exploit an LFI vulnerability and include a file they control, like an Apache log or image containing PHP code.

3. **Command Injection → File Write**

   * If attackers can run commands like:

     ```bash
     echo "<?php system(\$_GET['cmd']); ?>" > shell.php
     ```

     they effectively plant a web shell.

4. **Exploiting Vulnerable CMS/Plugins**

   * Outdated WordPress, Joomla, or Drupal plugins often allow shell upload.

---

## 3. Types of Web Shells

### 3.1 Simple Web Shells

* Minimal functionality.
* Just a line or two of code to run system commands.

**Example:**

```php
<?php echo shell_exec($_GET['c']); ?>
```

### 3.2 Semi-Interactive Shells

* Provide file browsing, command execution, and database access.
* Usually a few kilobytes of code.

### 3.3 Full-Featured GUI Web Shells

* Look like complete control panels with graphical dashboards.
* Allow:

  * File manager (upload/download/delete/edit)
  * SQL database manager
  * Network tools (port scanning, reverse shell creation)
  * Privilege escalation scripts
* Famous examples: **C99**, **R57**, **WSO**

### 3.4 Custom/Obfuscated Shells

* Hidden inside normal-looking code.
* Require a password or key to activate.
* Commands may be encoded in Base64 to avoid detection.

---

## 4. Capabilities of Web Shells

Once active, a web shell can provide:

* **System Command Execution**
  Run `whoami`, `ls`, `cat`, `netstat`, `uname -a` to fingerprint the system.

* **File System Access**
  Browse, read, modify, or delete files.

* **Database Access**
  Read `config.php` for MySQL credentials, then dump database contents.

* **Upload/Download of Malware**
  Plant ransomware, crypto miners, or backdoors.

* **Persistence**
  Add hidden users, cron jobs, or additional shells.

* **Pivoting**
  Use the web server as a staging point to attack internal systems.

**Example of Pivot**:
If a shell is planted on `web01.internal`, attackers may SSH or RDP into `db01.internal` using stolen credentials.

---

## 5. Example Attack Scenario

1. **Reconnaissance**

   * Attacker finds a vulnerable image upload feature.

2. **Upload Malicious File**

   * Instead of `photo.jpg`, attacker uploads `photo.php` containing:

     ```php
     <?php system($_GET['cmd']); ?>
     ```

3. **Access Web Shell**

   * They browse to:

     ```
     http://target.com/uploads/photo.php?cmd=ls
     ```

4. **Explore & Escalate**

   * List directories, read `/etc/passwd`, search for credentials.

5. **Persistence**

   * Upload a full GUI shell (like WSO).
   * Add a hidden admin user to the application.

6. **Lateral Movement**

   * Use stolen SSH keys or passwords to access deeper systems.

---

## 6. How Web Shells Stay Hidden

Attackers try to avoid detection by:

* **File Name Tricks**: Rename shell to `about.php`, `login.php`, `favicon.ico.php`.
* **Steganography**: Hide PHP code inside image metadata.
* **Encoding**: Use Base64, ROT13, or hex for commands.
* **Conditional Activation**: Shell only runs if a special password is passed.

**Example of hidden shell:**

```php
<?php
if($_GET['key'] == 'secret123'){
    system($_GET['cmd']);
}
?>
```

---

## 7. Detection Techniques

1. **File Integrity Monitoring**

   * Alert if new `.php` or `.asp` files appear unexpectedly.

2. **Log Analysis**

   * Look for suspicious queries like `?cmd=` or `?exec=`.

3. **Threat Hunting**

   * Search uploads folder for abnormal files.
   * Scan for known shell signatures (c99, r57).

4. **Web Application Firewalls (WAF)**

   * Block requests containing suspicious parameters.

5. **YARA/AV Signatures**

   * Many security products detect known shell code.

---

## 8. Prevention Strategies

* **Secure File Uploads**

  * Only allow safe extensions (`.jpg`, `.png`).
  * Verify MIME type and file content.
  * Store uploads **outside the web root**.

* **Input Validation & Sanitization**

  * Never directly execute or interpret user input.

* **Least Privilege**

  * Web server should not run as `root`.
  * Limit permissions on directories.

* **Patch & Update**

  * Keep CMS, frameworks, and plugins updated.

* **Deploy WAF**

  * Block common exploit patterns.

---

## 9. Real-World Cases

* **Equifax Breach (2017)**: Attackers uploaded malicious web shells after exploiting Apache Struts.
* **APT Groups**: Nation-state attackers deploy custom web shells for persistence on high-value targets.
* **WordPress Exploits**: Thousands of sites compromised yearly via vulnerable plugins and shells planted in `wp-content/uploads/`.

---

* A **web shell** is a remote backdoor planted via a web vulnerability.
* It enables attackers to control a server over HTTP.
* Can be simple one-liners or complex full GUIs.
* Used for reconnaissance, persistence, privilege escalation, and lateral movement.
* Detection requires monitoring, scanning, and anomaly detection.
* Prevention requires secure coding, server hardening, WAFs, and strict file handling.
