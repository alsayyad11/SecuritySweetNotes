
![a](https://github.com/user-attachments/assets/23a866df-c391-4c20-92ba-2d95007453b2)

## 1. What is Local File Inclusion (LFI)?

**Local File Inclusion (LFI)** is a type of **web application vulnerability** that occurs when an application allows an attacker to include and read **local files on the server** via the web browser.

* File inclusion is a normal practice in web development: developers dynamically include scripts, templates, or configuration files to build modular web pages.
* **Vulnerable behavior**: The application uses **user-supplied input** to decide which file to include **without proper validation**, allowing attackers to include files they shouldn’t have access to.

**Example:**
A PHP application includes a page based on the `page` parameter:

```php
<?php
$page = $_GET['page'];
include("pages/" . $page);
?>
```

* Safe input: `page=home.php` → includes `pages/home.php`.
* Malicious input: `page=../../../../etc/passwd` → includes system file `/etc/passwd`.

---

## 2. Causes of LFI

LFI vulnerabilities typically arise from **poor input validation** or lack of proper security mechanisms:

1. **File Inclusion Functions Misuse**

   * Functions like `include()`, `require()`, `file_get_contents()`, or `readfile()` that directly accept user input.
   * Example: `include($_GET['file']);`

2. **HTTP Parameters**

   * Query parameters in URLs or form fields that control file paths.
   * Example: `http://example.com/?template=header.php`

3. **Cookies**

   * If cookies are used to determine file inclusion.
   * Example: `$_COOKIE['theme']` used to include theme files.

4. **Session Variables**

   * If session data can be manipulated to control file inclusion.
   * Example: `include($_SESSION['page']);`

---

## 3. Exploitation of LFI

### 3.1 Reading Sensitive Files

* LFI allows an attacker to **read files they should not access**.
* Example payloads:

  * Linux: `../../../../etc/passwd`
  * Windows: `..\..\..\Windows\win.ini`

### 3.2 Directory Traversal

* LFI often **requires directory traversal sequences** (`../`) to move outside the intended folder.
* Example:

```
page=../../../../var/www/html/config.php
```

### 3.3 Log File Injection + LFI → Remote Code Execution

* Some applications log HTTP requests. Attackers can inject PHP code into logs and then include them via LFI.

**Steps:**

1. Inject PHP code into access log:

```
GET /<?php system($_GET['cmd']); ?> HTTP/1.1
```

2. Include the log file via LFI:

```
page=../../../../var/log/apache2/access.log
```

3. Access it in the browser:

```
http://target.com/?page=../../../../var/log/apache2/access.log&cmd=whoami
```

* Result: Remote code execution on the server.

### 3.4 Null Byte Injection (Legacy PHP)

* Older PHP versions terminated strings at a null byte (`%00`).
* Example:

```
page=../../../../etc/passwd%00.php
```

* Server reads `/etc/passwd` but thinks it ends with `.php`.

---

## 4. Impact of LFI

1. **Information Disclosure**

   * Read sensitive files: system configs, application credentials, user data.

2. **Remote Code Execution (RCE)**

   * When combined with log injection or file upload, LFI can lead to **full server compromise**.

3. **Directory Traversal**

   * LFI may involve directory traversal sequences, exposing unintended directories.

4. **Data Leakage**

   * Database credentials, API keys, passwords, or source code may be exposed.

5. **Chaining with Other Attacks**

   * LFI is often a stepping stone for:

     * File upload exploitation
     * Log poisoning → RCE
     * Sensitive configuration access

---

## 5. LFI vs Directory Traversal

| Feature               | Local File Inclusion (LFI)                                          | Directory Traversal (Path Traversal)                                              |
| --------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Primary Objective** | Include and display file contents via the web application           | Navigate the filesystem to access files or directories outside the intended scope |
| **Attack Method**     | Exploit file inclusion functions (include/require) using user input | Manipulate relative or absolute paths (`../`) to traverse directories             |
| **Scope**             | Focused on including files; may or may not use traversal sequences  | Broader; aims to read/modify/delete files, possibly leading to LFI                |
| **Impact**            | Information disclosure, RCE                                         | Information disclosure, system compromise, directory access                       |

**Summary:**

* LFI is a **specific type of vulnerability** focused on including files.
* Directory Traversal is **broader** and often a technique used within LFI attacks.

---

## 6. Real-World Example

Suppose a web application has this feature:

```
http://example.com/?page=home.php
```

Vulnerable code:

```php
<?php
include($_GET['page']);
?>
```

* Safe input: `home.php` → displays home page.
* Exploit input: `../../../../etc/passwd` → attacker reads Linux user accounts.
* Encoded payload (to bypass filters): `%2e%2e%2f%2e%2e%2fetc/passwd`

**Impact:**

* Discloses sensitive files.
* Can be chained for RCE via log poisoning.

---

## 7. Defense & Mitigation

1. **Validate Input**

   * Only allow filenames from a whitelist of known-safe files.
   * Avoid directly using user input in `include()`, `require()`, etc.

2. **Use Absolute Paths & realpath()**

   ```php
   $file = realpath("pages/" . $_GET['page']);
   if(strpos($file, "/var/www/html/pages/") === 0){
       include($file);
   } else {
       die("Access denied");
   }
   ```

3. **Disable Dangerous Functions**

   * `include`, `require` with user input should be avoided or sandboxed.

4. **Server Hardening**

   * Run web server with **least privileges**.
   * Sensitive files should be **outside the web root**.

5. **Web Application Firewall (WAF)**

   * Detect and block traversal sequences like `../`.

---

## 8. Summary 

| Aspect             | Details                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------ |
| Vulnerability Name | Local File Inclusion (LFI)                                                                 |
| Cause              | Unsanitized user input in file inclusion functions                                         |
| Exploitation       | Include files using `include()`, `require()`, directory traversal sequences, log poisoning |
| Impact             | Information disclosure, RCE, directory traversal, data leakage                             |
| Common Targets     | `/etc/passwd`, `/etc/shadow`, `wp-config.php`, log files, configuration files              |
| Prevention         | Whitelist files, sanitize input, use `realpath()`, server hardening, WAF                   |

