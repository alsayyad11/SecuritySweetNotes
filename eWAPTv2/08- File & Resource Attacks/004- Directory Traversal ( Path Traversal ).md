
![a](https://github.com/user-attachments/assets/9ddb96f7-9a2d-48d0-8470-e403246051d5)

## 1. What is Directory Traversal?

**Directory Traversal**, also called **Path Traversal** or **Directory Climbing**, is a **web application vulnerability** that allows attackers to access files or directories that are **outside the intended directory structure**.

* Web applications often store user data in specific directories (e.g., `/uploads` or `/user_data`).
* A Directory Traversal vulnerability occurs when the app **fails to properly validate user input** and allows attackers to manipulate paths.
* Attackers can move “up” the directory hierarchy and access **sensitive system or application files**.

**Example:**

A file download URL:

```
http://example.com/download?file=user123.txt
```

* Intended behavior: only allows files in `/uploads`.
* Vulnerable behavior: attacker requests:

```
http://example.com/download?file=../../../../etc/passwd
```

* Result: server returns `/etc/passwd`, a critical system file on Linux containing user account info.

---

## 2. Why Directory Traversal Happens

Directory Traversal vulnerabilities typically arise from **improper handling of user input**, especially when the application uses the input to access **file or directory paths**.

Common causes:

1. **Direct concatenation of user input into file paths** without validation.

   ```php
   $file = $_GET['file'];
   $path = "/var/www/uploads/" . $file;
   readfile($path);
   ```

   * If `$file` contains `../../etc/passwd`, the server will read a sensitive file.

2. **Insufficient sanitization or filtering**

   * Applications may try to block `../` but fail to account for encodings like `%2e%2e%2f` or variations like `..//`.

3. **Trusting client input**

   * Sometimes the app assumes filenames provided by the user are safe, e.g., filenames in form submissions, URL parameters, or JSON payloads.

---

## 3. Exploitation Techniques

Attackers use **input manipulation** to traverse directories:

### 3.1 Traversing the Directory Structure

* `../` in Linux/Unix systems → move **one directory up**.
* `..\` in Windows systems → move **one directory up**.
* URL-encoded equivalents:

  * `%2e%2e%2f` → `../`
  * `%2e%2e%5c` → `..\`

**Example:**
Target URL:

```
http://example.com/download?file=user123.txt
```

Attack payload:

```
file=../../../../etc/passwd
```

This moves up several directories (`../../../../`) until reaching the root (`/`) and accesses `/etc/passwd`.

---

### 3.2 URL-Encoding Bypass

Some applications block `../` directly. Attackers can encode it:

```
file=%2e%2e%2f%2e%2e%2fetc/passwd
```

* Server decodes the input and allows traversal.

---

### 3.3 Double-Encoding

Even encoded payloads may be blocked, so attackers can **double encode**:

```
file=%252e%252e%252fetc/passwd
```

* First decoding: `%25` → `%`
* Second decoding: `%2e%2e%2f` → `../`
* Traversal succeeds.

---

### 3.4 Directory Traversal with Null Byte (Legacy Systems)

In older PHP applications (`<5.3.4`), null bytes (`%00`) could terminate strings, bypassing filters:

```
file=../../../../etc/passwd%00.txt
```

* Application thinks the file ends with `.txt`, but the server reads `/etc/passwd`.

---

### 3.5 Accessing Application-Specific Files

Attackers often aim for **files that contain sensitive application data**:

| Target File                   | Purpose                                  |
| ----------------------------- | ---------------------------------------- |
| `/etc/passwd`                 | Linux user accounts                      |
| `/etc/shadow`                 | Password hashes                          |
| `/var/www/html/wp-config.php` | WordPress DB credentials                 |
| `/var/log/apache2/access.log` | Server logs (may contain sensitive info) |
| `C:\Windows\win.ini`          | Windows configuration                    |

---

### 3.6 Chain Attacks

Directory Traversal is often combined with other attacks:

1. **Local File Inclusion (LFI)** – include arbitrary files to execute code.
2. **Remote Code Execution (RCE)** – reading log files with injected PHP code.
3. **Configuration leakage** – reading files containing DB passwords to compromise the database.

**Example:**

* Attacker injects PHP code into Apache log:

```
GET /<?php system($_GET['cmd']); ?> HTTP/1.1
```

* Then traverses to `/var/log/apache2/access.log` and includes it using LFI.
* Result: RCE on the server.

---

## 4. Real-World Example

**Scenario:** File download feature:

```
http://example.com/download?file=invoice.pdf
```

**Exploitation:**

```
http://example.com/download?file=../../../../etc/passwd
```

* The attacker successfully accesses `/etc/passwd`.

**Impact:**

* Exposure of all user account information.
* Possible password hashes if combined with `/etc/shadow`.

---

### Windows Example

File path:

```
http://example.com/view?doc=report.txt
```

Payload:

```
http://example.com/view?doc=..\..\..\Windows\system.ini
```

* Access system configuration and sensitive settings on Windows servers.

---

## 5. Impact of Directory Traversal

1. **Unauthorized Access to Files**

   * View or download configuration files, user data, source code.

2. **Data Leakage**

   * Exposed credentials, financial data, intellectual property.

3. **System Compromise**

   * If combined with LFI, log injection, or file upload, can lead to **Remote Code Execution (RCE)**.

4. **Application Logic Bypass**

   * Download sensitive backups, bypass access restrictions, or retrieve admin-only files.

---

## 6. Methodology for Testing

1. **Identify Inputs Accepting File Paths**

   * Download links (`file=`)
   * Log viewers
   * Image or PDF renderers
   * Backup restore or export features

2. **Try Basic Traversal**

   * Use `../` or `..\` to move up directories.

3. **Test Multiple Levels**

   * `../../../../etc/passwd` (increment levels until root is reached)

4. **Try Encodings**

   * URL encode: `%2e%2e%2f`
   * Double encode: `%252e%252e%252f`

5. **Access Sensitive Files**

   * `/etc/passwd` (Linux)
   * `/etc/shadow` (Linux)
   * `C:\Windows\system.ini` (Windows)
   * Application configs (`wp-config.php`, `config.php`)

6. **Check for Chaining Opportunities**

   * Local File Inclusion (LFI)
   * Log injection + LFI → Remote Code Execution
   * Upload abuse → combine with traversal

---

## 7. Defense & Mitigation

1. **Input Validation**

   * Reject any input containing `../` or `..\`.
   * Use **whitelists**: allow only expected filenames.

2. **File Path Restrictions**

   * Use **absolute paths** and `realpath()` to ensure the file is inside the intended directory.

3. **Least Privilege**

   * Web server should **not have access** to sensitive system files.

4. **Avoid Exposing System Files**

   * Keep `/etc`, `/var/log`, and application config files **outside web root**.

5. **Use Web Application Firewalls (WAF)**

   * Block suspicious traversal sequences.

---

## 8. Example Safe Implementation in PHP

```php
<?php
$allowed_dir = "/var/www/uploads/";
$file = basename($_GET['file']);  // Removes directory traversal sequences
$filepath = $allowed_dir . $file;

if (!file_exists($filepath)) {
    die("File not found");
}

readfile($filepath);
?>
```

* `basename()` removes path traversal attempts like `../../etc/passwd`.
* Only files inside `/uploads/` can be accessed.

---

## 9. Summary 

| Aspect             | Details                                                                            |
| ------------------ | ---------------------------------------------------------------------------------- |
| Vulnerability Name | Directory Traversal / Path Traversal                                               |
| Cause              | Improper input validation in file paths                                            |
| Exploitation       | Using `../` or encoded sequences to access unauthorized directories                |
| Impact             | Unauthorized access, data leakage, potential RCE                                   |
| Common Targets     | `/etc/passwd`, `/etc/shadow`, `wp-config.php`, Windows config files                |
| Prevention         | Whitelist filenames, sanitize input, restrict file paths, use least privilege, WAF |
