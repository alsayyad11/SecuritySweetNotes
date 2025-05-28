## What is a MIME Type?

<p align="center">
  <img src="https://github.com/user-attachments/assets/d7276874-6ff2-4e21-a8e8-2b9212f35f69" alt="image" />
</p>



**MIME** stands for **Multipurpose Internet Mail Extensions**.
It's a standard used to indicate the nature and format of a document, file, or assortment of bytes.

Browsers use MIME types to understand **how to handle** a file received from a server.

For example:

* Is it an image? → `image/png`
* Is it an HTML page? → `text/html`
* Is it a PDF file? → `application/pdf`

---

### General MIME Type Structure

```
<type>/<subtype>
```

#### Examples:

* `text/html` → HTML file
* `application/json` → JSON data
* `image/jpeg` → JPEG image
* `application/pdf` → PDF document
* `application/octet-stream` → Binary file (unknown type)

---

## Why Do Browsers Care About MIME?

When a server sends a file, it includes a `Content-Type` header.
This tells the browser how to process the file.

Example HTTP header:

```http
Content-Type: text/html
```

If the browser sees this, it knows to **render it as a web page**, not download it.

---

## Common MIME Types

| Main Type      | Description                                      |
| -------------- | ------------------------------------------------ |
| `text/`        | Text files like `text/html`, `text/css`          |
| `image/`       | Images like `image/jpeg`, `image/png`            |
| `audio/`       | Audio files like `audio/mpeg`, `audio/ogg`       |
| `video/`       | Videos like `video/mp4`                          |
| `application/` | Executable or structured files (e.g., PDF, JSON) |
| `multipart/`   | Multi-part documents (e.g., email content)       |

📚 **Reference:** [Common MIME types on MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types/Common_types)

---

## MIME Type Spoofing – How Attackers Exploit It

### What is MIME Spoofing?

An attacker uploads a malicious file (like a `.php` or `.html` with JS),
but **disguises it** with a harmless-looking extension, like `.jpg`.

If the server doesn't inspect the file content, it might serve it as `image/jpeg`.
But browsers might **sniff** the actual content and **execute code** inside it.

---

### Practical Example:

Attacker uploads `virus.jpg` (which actually contains HTML/JS).
The server replies with:

```http
Content-Type: image/jpeg
```

But the file **contains HTML**, and if the browser sniffs it, **JavaScript gets executed** — a potential XSS or malware injection!

---

### How to Prevent MIME Sniffing

Use this HTTP header:

```http
X-Content-Type-Options: nosniff
```

This forces the browser to **trust the declared MIME type**, and **not sniff** the content.

---

### Other Exploits Using MIME:

1. **Extension Bypass**:

   * Upload a file like `shell.php.jpg` and server only checks `.jpg`.

2. **Execute on View**:

   * Upload `image.svg` with embedded JavaScript — some sites may render it inline, leading to XSS.

3. **Content-Type Confusion**:

   * Server says `application/pdf`, but file contains JavaScript — browser might still run it.

---

## Using Burp Suite to Test MIME Vulnerabilities

Burp Suite is a powerful tool for testing MIME type-related issues. Here’s how you can use it:

### Modify Response MIME Type with Burp:

1. Intercept a file download or preview request.
2. In Burp **HTTP history**, right-click the response → **"Show response in browser"** or **Send to Repeater**.
3. Manually **edit the `Content-Type` header** to test behavior. For example:

   ```http
   Content-Type: text/html
   ```
4. Observe if the browser renders it as HTML, executes embedded scripts, or shows alerts (XSS, etc.).
5. You can also **remove the Content-Type header** to force the browser to sniff the content.

### Goals of MIME Testing in Burp:

* Trigger unintended **HTML rendering**.
* Test **JavaScript execution** inside images like `.svg`.
* Bypass upload validation by **spoofing headers** in Burp.

---

## Attacks That Use MIME Exploits

| Attack Type            | MIME-dependent | Description                            |
| ---------------------- | -------------- | -------------------------------------- |
| MIME Sniffing          |               | Browser tries to guess content         |
| Content-Type Confusion |               | Tricking the browser                   |
| SVG-based XSS          |               | JavaScript inside images               |
| File Upload Exploits   |               | Dangerous files disguised as safe ones |

---

## Server-Side Protection Tips

1. Validate **actual file content**, not just the name.
2. Use tools like `finfo` (PHP) to detect real MIME type.
3. Always include this header:

   ```http
   X-Content-Type-Options: nosniff
   ```
4. Block dangerous extensions like `.php`, `.js`, `.svg`, etc.
5. Store uploaded files **outside the web root** and serve them through a secure script.

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/e8014f7e-29b0-4a7a-bf01-09d818a31b8c" alt="image" />
</p>


## What is `.htaccess`?

`.htaccess` is a configuration file for the **Apache web server**.
It allows you to control settings on a per-directory basis.

You can use it to:

* Block access to files
* Redirect URLs
* Configure MIME types or headers
* Disable script execution
* Add basic protection

---

### Useful `.htaccess` Examples

#### 1. Block PHP Execution in Uploads Folder:

```apache
<FilesMatch "\.(php|php5)$">
  Order Allow,Deny
  Deny from all
</FilesMatch>
```

---

#### 2. Block Access to Sensitive Files:

```apache
<Files "config.php">
  Order allow,deny
  Deny from all
</Files>
```

---

#### 3. Enable MIME Protection:

```apache
<IfModule mod_headers.c>
  Header set X-Content-Type-Options "nosniff"
</IfModule>
```

---

#### 4.  Prevent Upload of Dangerous File Types:

```apache
<FilesMatch "\.(exe|sh|php|pl)$">
  Order allow,deny
  Deny from all
</FilesMatch>
```

---

#### 5. Redirect Old URL:

```apache
Redirect 301 /old-page.html https://example.com/new-page.html
```

---

##  `.htaccess` as an Attack Vector

If an attacker can upload and control a `.htaccess` file:

* They might **enable execution** of uploaded PHP files.
* They might **change MIME types** to trick the browser.
* They could **redirect visitors** to malicious websites.

---

##  How to Protect `.htaccess`

1. Deny upload of files named `.htaccess`.
2. Never allow users to edit config files.
3. Separate file upload directories from your application code.

---



