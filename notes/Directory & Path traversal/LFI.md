## **What is Local File Inclusion (LFI)?**

Local File Inclusion (LFI) is a web vulnerability that allows an attacker to make a web application either display or execute files that are stored locally on the server. This vulnerability occurs when user input is passed to file inclusion functions (like `include()` or `require()` in PHP) **without proper sanitization**.

LFI can lead to serious consequences such as:

* **Reading sensitive files** (like credentials or config files)
* **Executing malicious code** (e.g., PHP web shells)
* **Cross-Site Scripting (XSS)** via log file injection
* **Remote Code Execution (RCE)** under certain conditions
  
---

## 👀 **Example of LFI**

Suppose the application includes a file based on a URL parameter:

```
https://example.com/?module=contact.php
```

An attacker could manipulate the URL like this:

```
https://example.com/?module=/etc/passwd
```

If the application does not properly validate the input, it may return the contents of the `/etc/passwd` file — which is a common target on Linux systems.

---

## **How Does LFI Work?**

When the application accepts a file path as user input and treats it as trusted, the attacker can inject arbitrary paths into the request. If the file exists and the application has permission to access it, it can be read or executed.

If the application also allows **file uploads**, the attacker may upload a malicious file (e.g., PHP web shell) and attempt to execute it via LFI — assuming they know where the file is stored.

---

## **How to Identify LFI Vulnerabilities**

### 1. **Basic Local File Inclusion**

You can test this by replacing the expected file name with a system file path:

```
Initial: https://example.com/?module=contact.php  
Test:    https://example.com/?module=/etc/passwd
```

If successful, the response might contain:

```
root:x:0:0:root:/root:/bin/bash
alex:x:500:500:/home/alex:/bin/bash
...
```

---

### 2. **Null Byte Injection**

If the application appends `.php` automatically to the input, you can bypass that by injecting a **null byte (`%00`)** to terminate the string:

```
https://example.com/preview.php?file=../../../../../passwd%00
```

> Note: Null byte injection is no longer effective in recent PHP versions but is important for legacy systems.

---

### 3. **Path and Dot Truncation**

In many PHP environments, filenames longer than **4096 bytes** are truncated. If you make the input string longer than that limit, PHP will cut off the extra characters — potentially dropping `.php` and allowing unintended files to be included.

Attackers may also combine this with:

* **Unicode encoding**
* **Double encoding**
* Other path obfuscation techniques

---

## **Impact of an LFI Exploit**

Depending on the situation, LFI can:

* Expose sensitive information (e.g., logs, credentials, source code)
* Allow attackers to discover internal structure or security misconfigurations
* Lead to full server compromise if combined with file upload and execution (RCE)

Even if the included code is not executed, the attacker may gain enough insight to craft another, more effective attack.

---
