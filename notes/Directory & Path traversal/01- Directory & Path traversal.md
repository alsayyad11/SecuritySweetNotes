### 1. **What is Directory Traversal/Path Traversal?**
![image](https://github.com/user-attachments/assets/bc1b6032-9545-41f3-8789-27bebb47c35e)

Directory traversal (also called file path traversal) is a web security vulnerability that allows an attacker to access files on the server running an application. This may include sensitive application data, code, backend credentials, and important operating system files. If the vulnerability allows write access, an attacker can also modify these files or execute code, potentially gaining full control over the server.

### 2. **Different Names of a Path Traversal/Directory Traversal Attack**

* **Path Traversal**
* **Backtracking**
* **Dot Dot Slash (../) Attack**

The attack leverages special characters like `../` (dot dot slash), which makes the browser or application move one level up in the directory structure. For example, `x/y/z/../` resolves to `x/y/`, allowing attackers to bypass directory structures and access files in other folders.

---
### Impacts of Directory Traversal
- The repercussions of a successful directory traversal attack can be dire. Attackers can gain access to configuration files, user databases, and proprietary information, leading to breaches of privacy and data theft.
- Furthermore, this vulnerability can serve as a stepping stone for launching more sophisticated attacks, such as remote code execution.

#### Example:

Consider a website’s file structure where to link `hobbies.html` to `index.html`:

```
../index.html
```

Here, `../` moves up one directory to reach the root or parent folder.

---

### 3. **How Does a Path/Directory Traversal Attack Work?**

If the web application code or server configuration is not secure, an attacker can exploit directory traversal vulnerabilities. Here's a vulnerable PHP example:

```php
$file = $_GET['file'];
file_get_contents('directory/' . $file);
```

In this case, an attacker could manipulate the URL like so:

```
https://example-website.com/?file=../../../../etc/passwd
```

This URL could lead to exposing the sensitive `/etc/passwd` file on Unix systems. Such attacks may also lead to credential theft, file modification, or full server control.

### 4. **How to Test for Path Traversal Vulnerabilities**

**Steps to Follow:**

a. **Look for file or directory parameters** (e.g., `include=main.inc` or `template=/en/sidebar`) or anything likely to interact with the server’s file system, such as displaying images or documents.

b. **Monitor error messages or unusual behavior**. If you see error messages about file paths, the application might be vulnerable.

c. **Modify the parameter** by adding a traversal sequence like `../../`. If the server responds the same, the app could be vulnerable.

d. **Check if traversal sequences are blocked or sanitized**. If the app filters sequences, see if it's possible to bypass using other techniques.

e. **Attempt to access files above the starting directory** (e.g., `/etc/passwd`), which could indicate a vulnerability.

f. **Test read/write access**. If you can write to or read from files like `/etc/passwd`, the application may be severely compromised.

g. **Write new files** or attempt to overwrite critical system files (e.g., system configuration files). This test helps identify write vulnerabilities.

**Tips:**

* **Use multiple traversal sequences**. If the server structure is deep, more sequences can avoid false negatives.
* **Platform differences**: Windows can tolerate both forward slashes `/` and backslashes `\`, while Unix/Linux systems only accept forward slashes. Some apps might be running Windows backend even if the front-end server is Unix-based, so test both.

---

### 5. **Reading Arbitrary Files via Directory Traversal/Path Traversal**

Consider an image load function in an insecure web application:

```html
<img src="/loadImage?filename=218.png">
```

This loads the image from `/var/www/images/218.png`. An attacker might modify the filename to access system files:

```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```

This translates to:

```
/var/www/images/../../../etc/passwd
```

Thus, the server reads `/etc/passwd`, exposing system information.

---

### 6. **Path/Directory Traversal in Simple Case**

In a simple case of path traversal, an attacker might simply input:

```
../../../etc/passwd
```

This could lead to the response containing the contents of the `/etc/passwd` file, a quick way to confirm a vulnerability.

---

### 7. **Common Obstacles in Exploiting Path Traversal Vulnerabilities**

Many applications implement defense mechanisms to block path traversal attacks. However, these defenses can often be bypassed through various techniques, such as:

* Using **absolute paths** (`filename=/etc/passwd`) instead of relative paths.
* Bypassing traversal filters with **nested traversal sequences** or using **URL encoding**.

### 8. **File Path Traversal, Traversal Sequences Blocked with Absolute Path Bypass**

If traversal sequences are blocked, an attacker may use absolute paths directly:

```
filename=/etc/passwd
```

This can bypass the directory traversal block and allow access to the file.

---

### 9. **File Path Traversal, Traversal Sequences Stripped Non-Recursively**

When traversal sequences are stripped non-recursively (i.e., only inner sequences are removed), an attacker can use **nested sequences** like:

```
….//….//….//etc/passwd
```

This allows the attacker to bypass the filtering and access sensitive files.

---

### 10. **File Path Traversal, Traversal Sequences Stripped with Superfluous URL-Decode**

Sometimes the server strips traversal sequences, but attackers can **URL encode** the sequences (`%2e%2e%2f`) or use **double URL encoding** (`%252e%252e%252f`) to bypass these restrictions and access the files.

For example:

```
https://insecure-website.com/loadImage?filename=%252e%252e%252f%252e%252e%252fetc/passwd
```

This can successfully allow access to the `/etc/passwd` file.

---

### 11. **File Path Traversal, Validation of Start of Path**

If the application expects specific file extensions (e.g., `.png`), an attacker might attempt to use a **null byte** (`%00`) to terminate the path before the extension:

```
filename=../../../etc/passwd%00.png
```

This could trick the application into reading `/etc/passwd` instead of a `.png` image.

---

### 12. **Mitigation of Path Traversal/Directory Traversal Vulnerabilities**

To prevent path traversal:

1. **Validate Input**: Ensure the user input matches a whitelist or strictly allows only certain characters (e.g., alphanumeric).
2. **Canonicalize Paths**: Use a secure method to resolve paths and verify that they start with an expected base directory. For instance, in Java:

```java
File file = new File(BASE_DIRECTORY, userInput);

if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // Process file
}
```

---
# References :

[File Path Traversal - PortSwigger](https://portswigger.net/web-security/file-path-traversal)

[Directory Path Traversal - Medium](https://medium.com/@Steiner254/directory-path-traversal-288a6188076)

[Directory Traversal — Web-based Application Security, Part 8](https://www.spanning.com/blog/directory-traversal-web-based-application-security-part-8/)

