
**Command Injection Testing**
**ID**: WSTG-INPV-12

This article explains how to test a web application for **OS Command Injection**. In this type of attack, a user tries to inject system commands through a web request to execute commands on the web server. When a web application doesn't properly filter user inputs, it can lead to command injection vulnerabilities.

### What is OS Command Injection?

OS Command Injection happens when an attacker uses a web interface to execute commands on the server's operating system (OS). If the server allows users to input data that gets passed to an OS command (like `ls`, `dir`, etc.), the attacker can execute harmful commands.

With command injection, attackers can:

* View sensitive information, such as passwords or files.
* Run malicious code or install malware on the server.

**Command injection is dangerous** and can lead to serious security issues if the web application doesn't properly sanitize or validate user inputs.

---

### Test Objectives

* **Identify potential command injection points**: Find areas in the application where user inputs can be passed to the OS for execution.
* **Assess vulnerabilities**: Check if the application is vulnerable to command injection attacks.

---

### How to Test for OS Command Injection

When testing, you’ll typically try to find places in the application where user inputs (like file names or parameters) are passed to OS commands. Here's how you can test:

#### Example 1: Modifying a URL

Sometimes, a web application shows file names in the URL. Let’s say there's a link to view a file:

**Original URL**:

```
http://example.com/cgi-bin/viewFile.pl?doc=report1.txt
```

You can try to modify the URL to inject a command like this:

**Modified URL**:

```
http://example.com/cgi-bin/viewFile.pl?doc=report1.txt|ls
```

Here, the `|` character is used to run the `ls` command after processing the file, which lists the files in the directory. If the app is vulnerable, it may show the contents of the directory instead of the file.

---

#### Example 2: Using Semicolon to Chain Commands

Another common technique is to use a semicolon (`;`) to chain commands. For example, in a URL, you might try this:

**Modified URL**:

```
http://example.com/viewFile.php?file=report1.txt;%20cat%20/etc/passwd
```

In this case:

* `%20` is URL encoding for a space.
* `;` tells the server to execute another command after the file is processed.
* The `cat /etc/passwd` command tries to read a sensitive file (`passwd`), which stores user information.

If the app doesn't properly handle inputs, it might expose sensitive data like the usernames and passwords on the server.

---

### Example of POST Request Injection

Sometimes, commands can be injected through HTTP POST requests, not just URLs. Here’s an example of how a vulnerable app might process a POST request to retrieve a document:

**Original POST Request**:

```
POST /public/doc HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

Doc=Document1.pdf
```

If the application doesn't properly validate the input, an attacker might try to inject a command in the `Doc` field, like this:

**Injected POST Request**:

```
POST /public/doc HTTP/1.1
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

Doc=Document1.pdf|dir
```

The `|dir` part will execute the `dir` command (on Windows) or `ls` (on Linux) and display the directory contents instead of the document. This is an example of a successful **Command Injection** attack.

---

### Common Special Characters for Command Injection

When testing for command injection, these special characters can be used:

* `|` (pipe): Allows running multiple commands, one after the other.
  Example: `cmd1|cmd2`

* `;` (semicolon): Also runs multiple commands.
  Example: `cmd1;cmd2`

* `&&`: Runs the second command only if the first command succeeds.
  Example: `cmd1&&cmd2`

* `||`: Runs the second command only if the first command fails.
  Example: `cmd1||cmd2`

* `$()`: Executes a command inside parentheses.
  Example: `$(whoami)`

These characters can be used to trick the application into running additional commands that it shouldn't be.

---

### Dangerous APIs That Can Lead to Command Injection

Certain programming functions (APIs) are known to be risky because they allow commands to be run on the server. These include:

* **Java**: `Runtime.exec()`
* **C/C++**: `system()`, `exec()`
* **Python**: `exec()`, `os.system()`, `subprocess.call()`
* **PHP**: `system()`, `shell_exec()`, `exec()`

If these functions are used in a web application without proper validation, they can open the door to command injection.

---

### How to Prevent OS Command Injection

1. **Sanitization**:
   The inputs (like URL parameters or form data) must be sanitized to ensure no harmful characters (e.g., `|`, `;`, `&`, `$`, etc.) can get through. This can be done using:

   * **Deny List**: A list of characters that should be blocked.
   * **Allow List**: A list of characters that are explicitly allowed, which is more secure than blocking bad characters.

2. **Escaping Special Characters**:
   Escape any special characters that could be used for command injection. For example:

   * For Windows: `|`, `;`, `&`, `>`, `<`, `$`, etc.
   * For Linux: `{`, `}`, `|`, `&`, `>`, `<`, `!`, etc.

3. **Permissions**:
   Ensure that the web application and its components only have the minimum permissions required to perform their tasks. If the application doesn’t need to execute system commands, make sure it doesn’t have the ability to do so.

---

### Tools to Help Test for Command Injection

* **Burp Suite**: A web vulnerability scanner that can help you identify command injection vulnerabilities.
* **OWASP ZAP**: Another tool for testing security in web applications, with features for identifying command injection.

---
### References

- OWASP Web Security Testing Guide: [Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection.html)

