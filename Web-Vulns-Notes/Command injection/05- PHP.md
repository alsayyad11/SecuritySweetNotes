
##  Dangerous Functions in PHP

There are several PHP functions that execute **system-level commands**:

| Function       | Description                                |
| -------------- | ------------------------------------------ |
| `exec()`       | Executes a command and returns output      |
| `system()`     | Executes a command and displays raw output |
| `passthru()`   | Executes command and sends raw output      |
| `shell_exec()` | Like backticks — captures command output   |

>  These are **dangerous** if user input is passed directly into them.

---

##  Vulnerable Example 

```php
<?php
$userInput = $_GET['ip'];
system("ping " . $userInput);
?>
```

If someone visits:

```
http://example.com?ip=127.0.0.1; ls
```

This command will be executed:

```
ping 127.0.0.1; ls
```

###  Problem:

* `;` lets the attacker **chain another command**.
* Now the system runs **both**: `ping` and `ls` — this is **command injection**!

---

##  How to Prevent It

###  1. Use `escapeshellarg()`

This function **escapes user input** so it can't break the command.

 Fixed version:

```php
<?php
$userInput = escapeshellarg($_GET['ip']);
system("ping " . $userInput);
?>
```

So this:

```php
escapeshellarg("127.0.0.1; ls")
```

Becomes:

```
'127.0.0.1; ls'
```

Which the shell treats as a **single harmless string**, not a command.

---

###  2. Use `escapeshellcmd()` (for the command itself)

* Use this if you're allowing users to **choose a command**, like from a dropdown.
* It escapes **dangerous characters in the command name**.

```php
$command = escapeshellcmd($_GET['cmd']);
system($command);  // Better, but still risky if cmd is user-controlled
```

---

###  3. Validate Input Using a Whitelist

Don’t let users type anything.

 Instead, **only allow specific values**:

```php
$allowedIps = ['127.0.0.1', '192.168.1.1'];

if (in_array($_GET['ip'], $allowedIps)) {
    system("ping " . escapeshellarg($_GET['ip']));
} else {
    echo "Invalid IP!";
}
```

---

### 4. Don’t Use Shell Commands If Not Needed

Ask yourself:

>  "Do I really need to call a shell command?"

 In many cases, **PHP has native functions** that can do the same thing safely.

**Instead of:**

```php
system("ls");
```

**Use:**

```php
print_r(scandir('.'));
```

---

##  Summary Cheat Sheet

| ❌ Don’t Do This                    | ✅ Do This                                 |
| ---------------------------------- | ----------------------------------------- |
| `system($_GET['input'])`           | `system(escapeshellarg($_GET['input']))`  |
| Let users send commands            | Use **hardcoded** commands or a whitelist |
| Concatenate strings in commands    | Use **escaping** + **validation**         |
| Use system commands when avoidable | Use **native PHP functions**              |

---
