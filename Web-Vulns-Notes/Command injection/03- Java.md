# ProcessBuilder vs Runtime.exec() in Java

### **What is `Runtime.exec()`?**

* **`Runtime.exec()`** is a method in Java that allows you to run system commands, such as calling shell commands on a Linux system or command prompt commands on Windows.
* It works by invoking the system's shell (like `/bin/sh` on Unix-based systems or `cmd.exe` on Windows) and executing the given command string.

#### **How does `Runtime.exec()` work?**

When you call **`Runtime.getRuntime().exec("command")`**, it passes the **command** to the system shell for execution. For example:

```java
Runtime.getRuntime().exec("curl --help");
```

* **`curl --help`** is a shell command that would show you the help for the `curl` utility.
* The shell parses the command, breaks it into separate arguments, and then executes it.

But the problem with this is that the **shell** allows special characters like **`&`**, **`;`**, **`|`**, etc., which have special meanings in the shell.

For example:

```java
Runtime.getRuntime().exec("curl --help; rm -rf /");
```

In this case, if an attacker is able to manipulate the input, they can add commands like **`rm -rf /`** which would delete all files on the system.

This is **Command Injection**—a severe security vulnerability where an attacker can inject arbitrary commands into your application’s process.

### **What is `ProcessBuilder`?**

**`ProcessBuilder`** is a class in Java that provides a more controlled and secure way to execute system commands. Instead of passing the command to the shell, it executes the command directly, which means it doesn’t interpret shell-specific characters like **`;`** or **`&`**.

#### **How does `ProcessBuilder` work?**

With **`ProcessBuilder`**, you don't pass the entire command as a single string to the shell. Instead, you pass the command and its arguments as separate strings in a list (or array). For example:

```java
ProcessBuilder processBuilder = new ProcessBuilder("curl", "--help");
processBuilder.start();
```

Here’s what happens:

* **`ProcessBuilder`** takes the command **`curl`** and its argument **`--help`** separately.
* It doesn’t pass this through the shell. Instead, it directly executes **`curl`** with the **`--help`** argument.

This approach is safer because:

1. **No shell interpretation**: It avoids interpreting shell metacharacters (such as **`;`**, **`&`**, **`|`**) in the way **`Runtime.exec()`** would.
2. **Prevents command injection**: Since the input is passed as arguments and not as a string to the shell, even if the user input contains malicious characters, they won’t be able to execute additional commands.
3. **Less complexity**: There’s no need to worry about shell-specific quirks when using **`ProcessBuilder`**.

### **Key Differences Between `Runtime.exec()` and `ProcessBuilder`**

1. **Execution method**:

   * **`Runtime.exec()`** executes the command via the **shell** (e.g., `/bin/sh` on Linux, `cmd.exe` on Windows).
   * **`ProcessBuilder`** directly executes the command without using the shell.

2. **Security**:

   * **`Runtime.exec()`** is prone to **command injection** because the shell interprets metacharacters like **`&`**, **`;`**, and **`|`**, allowing attackers to inject additional commands.
   * **`ProcessBuilder`** is safer because it doesn’t invoke the shell, so those metacharacters can’t be used to exploit vulnerabilities.

3. **Input handling**:

   * With **`Runtime.exec()`**, the command string is passed directly, which can include special shell characters, making it vulnerable.
   * **`ProcessBuilder`** separates the command from its arguments, preventing metacharacters from being misinterpreted by the shell.

### **Command Injection Risk Example**

Let's say your application allows users to provide a URL and fetch data from it using **`curl`**:

```java
String url = userInput; // e.g., http://example.com
Runtime.getRuntime().exec("curl " + url);
```

* If the user inputs **`http://example.com; rm -rf /`**, this will be executed as:

```bash
curl http://example.com; rm -rf /
```

* The **`curl`** command will be executed, and after that, the **`rm -rf /`** command will delete all files on the system. This is a **command injection attack**.

But with **`ProcessBuilder`**, if you separate the command from its arguments:

```java
ProcessBuilder processBuilder = new ProcessBuilder("curl", userInput);
processBuilder.start();
```

* Here, **`userInput`** can’t inject another command because **`ProcessBuilder`** treats it as a single argument and doesn’t allow shell metacharacters to execute additional commands.

### **Conclusion**

* **Use `ProcessBuilder`** whenever possible because it is safer and avoids the security risks associated with **`Runtime.exec()`**.
* If you **must use `Runtime.exec()`**, be **extremely careful** with user input and **sanitize** it thoroughly to avoid command injection.
* **Avoid shell metacharacters** such as **`;`**, **`&`**, and **`|`** from user input or any untrusted source.

### **Recommendation for Secure Code**:

* Prefer using libraries or methods that don't require calling OS commands. For example, use Java’s built-in methods like `mkdir()` instead of invoking **`mkdir`** via shell commands.


### Code to Test Command Execution Behavior

```java
String[] specialChars = new String[]{"&", "&&", "|", "||"};
String payload = "cmd /c whoami";
String cmdTemplate = "java -version %s " + payload;
String cmd;
Process p;
int returnCode;

for (String specialChar : specialChars) {
    cmd = String.format(cmdTemplate, specialChar);
    System.out.printf("#### TEST CMD: %s\n", cmd);
    p = Runtime.getRuntime().exec(cmd);
    returnCode = p.waitFor();
    System.out.printf("RC    : %s\n", returnCode);
    System.out.printf("OUT   :\n%s\n", IOUtils.toString(p.getInputStream(), "utf-8"));
    System.out.printf("ERROR :\n%s\n", IOUtils.toString(p.getErrorStream(), "utf-8"));
}

System.out.printf("#### TEST PAYLOAD ONLY: %s\n", payload);
p = Runtime.getRuntime().exec(payload);
returnCode = p.waitFor();
System.out.printf("RC    : %s\n", returnCode);
System.out.printf("OUT   :\n%s\n", IOUtils.toString(p.getInputStream(), "utf-8"));
System.out.printf("ERROR :\n%s\n", IOUtils.toString(p.getErrorStream(), "utf-8"));
````

### Result of the Test:

#### 1. **Test Command: `java -version & cmd /c whoami`**

```bash
RC    : 0
OUT   :
ERROR :
java version "1.8.0_31"
```

#### 2. **Test Command: `java -version && cmd /c whoami`**

```bash
RC    : 0
OUT   :
ERROR :
java version "1.8.0_31"
```

#### 3. **Test Command: `java -version | cmd /c whoami`**

```bash
RC    : 0
OUT   :
ERROR :
java version "1.8.0_31"
```

#### 4. **Test Command: `java -version || cmd /c whoami`**

```bash
RC    : 0
OUT   :
ERROR :
java version "1.8.0_31"
```

#### 5. **Test Payload Only: `cmd /c whoami`**

```bash
RC    : 0
OUT   :
mydomain\simpleuser
ERROR :
Incorrect usage:
```

### Explanation of the Result:

* When testing with special characters (e.g., `&`, `&&`, `|`, `||`), the command executes `java -version` and ignores the second command (`cmd /c whoami`) because **`Runtime.exec()`** doesn't invoke a shell and doesn't support shell metacharacters.
* However, when the **payload** (`cmd /c whoami`) is run by itself, it correctly executes the command and returns the system's user information.

### Example of Incorrect Usage with `ProcessBuilder`:

```java
ProcessBuilder b = new ProcessBuilder("C:\\DoStuff.exe -arg1 -arg2");
```

In this example, the entire command and its arguments are passed as a single string, which can be manipulated and may lead to malicious strings being injected.

### Correct Usage with `ProcessBuilder`:

```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "TrustedArg1", "TrustedArg2");

Map<String, String> env = pb.environment();

pb.directory(new File("TrustedDir"));

Process p = pb.start();
```



