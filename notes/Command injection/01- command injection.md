#  Command Injectio
- is an attack that executes arbitrary commands on the host OS via a vulnerable application.
- This happens when user input (from forms, cookies, headers, etc.) is passed directly to the system shell without proper validation.
- The attacker-supplied commands are usually executed with the privileges of the vulnerable application.
-  Command injection is often caused by **insufficient input validation**.

> Unlike **Code Injection**, where the attacker adds new code, in **Command Injection**, the attacker extends the application's existing functionality to execute system commands without needing to inject new code.

---

## Different ways of injecting OS Commands:

- ; The semicolon is the most common metacharacter used to test an injection flaw. The shell will run all the commands in sequence separated by the semicolon.
- & Separate multiple commands on one command line. It runs the first command then the second command.
- && Runs the command following && only if the preceding command is successful.
- | The Pipe, pipes the output of the first command into the second command.
- || Redirects the standard outputs of the first command to the standard input of the second command.
- ‘ The quote is used to force the shell to interpret and run commands between backticks. Following is an example of this command: Variable=”OS version ‘uname -a’” && echo $variable.
- () The brackets are used to nest commands.
- #The Hash is used as a command-line comment.

## How to Find Command Injection:

Any endpoint of a web application that allows the user to enter any input value to be processed by a backend server can be a valid start point for finding any sort of injection point.

## Useful commands to test for Command Injection:

![image](https://github.com/user-attachments/assets/472ef87e-abff-480b-b563-02effdd9b625)




### 🧪 Examples

#### **Example 1: UNIX `cat` Wrapper**

```c
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
 char cat[] = "cat ";
 char *command;
 size_t commandLength;

 commandLength = strlen(cat) + strlen(argv[1]) + 1;
 command = (char *) malloc(commandLength);
 strncpy(command, cat, commandLength);
 strncat(command, argv[1], (commandLength - strlen(cat)) );

 system(command);
 return (0);
}
```

**Normal Use**:

```
$ ./catWrapper Story.txt
```

**With Attack**:

```
$ ./catWrapper "Story.txt; ls"
```

This allows the attacker to execute arbitrary commands like `ls`.

---

#### **Example 2: Privileged Program (`setuid root`)**

```c
int main(char* argc, char** argv) {
 char cmd[CMD_MAX] = "/usr/bin/cat ";
 strcat(cmd, argv[1]);
 system(cmd);
}
```

If the program is set to `setuid root`, an attacker can pass commands like `";rm -rf /"`, leading to dangerous operations (e.g., deleting the system).

---

#### **Example 3: Environment Variable Manipulation**

```c
char* home=getenv("APPHOME");
char* cmd=(char*)malloc(strlen(home)+strlen(INITCMD));
if (cmd) {
 strcpy(cmd,home);
 strcat(cmd,INITCMD);
 execl(cmd, NULL);
}
```

An attacker can modify the `$APPHOME` environment variable to execute malicious code with the application's elevated privileges.

---

#### **Example 4: Path Hijacking in `make` Command**

```c
system("cd /var/yp && make &> /dev/null");
```

Since `make` is not specified with an absolute path, an attacker can modify the `$PATH` variable to point to a malicious `make`, which is then executed with root privileges.

---

#### **Example 5: Using `time` with `system()`**

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
     char command[256];
     if(argc != 2) {
          printf("Error: Please enter a program to time!\n");
          return -1;
     }

     memset(&command, 0, sizeof(command));
     strcat(command, "time ./");
     strcat(command, argv[1]);

     system(command);
     return 0;
}
```

An attacker can inject commands like `ls; cat /etc/shadow`.

---

#### **Example 6: PHP Command Injection**

```php
<?php
print("Please specify the name of the file to delete");
print("<p>");
$file=$_GET['filename'];
system("rm $file");
?>
```

If an attacker supplies a filename like `bob.txt; id`, the `id` command will be executed.

---

### 🔐 Prevention Tips

1. **Avoid using system calls** like `system()` or `exec()`.
2. **Use safer APIs** (e.g., Java's `javax.mail` instead of using `Runtime.exec()`).
3. **Sanitize input** to block dangerous characters like `;`, `&`, `|`, etc.
4. **Use full paths** when invoking system commands.
5. **Validate environment variables** to prevent malicious manipulation.

---

