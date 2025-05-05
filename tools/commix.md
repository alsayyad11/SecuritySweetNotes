## 💣 Commix (Command Injection Exploiter)

### ✅ What is Commix?
Commix is a tool used to test websites and web apps for **Command Injection** vulnerabilities.  
Command Injection means the attacker can run system commands on the server using user input (like in forms or URLs).

---

### ✅ What is it used for?
- Find and exploit **command injection** bugs.  
- Test if a web parameter can be used to run OS commands.  
- Gain access to the target system if it is vulnerable.

---

### ✅ Features of Commix:
- Easy to use from the terminal with simple commands.  
- Supports GET, POST, and Cookie-based inputs.  
- Can be used for both **blind** and **classic** command injection.  
- Supports many techniques to bypass filters.  
- Can open reverse shells or bind shells if the server is vulnerable.

---

### ✅ Example usage:
```bash
commix --url="http://target.com/login.php" --data="username=admin&password=123" --technique=CMD

