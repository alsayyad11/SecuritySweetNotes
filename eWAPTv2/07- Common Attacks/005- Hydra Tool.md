<img width="1280" height="640" alt="1" src="https://github.com/user-attachments/assets/6ce5022f-7b31-440a-9819-9733e8b4c94f" />

## 1. What is Hydra?

**Hydra** (also called **THC-Hydra**) is a popular password-cracking tool used by penetration testers and security researchers. Its main purpose is to **brute-force login credentials** (username/password) against various protocols and services.

Think of it this way:
When an application (like SSH, FTP, HTTP, MySQL, etc.) requires a login, Hydra can automatically try many username and password combinations until it finds the correct one.

---

## 2. Why Hydra is Important?

* **Speed**: It is very fast because it uses parallel connections (multi-threading) to test many logins at the same time.
* **Wide Support**: It supports many different services (FTP, SSH, HTTP, SMB, RDP, Telnet, MySQL, Postgres, VNC, etc.).
* **Automation**: Instead of trying passwords manually, Hydra automates the process.

Hydra is mainly used in:

* Penetration Testing (to check password strength).
* Red Teaming (simulating real attackers).
* Security Assessments.

> Note: Hydra is for legal penetration testing or CTFs. Using it against systems you don’t own or without permission is **illegal**.

---

## 3. How Hydra Works

Hydra follows a **brute force attack** or a **dictionary attack**:

* **Brute Force**: Trying every possible combination of characters until the password is found (time-consuming).
* **Dictionary Attack**: Using a wordlist (like `rockyou.txt`) that contains millions of common passwords, and testing them one by one.

Hydra sends login requests to the target service using the given **protocol** (like SSH, FTP, etc.) with different username/password combinations until it finds a valid match.

---

## 4. Hydra Syntax

The basic command structure of Hydra looks like this:

```bash
hydra -l <username> -P <password_wordlist> <target> <protocol>
```

* `-l` → specifies the username
* `-L` → specifies a file containing a list of usernames
* `-p` → specifies a single password
* `-P` → specifies a file containing a list of passwords
* `<target>` → the target IP or domain name
* `<protocol>` → the service to attack (ssh, ftp, http, smb, mysql, etc.)
* `-t` → number of parallel threads (default 16, more threads = faster but heavier on network)
* `-vV` → verbose output (shows each attempt)

---

## 5. Examples of Hydra Usage

### Example 1: SSH Brute Force (Single User, Wordlist of Passwords)

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10
```

* Target: `192.168.1.10`
* Protocol: `ssh`
* Username: `root`
* Passwords: taken from `rockyou.txt`

Hydra will try every password from the wordlist for the user `root`.

---

### Example 2: FTP Brute Force (Multiple Users and Passwords)

```bash
hydra -L users.txt -P passwords.txt ftp://192.168.1.20
```

* Target: `192.168.1.20`
* Protocol: `ftp`
* Users: loaded from `users.txt`
* Passwords: loaded from `passwords.txt`

This will test every combination of usernames from `users.txt` with passwords from `passwords.txt`.

---

### Example 3: HTTP Login Form Brute Force

Web applications often use login forms. Hydra supports HTTP/HTTPS forms.

```bash
hydra -L users.txt -P passwords.txt 192.168.1.30 http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
```

* Target: `192.168.1.30`
* Protocol: `http-post-form`
* Path: `/login` page
* Parameters: `username` and `password`
* `^USER^` and `^PASS^` → placeholders for Hydra to replace with values from the wordlists
* `F=Invalid` → failure message in the response that means the login failed

If Hydra finds a login where the failure message doesn’t appear, it means the credentials worked.

---

### Example 4: MySQL Database Brute Force

```bash
hydra -L users.txt -P passwords.txt mysql://192.168.1.40
```

Hydra will try to log in to the MySQL service using usernames and passwords from the lists.

---

### Example 5: RDP (Remote Desktop Protocol)

```bash
hydra -L users.txt -P passwords.txt rdp://192.168.1.50
```

Hydra will test RDP logins against the target machine.

---

## 6. Key Tips When Using Hydra

* Always have **permission** before testing.
* Use the right number of threads (`-t 4`, `-t 16`, etc.) to balance speed and avoid crashing services.
* Use **specific wordlists** for better results (e.g., company-related passwords, not just rockyou).
* Hydra works best when you already know/guess the **username**.
* Combine Hydra with **Recon tools** (like Nmap) to find open ports and services before attacking.

---

## 7. Alternatives to Hydra

* **Medusa** – similar tool, also supports multi-threaded brute forcing.
* **Ncrack** – specialized in network authentication cracking.
* **Burp Suite Intruder** – for brute forcing web logins.
