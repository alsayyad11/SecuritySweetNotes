# Broken Authentication: Full Methodology for Identifying and Exploiting Vulnerabilities  
**Source:** [Dinesh Pathro on Medium](https://mrdineshpathro.medium.com/broken-authentication-full-methodology-for-identifying-and-exploiting-vulnerabilities-63a55c3d4399)

---

## What is Broken Authentication?

Broken Authentication is one of the most critical vulnerabilities in web applications. It happens when the system's login and session management processes are poorly secured, allowing attackers to gain unauthorized access to user accounts.

**Common causes:**

* Storing passwords in plain text.
* Weak or missing session expiration.
* Predictable or stealable session tokens.
* Allowing weak or default passwords (e.g., "123456").

---

## 1. Reconnaissance – Information Gathering

Before launching any attack, gather details about how the authentication system works.

**Look for endpoints like:**

* /login
* /signin
* /auth
* /reset-password
* /logout

**Check if the app uses MFA (SMS, Email, App-based).**

**Tools for this phase:**

* Burp Suite: Crawler to identify forms and endpoints.
* OWASP ZAP: Open-source alternative to Burp.
* Wfuzz: Useful for testing login form behavior.
* dirb / gobuster: Discover hidden or unlinked paths such as /admin-login or /old-auth.

---

## 2. Assessing Authentication Mechanisms

**Key aspects to evaluate:**

* Are there minimum password requirements?
* Does the app require symbols, uppercase, lowercase, numbers?
* Is there an account lockout mechanism after failed login attempts?
* Are cookies set with HttpOnly, Secure, and SameSite flags?
* Do sessions expire after inactivity?

---

## 3. Exploitation Techniques

### Brute Force:

Try many password combinations for a single username until one works:

```bash
hydra -l admin -P passwords.txt http://target.com/login
```

### Password Spraying:

Use one password across many usernames to avoid lockouts.

### Session Fixation:

Set a fixed session ID before the victim logs in. If the session remains valid, hijack it.

### Credential Stuffing:

Use leaked username/password combos from data breaches.

---

## Recommended Tools

* Hydra: For brute-force login attacks.
* Burp Suite Intruder: For testing multiple combinations.
* Sentry MBA / Snipr: For automated credential stuffing.
* Cookie Editor: To modify and inspect cookies manually.

---

## 4. Post-Exploitation

Once inside a user account:

### Privilege Escalation:

* Look for admin panels or role misconfigurations.
* Test for IDOR (Insecure Direct Object Reference) issues.

### Persistence:

* Create a new admin user.
* Capture and reuse session tokens.
* Search for API keys or secrets in local storage or configuration files.

---

## 5. Defense Against Broken Authentication

### Best Practices:

* Enforce strong passwords (at least 12 characters, with symbols, uppercase, etc.).
* Enable 2FA/MFA for all users.
* Secure session management:

  * Regenerate session IDs after login.
  * Set automatic expiration.
* Use rate-limiting and CAPTCHA to prevent brute force.
* Implement SIEM tools to monitor login behavior and detect anomalies.

---

## 6. Discovering Hidden Endpoints

### Tools:

* dirb, gobuster

```bash
dirb http://target.com /usr/share/wordlists/dirb/common.txt
```

### Common authentication-related paths:

* /register
* /signup
* /reset-password
* /forgot-password
* /profile
* /change-password

---

## 7. Password Storage Review

### Ensure:

* Passwords are not stored in plain text.
* Strong hashing algorithms are used: bcrypt, PBKDF2, Argon2.

### If you obtain password hashes:

* Use Hashcat or John the Ripper for offline brute-forcing.

---

## 8. Rate-Limiting and Lockout Testing

* Does the application enforce CAPTCHA?
* Is there a lockout after multiple failed login attempts?
* Check HTTP response codes (403 Forbidden, 401 Unauthorized).

---

## 9. MFA/2FA Testing

* Is 2FA implemented using SMS? If so, it may be vulnerable to SIM swapping.
* Email-based 2FA can be bypassed if the attacker has email access.
* Test fallback/recovery mechanisms – can they bypass MFA?

---

## OAuth / JWT Token Exploitation

* Decode JWT tokens using jwt.io or similar tools.
* Look for:

  * Tokens that don’t expire.
  * Weak signing secrets.
  * Replay of old tokens that still work.

---

## Post-Exploitation Techniques

* Install a backdoor (new admin user).
* Persist access using stolen session cookies or tokens.
* Search for sensitive tokens or credentials in config files, localStorage, or cookies.

---

## Defense Summary

* Enforce a strong Password Policy.
* Enable MFA across all accounts.
* Secure session handling (regeneration, expiration).
* Use proper cookie flags (HttpOnly, Secure).
* Enable SIEM or equivalent monitoring tools for login activity and anomalies.

---

