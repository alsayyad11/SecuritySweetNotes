
## **1. Authentication Testing Overview**

**Authentication** is the process that verifies the identity of a user — ensuring that the person trying to access the system is who they claim to be.
Common authentication mechanisms include:

* **Username + Password**
* **Multi-Factor Authentication (MFA)**
* **SSO (Single Sign-On)**
* **OAuth / OpenID Connect tokens**

The goal of **authentication testing** is to identify weaknesses in how authentication is implemented — to ensure users cannot bypass or break it.

---

## **2. Testing for Credentials Transported Over an Encrypted Channel**

### **Purpose**

To verify that user credentials (e.g., username, password) are transmitted securely over HTTPS and **not exposed in plaintext** over the network.

### **Why It Matters**

If login credentials are sent over HTTP (unencrypted), an attacker can intercept them via **Man-in-the-Middle (MITM)** attacks using tools like Wireshark or Burp Suite proxy.

### **Testing Steps**

1. Open **Burp Suite** or **OWASP ZAP** and intercept the login request.
2. Check if the login form submits credentials to an **HTTPS endpoint**.
3. Review the **Request Headers**:

   * Look for: `POST /login HTTP/1.1`
   * Ensure: `https://` not `http://`
4. Inspect if any **redirect** from HTTPS to HTTP happens.
5. Verify that credentials are not included in the **URL query string**.

### **Example**

```http
POST http://example.com/login HTTP/1.1
username=admin&password=12345
```

→ Vulnerable (credentials sent in plaintext)

---

## **3. Testing for Default Credentials**

### **Purpose**

To identify accounts that use factory-set or predictable credentials, e.g., `admin:admin`, `root:root`.

### **Why It Matters**

Developers sometimes forget to remove or change default admin credentials, especially in:

* CMS (WordPress, Joomla)
* Routers or IoT devices
* Admin panels

### **Testing Steps**

1. Identify the application or service type.
2. Search online for **default credentials** (e.g., “Tomcat default credentials”).
3. Try common username-password combinations manually or with tools like **Hydra** or **Medusa**.

### **Example**

```
Username: admin
Password: admin123
```

If login succeeds → **Vulnerability confirmed.**

---

## **4. Testing for Weak Lockout Mechanisms**

### **Purpose**

To test how the application handles multiple failed login attempts.

### **Why It Matters**

A weak or missing lockout mechanism allows **brute force attacks** — attackers can guess credentials endlessly.

### **Testing Steps**

1. Try multiple wrong passwords for the same user.
2. Observe the response:

   * Is there a **CAPTCHA** after several failures?
   * Does the account lock after, say, 5 attempts?
   * Is the lockout temporary or permanent?
3. Check if the mechanism is **IP-based** (can attacker bypass by changing IP?)

### **Example**

If you can send 1000 login attempts without being blocked — **weak lockout mechanism**.

---

## **5. Testing for Bypassing Authentication Schema**

### **Purpose**

To check if it’s possible to bypass authentication completely using logic flaws or parameter manipulation.

### **Common Techniques**

* **URL Direct Access**:

  ```
  /login -> redirects to /dashboard
  Accessing /dashboard directly may skip login check
  ```
* **Modifying Cookies or Tokens**:

  ```
  isAuthenticated=true
  ```
* **SQL Injection in Login Form**:

  ```
  ' OR '1'='1
  ```

### **Example**

```sql
SELECT * FROM users WHERE username='$user' AND password='$pass';
```

If not properly sanitized, using `' OR '1'='1` may bypass login.

---

## **6. Testing for Vulnerable "Remember Password" Function**

### **Purpose**

To check if the "Remember Me" feature stores credentials or session tokens insecurely.

### **Why It Matters**

If credentials or tokens are stored in plain text (e.g., in cookies or localStorage), attackers can steal them.

### **Testing Steps**

1. Log in with "Remember Me" checked.
2. Inspect browser storage:

   * **Cookies**
   * **localStorage**
   * **sessionStorage**
3. Look for cleartext passwords or tokens.

### **Example**

```json
{
  "username": "admin",
  "password": "123456"
}
```

→ Vulnerable (stored in plaintext).

---

## **7. Testing for Browser Cache Weaknesses & Cache Control Headers**

### **Purpose**

To ensure sensitive pages (like dashboards) are not cached by browsers or proxies.

### **Why It Matters**

If sensitive data is cached, another user using the same browser can access it via browser history.

### **Testing Steps**

1. Log in, open sensitive pages.
2. Log out.
3. Press **Back** button — if data still visible → caching issue.
4. Check HTTP response headers:

   * `Cache-Control: no-store`
   * `Pragma: no-cache`
   * `Expires: 0`

### **Example (Secure Response)**

```http
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Expires: 0
```

If missing, caching risk exists.

---

## **8. Testing for Weak Password Policy**

### **Purpose**

To ensure the application enforces strong password rules.

### **Why It Matters**

Weak password policies lead to easy credential guessing or brute-forcing.

### **Testing Steps**

1. Try setting a short or simple password:

   * "12345"
   * "password"
   * "qwerty"
2. Check if the system accepts them.
3. Review password policy (e.g., complexity, length, expiration).

### **Example**

If system accepts `1234` → **Weak Password Policy**.

**Strong Policy Example:**

* At least 12 characters
* Uppercase + lowercase + digit + special character

---

## **9. Testing for Weak Authentication in Alternative Channels**

### **Purpose**

To verify if other authentication channels (like APIs, mobile apps, or backup login portals) use weaker security.

### **Why It Matters**

Attackers may bypass the main secure login page by targeting:

* **Mobile app API endpoints**
* **Admin or beta login portals**
* **Legacy authentication APIs**

### **Testing Steps**

1. Discover alternative endpoints (`/api/login`, `/admin/login`).
2. Intercept their requests using Burp Suite.
3. Check for:

   * Missing HTTPS
   * No rate limiting
   * No MFA
   * Simpler password validation

### **Example**

Main login uses **2FA**, but `/api/login` allows login with just username/password → **vulnerability**.

---

## **Summary**

| Test Type                          | What It Checks         | Example of Vulnerability          |
| ---------------------------------- | ---------------------- | --------------------------------- |
| Credentials over Encrypted Channel | HTTPS usage            | Plain HTTP login form             |
| Default Credentials                | Default admin accounts | `admin:admin`                     |
| Weak Lockout                       | Brute force protection | No lock after 10 failed attempts  |
| Authentication Bypass              | Logic flaw / SQLi      | Access `/dashboard` without login |
| Remember Password                  | Insecure storage       | Password in cookie                |
| Cache Weakness                     | Missing headers        | Data visible after logout         |
| Weak Password Policy               | Password complexity    | Accepting “12345”                 |
| Alternative Channels               | API/mobile auth        | No HTTPS or weak login check      |
