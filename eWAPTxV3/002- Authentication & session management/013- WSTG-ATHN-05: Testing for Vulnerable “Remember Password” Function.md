
## **1. Introduction**

The “Remember Password” feature is designed to **improve user convenience** by allowing browsers or applications to remember login credentials so users don’t have to retype them every time.

However, **if not implemented securely**, this feature can introduce **severe security risks**, such as:

* Exposing plaintext credentials in the browser, source code, or local storage.
* Allowing unauthorized users to log in automatically.
* Making password theft trivial in shared or compromised systems.

---

## **2. Purpose of the Test**

The goal of this test is to:

* Identify insecure implementations of the **“Remember Password”** feature.
* Ensure that sensitive credentials are **never stored in plaintext** or **accessible to unauthorized users**.
* Verify that “Remember Password” does **not bypass authentication or session expiration** mechanisms.

---

## **3. How “Remember Password” Works**

There are **two main contexts** for this feature:

### **3.1. Browser-Level Remember Password**

Handled by browsers like Chrome, Firefox, or Edge.

* The browser detects `<input type="password">` fields.
* It offers to store the username and password locally (in browser memory or disk).
* On future visits, the browser **auto-fills** credentials into the login form.

**Risk:**
If a system is shared (e.g., public computer), anyone can log in without authentication.

---

### **3.2. Application-Level “Remember Me”**

Implemented by developers, often via cookies or tokens.

Example:

```http
Set-Cookie: rememberMe=eyJ1c2VyIjoiYWRtaW4iLCJ0b2tlbiI6IjEyMzQifQ==
```

On next visit, the app:

* Reads the `rememberMe` cookie.
* Authenticates the user automatically if the token is valid.

**Risk:**
If the cookie is **predictable, unencrypted, or non-expiring**, attackers can reuse it to impersonate users.

---

## **4. Common Vulnerabilities**

### **4.1. Storing Plaintext Passwords**

Passwords stored in:

* Cookies
* LocalStorage / SessionStorage
* IndexedDB
* Hidden form fields
* Logs or HTML source code

**Example (Insecure Cookie):**

```http
Set-Cookie: rememberMe=admin:password123
```

Anyone with access to this cookie can decode and reuse it.

---

### **4.2. Long-Lived or Non-Expiring Tokens**

Tokens that never expire allow indefinite access — even if a password changes.

**Example:**
A `rememberMe` token valid for months means a stolen laptop = stolen account.

---

### **4.3. Reusable or Predictable Tokens**

If tokens are generated without proper randomness (e.g., Base64(username + timestamp)), attackers can predict or forge valid tokens.

---

### **4.4. Missing Binding Between Token and Device/IP**

If the application doesn’t tie the remember-me token to:

* a specific IP address,
* user agent, or
* device fingerprint,

then stolen tokens can be reused anywhere.

---

### **4.5. Insecure Cookie Flags**

Cookies missing these attributes are vulnerable:

* `Secure`: prevents transmission over HTTP.
* `HttpOnly`: prevents JavaScript access.
* `SameSite`: mitigates CSRF.

---

### **4.6. Session Confusion**

Poorly designed “Remember Me” can **re-activate expired sessions**, effectively bypassing logout or session timeout policies.

---

## **5. Testing Methodology**

Let’s go step-by-step as OWASP recommends.

---

### **Step 1: Identify “Remember Me” Functionality**

Check login pages for:

* A checkbox labeled “Remember Me” or “Keep me signed in”.
* Hidden fields related to `rememberMe`, `auth_token`, or similar.

**Example HTML:**

```html
<form action="/login" method="POST">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="checkbox" name="rememberMe" value="true"> Remember Me
</form>
```

---

### **Step 2: Capture the Login Request and Response**

Use **Burp Suite** or **OWASP ZAP**:

* Log in with “Remember Me” checked.
* Inspect the server’s response.
* Look for cookies or headers containing “remember”, “token”, or “auth”.

Example:

```http
Set-Cookie: remember_token=eyJ1c2VyIjoiam9obiIsImtleSI6IjEyMzQ1NiJ9
```

Decode base64 or JWT values to check for:

* plaintext credentials,
* static user data,
* timestamps or predictable patterns.

---

### **Step 3: Inspect Client-Side Storage**

Check:

* `localStorage` and `sessionStorage`
* Browser password manager
* IndexedDB
* Cookie storage

Example (Insecure LocalStorage):

```js
localStorage.setItem("username", "admin");
localStorage.setItem("password", "admin123");
```

---

### **Step 4: Replay or Forge Tokens**

Try reusing the captured cookie on a new browser or IP.
If it still authenticates, the system doesn’t tie tokens to sessions, devices, or IPs.

**Example Attack:**

1. Attacker steals a victim’s `rememberMe` cookie.
2. Imports it into their browser.
3. Gains full account access — even after victim logs out.

---

### **Step 5: Test for Token Expiration**

Wait several hours or days, then attempt to reuse the token.
If it still works → **token doesn’t expire** (vulnerable).

---

### **Step 6: Modify and Replay Tokens**

Try editing the cookie/token value:

```bash
rememberMe=eyJ1c2VyIjoiYWRtaW4ifQ==
```

Change `"user": "john"` → `"user": "admin"`, re-encode, resend.
If the app grants access → token validation is weak.

---

### **Step 7: Check Cookie Security Flags**

In Burp or browser dev tools, check if:

```
Secure: true
HttpOnly: true
SameSite: Lax or Strict
```

are set.
Missing any of these = risk of **MITM** or **XSS-based theft**.

---

## **6. Real-World Example**

**Scenario:**
A social media platform allows “Remember Me.”
After login, the app sets:

```http
Set-Cookie: remember_token=base64(admin:admin123)
```

Attacker inspects cookies, decodes it, and sees the plaintext credentials.
Now they can reuse this cookie or even extract admin’s password.

**Result:**
Complete authentication bypass and credential leakage.

---

## **7. Secure Implementation Guidelines**

| Control                                     | Description                                                                                  |
| ------------------------------------------- | -------------------------------------------------------------------------------------------- |
| **Use Secure, Random Tokens**               | Generate tokens with strong cryptographic randomness (e.g., `UUIDv4`, 256-bit key).          |
| **Encrypt Tokens**                          | Encrypt all sensitive data before storing it client-side. Never store plaintext credentials. |
| **Set Expiration**                          | Tokens should expire after a short, defined period (e.g., 7 days).                           |
| **Bind Token to Device/IP**                 | Store user agent and IP hash with the token; reject if changed.                              |
| **Use Secure Cookie Attributes**            | `HttpOnly`, `Secure`, and `SameSite=Strict`.                                                 |
| **Invalidate on Logout or Password Change** | Deleting or changing the password should invalidate all remember-me tokens.                  |
| **Rotate Tokens Periodically**              | Regenerate tokens after each successful authentication.                                      |
| **Avoid Storing Passwords**                 | Always use server-side reference tokens instead of credentials.                              |

---

## **8. Example of Secure Remember-Me Token Design**

**Step 1:**
User logs in and checks “Remember Me.”
The server generates a random token (e.g., `sha256(uuid + salt)`).

**Step 2:**
Store the token server-side in the database:

```sql
user_id | token_hash                          | expiry
---------------------------------------------------------------
1       | 9f86d081884c7d659a2feaa0c55ad015... | 2025-10-20
```

**Step 3:**
Send the token to the client as a cookie:

```http
Set-Cookie: rememberMe=9f86d081884c7d65; Secure; HttpOnly; SameSite=Strict
```

**Step 4:**
When the cookie is presented again, the server compares hashes and ensures:

* Token not expired.
* Device/IP matches.
* Token not reused.

---

## **9. Browser Password Managers: Testing and Risks**

Browsers also store credentials.
Check whether:

* The app sets `autocomplete="off"` for password fields.
* Login forms use HTTPS.
* Sensitive fields aren’t pre-filled automatically.

**HTML Example:**

```html
<input type="password" name="password" autocomplete="off">
```

**Risk Example:**
If autocomplete is allowed on public computers, anyone could open the page → credentials autofill → log in as the victim.

---

## **10. Modern Storage Locations & Security Risks**

| Storage Method               | Example                            | Risk                             |
| ---------------------------- | ---------------------------------- | -------------------------------- |
| **Cookies**                  | `rememberMe=admin:1234`            | Stolen or reused if unprotected. |
| **LocalStorage**             | `localStorage.password="admin123"` | Accessible via XSS.              |
| **IndexedDB**                | Client-side database               | XSS or browser compromise risk.  |
| **SessionStorage**           | Temporary but visible to scripts   | Still accessible via JS.         |
| **Browser Password Manager** | Chrome saved password              | Unsafe on shared devices.        |

---

## **11. Example Tools for Testing**

* **Burp Suite / OWASP ZAP** – inspect requests and cookies.
* **CyberChef / Base64 decoder** – decode encoded cookies.
* **Postman** – replay tokens.
* **Cookie-Editor browser extension** – modify cookies manually.
* **Browser dev tools** – inspect storage (Application → Storage → Cookies/LocalStorage).

---

## **12. Notes**

* “Remember Password” should **never store credentials** in plaintext.
* Prefer **secure, random, short-lived tokens** instead of passwords.
* Always apply `Secure`, `HttpOnly`, and `SameSite` flags to cookies.
* Tokens should expire and be invalidated on password change or logout.
* Client-side data (cookies, localStorage) must not be trusted or decrypted directly.

---
