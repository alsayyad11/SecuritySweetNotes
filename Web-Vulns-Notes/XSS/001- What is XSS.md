<img width="795" height="397" alt="image" src="https://github.com/user-attachments/assets/7a494078-fd86-43c7-96bc-f5e15fa7a648" />

## What is XSS?

**Cross-Site Scripting (XSS)** is a web vulnerability that allows an attacker to inject malicious scripts (usually JavaScript) into a website. These scripts are then executed in the browser of another user.

* It is a **client-side vulnerability**.
* The injected script runs in the context of the vulnerable web page.
* Any user who visits the affected page may be impacted.
* It breaks the **Same-Origin Policy**, allowing attackers to act on behalf of other users.
* If the victim is an admin, the attacker could gain full control over the application.

---

## How XSS Works

1. **Injection**
   The attacker submits input that contains malicious JavaScript code, often using form fields, URL parameters, or HTTP headers.

2. **Delivery**
   The application includes this malicious input directly in the server’s response (in unsafe ways) or processes it via JavaScript on the frontend.

3. **Execution**
   When the victim opens the page, the browser automatically executes the script as if it was part of the trusted site.

4. **Result**
   The attacker’s code runs with the same privileges as the website:

   * Can access cookies, localStorage, DOM, and sensitive user data.
   * Can trigger actions or API calls as if it were the user.

---

## Goal of XSS Attacks

The main goal of XSS is to **exploit the browser** and manipulate what the user sees or does. It can also be used to **steal sensitive data** or **gain access** to the system.

| Goal                      | Description                                               |
| ------------------------- | --------------------------------------------------------- |
| Session Hijacking         | Stealing cookies to impersonate the user                  |
| Account Takeover          | Gaining full control over user accounts                   |
| Credential Theft          | Displaying fake login forms to capture credentials        |
| Defacement                | Modifying how the website appears                         |
| Keylogging                | Logging user keystrokes to steal data                     |
| Phishing                  | Redirecting users to fake websites                        |
| Bypassing Access Controls | Performing unauthorized actions as the user               |
| Worm-like Spread          | Injecting scripts that spread automatically between users |

---

## XSS Proof of Concept (PoC)

To confirm an XSS vulnerability, researchers usually inject a simple JavaScript payload like:

```html
<script>alert(1)</script>
```

* This triggers a pop-up if the script is executed.
* It's commonly used because it's harmless, short, and easy to spot.

### Note for Chrome users:

Since **Chrome v92**, `alert()` doesn’t work inside cross-origin iframes.
In those cases, you can use:

```javascript
print()
```

Most labs or challenges (like those from PortSwigger) are updated to support `print()` as well.

---

## XSS Impact

The impact of XSS depends on:

* The type of application (public, sensitive, or admin panel).
* The privileges of the affected user.
* Whether security controls like CSP are in place.

| Scenario                             | Expected Impact                                 |
| ------------------------------------ | ----------------------------------------------- |
| Public site (anonymous users)        | Often minimal, unless used for phishing         |
| Application with sensitive user data | Serious (e.g. bank info, health records, email) |
| Admin user compromised               | Critical — full application takeover possible   |

---

## How to Detect XSS Vulnerabilities

### Manual Testing

1. Inject unique test strings (e.g., `test123`) in input fields or URL parameters.
2. Check where these strings appear in the HTML response or page DOM.
3. Try injecting JavaScript payloads in those places.
4. Based on the output context (HTML body, attribute, script tag, etc.), craft a suitable payload.

### DOM-Based XSS

* Inject a unique string (e.g., `xyz123`) in the URL.
* Open DevTools and search the DOM for it.
* If found, test if JavaScript injection is possible (e.g., via `innerHTML`, `document.write`, etc.).

### Automated Tools

* **Burp Suite Scanner** can detect:

  * Reflected XSS
  * Stored XSS
  * Many DOM-based XSS variants
* Uses both **static** (code analysis) and **dynamic** (runtime behavior) scanning.

---

## How to Prevent XSS

1. **Filter input on arrival**
   Only allow what’s expected (e.g., reject `<`, `>`, quotes, etc.) based on the context.

2. **Encode output properly**
   Use appropriate encoding for the output location:

   * HTML encoding: `&lt;`, `&gt;`, etc.
   * JavaScript encoding
   * URL encoding

3. **Use proper HTTP response headers**

   * `Content-Type: text/plain` or `application/json` if no HTML expected
   * `X-Content-Type-Options: nosniff`

4. **Implement Content Security Policy (CSP)**

   * Acts as a safety net
   * Can block inline scripts, unauthorized domains, etc.

---

## Common Questions

* **Is XSS common?**
  Yes, it's one of the most common web vulnerabilities.

* **Is it often exploited?**
  Not always, but it’s dangerous when it is — especially against high-value targets.

* **XSS vs. CSRF?**
  XSS = attacker runs JS in victim’s browser.
  CSRF = attacker tricks victim into performing actions.

* **XSS vs. SQLi?**
  XSS = affects users (client-side).
  SQLi = affects the server/database (server-side).

* **How to prevent XSS in PHP?**

  * Filter input (whitelist only).
  * Use `htmlentities()` when outputting data.

* **How to prevent XSS in Java?**

  * Filter/validate input.
  * Use libraries like Google Guava or custom HTML encoders.

---
