
## What is Reflected XSS?

**Reflected Cross-Site Scripting (XSS)** is a type of web vulnerability that occurs when an application includes **untrusted user input** directly in its HTTP response **without proper sanitization or encoding**. This allows attackers to inject **malicious JavaScript code** into a webpage, which then runs in the victim’s browser.

Unlike **Stored XSS**, which persists across sessions and users, **Reflected XSS is non-persistent** — it only executes when the victim **clicks a malicious link or submits a crafted request**.

---

## How Reflected XSS Works

### Step-by-Step:

1. **User Input Injection**
   The attacker crafts input containing a malicious JavaScript payload, usually placed in a URL parameter, form field, or HTTP header.

2. **Request Handling**
   The victim is tricked into making a request (e.g., by clicking a link, submitting a form). The server receives the malicious input.

3. **Server Reflection**
   The server reflects that input back into the response **without validation or escaping**. The payload becomes part of the page.

4. **Script Execution**
   The browser renders the page and executes the malicious script in the context of the vulnerable website.

---

## Example: Basic Reflected XSS Attack

### Malicious URL:

```
https://insecure-website.com/search?query=<script>alert('XSS')</script>
```

### Server Response:

```html
<p>You searched for: <script>alert('XSS')</script></p>
```

### Result:

When the victim clicks the link, the `alert()` function is executed in their browser.

---

## Real-World Impact

An attacker who controls the script executed in the victim's browser can:

| Action                 | Description                                                                   |
| ---------------------- | ----------------------------------------------------------------------------- |
| **Session Hijacking**  | Steal session cookies and impersonate the victim                              |
| **Credential Theft**   | Display fake login forms to capture usernames and passwords                   |
| **Account Takeover**   | Use session tokens to fully control user accounts                             |
| **Phishing**           | Redirect users to fake or malicious pages                                     |
| **Page Manipulation**  | Change the appearance or behavior of the page to mislead users                |
| **Malware Delivery**   | Force the browser to download malicious files or connect to malicious domains |
| **Worm-like Behavior** | Auto-distribute the payload to other users via forms, chat inputs, etc.       |

---

## How Attackers Deliver Reflected XSS

Since Reflected XSS doesn’t persist on the server, the **attacker must deliver the malicious request to the victim**. Common delivery methods include:

* Sending a **link via email**, social media, or messaging apps
* Embedding links in **malicious websites**
* Posting links in **user-generated content** (if allowed)
* Using **redirects or iframes** from third-party services

The attack only works when the victim **interacts with the malicious link**.

---

## Reflected XSS in Different Contexts

The **location** where the reflected data appears in the response affects how it can be exploited:

| Context                  | Example                            | Payload Type                     |
| ------------------------ | ---------------------------------- | -------------------------------- |
| HTML Body (between tags) | `<p>...user input...</p>`          | `<script>alert(1)</script>`      |
| HTML Attribute           | `<input value="...user input...">` | `" onfocus=alert(1) autofocus="` |
| JavaScript Context       | `var msg = '...user input...';`    | `' ; alert(1)//`                 |
| URL Context              | `<a href="...user input...">`      | `javascript:alert(1)`            |

---

## Manual Testing for Reflected XSS

### 1. Identify Entry Points

* Parameters in the URL (`GET`)
* Form fields (`POST`)
* URL paths
* Headers (like `Referer`, `User-Agent`, `X-Forwarded-For`)

### 2. Inject Unique Test Strings

Use a random alphanumeric string (e.g., `xssTest88`) to identify reflections.

### 3. Observe Reflections in Response

Check if the test string appears unescaped in the response HTML, attributes, or scripts.

### 4. Determine Context

Identify where the reflection happens — this tells you what type of payload to use.

### 5. Craft and Inject Payload

Based on the context, try a safe test payload like:

```html
<script>alert(document.domain)</script>
```

### 6. Confirm in Browser

Open the crafted link in a browser. If the alert is triggered, XSS is confirmed.

---

## Reflected vs Stored XSS

| Feature                 | Reflected XSS                              | Stored XSS                                         |
| ----------------------- | ------------------------------------------ | -------------------------------------------------- |
| Persistence             | Non-persistent (per-request)               | Persistent (stored in database or backend)         |
| Trigger                 | Requires user to click or interact         | Triggered automatically on page load               |
| Delivery Method         | External (via link, form, etc.)            | Internal (embedded in content served to all users) |
| User Interaction Needed | Yes                                        | No                                                 |
| Common Use Cases        | Search forms, URL previews, error messages | Comments, forums, chat, profiles                   |

---

## Reflected vs Self-XSS

**Self-XSS** is a variation where the user themselves is tricked into executing malicious code by **pasting it into the browser’s developer console**.

| Feature     | Reflected XSS                    | Self-XSS                                 |
| ----------- | -------------------------------- | ---------------------------------------- |
| Delivery    | External (via link or request)   | Requires manual user action (paste code) |
| Exploitable | Remotely exploitable by attacker | Requires social engineering              |
| Severity    | Medium to High                   | Low                                      |

---

## Tools for Detection

* **Burp Suite** (Scanner, Repeater, Intruder)
* **OWASP ZAP**
* Browser DevTools (View source, console)
* Manual payload testing

---

## Summary

| Key Point        | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| What is it?      | Vulnerability where input is reflected and executed in real-time |
| Delivery         | Via malicious links or requests                                  |
| Persistence      | Non-persistent                                                   |
| User Interaction | Required (user must click or trigger the request)                |
| Severity         | Medium–High depending on the target user                         |
| Common Targets   | Search pages, error messages, login redirects                    |
| Protection       | Validate input, encode output, enforce CSP, use security headers |

---
