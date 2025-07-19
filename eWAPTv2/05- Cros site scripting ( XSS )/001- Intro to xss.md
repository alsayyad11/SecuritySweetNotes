<img width="1032" height="544" alt="11a5af1828f848fa85dfcd48cf82b65e" src="https://github.com/user-attachments/assets/38a859ef-7604-4657-85bc-d32810efa85d" />

##  What is XSS?

**Cross-Site Scripting (XSS)** is a **client-side vulnerability** that allows attackers to inject **malicious scripts** into web applications. These scripts are executed in the **victim’s browser**, not on the server.

The goal of XSS is usually to **steal data**, **manipulate web content**, or **interact with the user’s session** without permission.

---

##  Why Is XSS Dangerous?

Because the browser **trusts the content coming from the website**, when malicious scripts are injected, the browser executes them as if they were part of the legitimate application.

If the attacker’s script runs in your session:

* It can **steal your cookies**
* Imitate your actions
* Log your keystrokes
* Display fake interfaces (phishing)
* Even gain access to sensitive information

---

##  Why Does XSS Happen?

XSS usually happens due to **improper handling of untrusted input**.
When a web application:

1. Accepts input from the user,
2. Fails to **sanitize or encode** that input,
3. Then reflects or stores it into the HTML output...

...the browser will treat the input as **code**, not as plain text.

Example:

```html
<input name="name" value="<script>alert('XSS')</script>">
```

Without proper encoding, this script will run when the page loads.

---

##  What Technologies Are Affected?

XSS is typically exploited through:

* **JavaScript** (most common)
* HTML and the DOM
* CSS and inline styles
* Flash and other client-side technologies (deprecated, but still seen in legacy apps)

---

##  What Do Attackers Use XSS For?

Here are some real-world motivations:

| Goal                     | Description                                               |
| ------------------------ | --------------------------------------------------------- |
| **Session Hijacking**    | Stealing cookies or session tokens to impersonate users   |
| **Phishing**             | Displaying fake login forms or popups                     |
| **Keylogging**           | Capturing everything the user types                       |
| **Browser Exploitation** | Triggering browser vulnerabilities to gain further access |
| **Data Theft**           | Accessing form inputs, personal data, etc.                |
| **Malicious Redirects**  | Forcing the user to visit attacker-controlled sites       |

---

##  Types of XSS

XSS can be classified into **three primary categories** based on how the payload is delivered and executed.

---

### 1️- Stored XSS (Persistent)

####  Overview:

* The malicious payload is **stored** on the server (e.g., in a database).
* When other users access the affected page, the script is **automatically executed** in their browser.

####  Example Scenario:

* Attacker posts a comment containing a malicious `<script>` tag.
* The comment is saved to the database.
* Any user visiting that page triggers the script in their browser.

####  Attack Flow:

```
Attacker → submits malicious input (e.g., in a comment)
↓
Web app → stores it in DB without sanitization
↓
Victim → opens the page
↓
Browser → executes the malicious script
↓
Attacker → receives stolen session/cookie/data
```

####  Common Targets:

* Blogs, forums, admin panels, message boards, product reviews

---

### 2️- Reflected XSS (Non-Persistent)

####  Overview:

* The payload is **reflected** immediately in the server’s response.
* It is not stored on the server.
* The attacker must convince the victim to click a **crafted malicious URL**.

####  Example Scenario:

* Attacker sends a victim a link like:

  ```
  https://example.com/search?q=<script>steal()</script>
  ```
* The search page reflects the `q` parameter directly in the HTML without filtering.
* The victim’s browser executes the script as part of the response.

####  Attack Flow:

```
Attacker → crafts malicious URL
↓
Victim → clicks the URL
↓
Web app → reflects the payload in response
↓
Browser → executes the script
↓
Attacker → gains access to user data/session
```

####  Common Targets:

* Search forms, error messages, status alerts, login errors

---

### 3️- DOM-Based XSS (Client-Side Only)

####  Overview:

* The vulnerability exists in **client-side JavaScript code**.
* The malicious input is handled directly by the browser — the **server is not involved** in injecting or reflecting the payload.

####  Example Scenario:

* A single-page application reads `document.location.hash` or `window.location.search` and writes it into the DOM using `innerHTML` or similar unsafe functions.

* Attacker sends:

  ```
  https://example.com/#<script>steal()</script>
  ```

* The app’s JS reads the hash and inserts it into the page **without sanitization**.

####  Attack Flow:

```
Attacker → crafts a URL with payload in fragment/query
↓
Victim → visits the page
↓
JavaScript → reads and injects untrusted data into DOM
↓
Browser → executes the script
↓
Attacker → collects stolen data
```

####  Common Targets:

* SPAs (Single Page Applications), AJAX-powered apps, dynamic front-ends using frameworks like React, Vue, Angular (when insecurely configured)

---
