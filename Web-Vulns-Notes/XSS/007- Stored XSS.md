### What is Stored XSS?

**Stored XSS**, also known as **Persistent** or **Second-Order XSS**, occurs when an attacker is able to inject malicious JavaScript into a web application, and that code gets **stored** on the server (e.g., in a database or file system) and is later served to other users **without proper sanitization**.

Unlike **Reflected XSS**, where the payload is reflected immediately in the response, **Stored XSS lives inside the application** and is executed **whenever** a user loads the affected content.

---

### Real-life Scenario:

Imagine a website allows users to post comments under blog articles. The user submits their comment like this:

```http
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded

postId=3&comment=Nice+post!&name=Ali&email=ali@example.com
```

The server stores that comment in the database. Then, when someone views the blog post, they see:

```html
<p>Nice post!</p>
```

Now, suppose an attacker submits the following:

```html
<script>alert('XSS')</script>
```

When another user loads the blog post, the comment is rendered as:

```html
<p><script>alert('XSS')</script></p>
```

The script **executes automatically** in the user’s browser.

---

### How Stored XSS Works – Step-by-Step

1. **Injection**
   The attacker submits malicious data (JavaScript code) through a form or endpoint.

2. **Storage**
   The application stores the input in a persistent location like a database or log file **without sanitizing it**.

3. **Retrieval**
   Another user visits a page that retrieves and displays this data.

4. **Execution**
   The stored payload is delivered inside the HTML response and executed by the user’s browser.

---

### Impact of Stored XSS

If the attacker’s script is executed inside a victim’s browser, they can:

* Hijack the victim’s session (steal cookies or tokens)
* Steal sensitive information
* Modify content of the page
* Perform actions on behalf of the victim
* Spread the attack to other users (like a **worm**)

Stored XSS is particularly **dangerous** in apps where users are authenticated or have access to sensitive information, such as:

* Admin dashboards
* Messaging systems
* E-commerce profiles
* Customer support systems

---

### Key Difference from Reflected XSS

| Feature             | Reflected XSS                       | Stored XSS                                |
| ------------------- | ----------------------------------- | ----------------------------------------- |
| Payload Location    | Comes from the request (URL, etc.)  | Comes from server storage (DB, files...)  |
| Requires User Click | Yes                                 | No                                        |
| Persistence         | Temporary (only when user clicks)   | Persistent (remains stored until deleted) |
| Attack Vector       | External (email, link, phishing...) | Internal (stored inside the app)          |
| Risk Level          | Medium                              | High                                      |

---

### Where Stored XSS Might Be Found

* Blog comment sections
* User profile names or bios
* Product reviews
* Chat messages
* Admin logs
* Support tickets

---

### How to Find Stored XSS

Manual testing usually includes:

1. **Submit a test payload** into any input fields (e.g., `<script>alert('XSS')</script>`).
2. **Monitor** other pages where this input might be rendered.
3. If the input appears unescaped in a response, and the script is executed, it’s vulnerable.

Automated tools like **Burp Suite**, **ZAP**, or **Nuclei** can also help find stored XSS, but manual confirmation is essential.

---

### Example (Vulnerable)

#### Comment Form Submission

```html
<form method="POST" action="/comment">
  <input name="name">
  <textarea name="comment"></textarea>
  <button type="submit">Post Comment</button>
</form>
```

#### Displaying Comments (Vulnerable Code)

```php
echo "<p>" . $_POST['comment'] . "</p>";
```

If the input was:

```html
<script>alert('XSS')</script>
```

The output becomes:

```html
<p><script>alert('XSS')</script></p>
```

...which gets executed immediately in the browser.

---

### Summary

| Element       | Description                                                               |
| ------------- | ------------------------------------------------------------------------- |
| Vulnerability | User-controlled input is stored and rendered without escaping             |
| Danger        | Auto-executed malicious JavaScript affects all users who view the content |
| Entry Points  | Any form or field where users submit text that is stored                  |
| Exit Points   | Any page or component that displays stored user input                     |
| Mitigation    | Sanitize input, encode output, use CSP, and secure frameworks             |

---
