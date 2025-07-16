### 1. **Output Encoding (Escaping)**

Make sure any user-generated content is **encoded properly before it’s inserted into the HTML**. This is your most important defense.

#### Example (in HTML context):

If a user submits:

```html
<script>alert(1)</script>
```

You should **not render this directly**. Instead, you must encode it like:

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

#### Use safe encoding functions:

* **In PHP**:

  ```php
  echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
  ```
* **In JavaScript (for DOM)**:
  Avoid using `.innerHTML` — instead, use `.textContent`:

  ```js
  element.textContent = userInput;
  ```

---

### 2. **Use Safe JavaScript APIs**

Avoid APIs like:

* `innerHTML`
* `document.write`
* `eval`
* `setTimeout`/`setInterval` with strings

✅ Use:

* `textContent`
* `setAttribute`
* `createElement`

---

### 3. **Input Validation (optional, not a substitute)**

While encoding is the primary defense, **basic input validation** can help reduce risks.

* Accept only expected formats:

  * Emails: `^[\w.-]+@[\w.-]+\.\w{2,}$`
  * Names: letters only
* Reject characters like `<`, `>`, `'`, `"`, etc. **if they're not needed**.

**Important**: Validation is not enough by itself. Encoding is still required.

---

### 4. **Use Templating Engines That Auto-Escape**

Frameworks and templating systems like:

* **React.js**
* **Django templates**
* **Mustache / Handlebars**
* **Twig (PHP)**

automatically escape output, unless you explicitly disable it.

---

### 5. **HTTP Security Headers**

#### Content Security Policy (CSP)

Set a strict CSP to **limit where scripts can come from** and block inline scripts.

```http
Content-Security-Policy: default-src 'self'; script-src 'self'
```

> This helps mitigate XSS even if some HTML is improperly rendered.

#### Other useful headers:

```http
X-Content-Type-Options: nosniff
X-XSS-Protection: 0  (modern browsers ignore this, rely on CSP instead)
```

---

### 6. **Sanitize HTML if Rich Input Is Allowed**

If you allow rich text (like blog posts or comments), you need to **sanitize it safely**.

Use libraries that remove dangerous tags and attributes:

* **JavaScript**: DOMPurify
* **Python**: bleach
* **PHP**: HTML Purifier

#### Example using DOMPurify:

```js
const cleanHTML = DOMPurify.sanitize(userInput);
element.innerHTML = cleanHTML; // Safe
```

---

## Summary 

| Technique               | Purpose                                 | Notes                          |
| ----------------------- | --------------------------------------- | ------------------------------ |
| Output Encoding         | Escape untrusted input before rendering | Most important defense         |
| Safe DOM APIs           | Prevent script injection                | Avoid innerHTML and eval       |
| Input Validation        | Reduce risk of invalid input            | Not a replacement for encoding |
| Templating Engines      | Auto-escape output                      | Use secure frameworks          |
| Content Security Policy | Limit where scripts run from            | Helps mitigate impact of XSS   |
| HTML Sanitization       | Clean rich input like blog comments     | Use trusted libraries          |

---

