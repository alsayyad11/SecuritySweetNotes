## What is DOM-Based XSS?

**DOM-Based Cross-Site Scripting (XSS)** is a type of XSS vulnerability that happens **entirely on the client-side** (inside the browser) without involving a server-side response that reflects the input directly.

It occurs when **data from an untrusted source (like the URL or local storage)** is **read by JavaScript** and then **written to the DOM in an unsafe way**, allowing attackers to inject malicious scripts.

---

## Data Flow in DOM XSS

To understand DOM XSS, you need to think in terms of:

* **Source**: Where the data comes from (e.g., `location.href`, `document.referrer`, `location.hash`, etc.)
* **Sink**: Where the data ends up (e.g., `innerHTML`, `document.write()`, `eval()`, etc.)

> When untrusted input flows from a **source** to a **sink** without sanitization or validation, it may lead to DOM XSS.

---

## Common DOM XSS Sources

These are typical sources where an attacker can inject data:

* `location.href`
* `location.search`
* `location.hash`
* `document.referrer`
* `document.URL`
* `document.cookie`
* `window.name`
* `localStorage`
* `sessionStorage`

---

## Common DOM XSS Sinks

These are functions or properties that can **execute or render malicious scripts** if untrusted data reaches them:

### Pure JavaScript Sinks

* `element.innerHTML`
* `element.outerHTML`
* `document.write()`
* `document.writeln()`
* `element.insertAdjacentHTML()`
* `element.onevent = ...` (like `onclick`, `onerror`)
* `eval()`
* `Function()`
* `setTimeout(string)`
* `setInterval(string)`

### jQuery Sinks

These jQuery functions can introduce DOM XSS if untrusted input is passed:

* `html()`
* `append()`
* `prepend()`
* `before()`
* `after()`
* `wrap()`
* `wrapInner()`
* `replaceWith()`
* `replaceAll()`
* `add()`
* `insertAfter()`
* `insertBefore()`
* `animate()`
* `jQuery.parseHTML()`
* `$.parseHTML()`
* `constructor()`
* `init()`
* `index()`
* `has()`

---

## Example: Dangerous Use of `innerHTML`

```javascript
const comment = {
  author: '<img src=x onerror=alert("XSS")>'
};
element.innerHTML = comment.author; // Vulnerable sink
```

If the input is not sanitized, the browser will render the malicious tag and execute the script.

---

## Stored DOM XSS

In **Stored DOM XSS**, the attacker’s input is **stored on the server**, but the actual execution still happens in the **browser via a DOM sink**.

### Example Flow:

1. Attacker submits malicious input:
   `POST /add_comment` → payload: `<img src=0 onerror=alert(1)>`
2. Server stores the comment in DB.
3. Later, the page fetches the comment and injects it into the page using:

   ```javascript
   commentContainer.innerHTML = comment.author;
   ```
4. The malicious code gets executed when viewed by any user.

> So even though it's **stored** on the server, the **execution happens on the client via DOM manipulation**, making it a **stored DOM XSS**.

---

## Escaping Gone Wrong

Many developers try to **escape special characters**, but do it incorrectly.

### Incorrect Escape Example:

```javascript
function escapeHTML(html) {
    return html.replace('<', '&lt;').replace('>', '&gt;');
}
```

This only replaces **the first occurrence** of `<` and `>`, not all.

### Bypass:

```html
<><img src=0 onerror=alert(1)>
```

The first `<` and `>` are replaced, but the second set is not, so the image tag remains functional and the payload executes.

---

## Proper Mitigation

To prevent DOM XSS:

### 1. Avoid Using Dangerous Sinks

Never use `.innerHTML`, `.outerHTML`, `document.write()`, etc., with untrusted input. Prefer safer alternatives like:

* `textContent`
* `setAttribute()` for properties
* `createTextNode()`

### 2. Sanitize Input Properly

If you **must** use innerHTML, then **sanitize** the input using robust libraries like:

* [DOMPurify](https://github.com/cure53/DOMPurify)
* [sanitize-html](https://github.com/apostrophecms/sanitize-html)

### 3. Escape Properly

If you want to escape input manually, do it completely:

```javascript
function escapeHTML(html) {
  return html
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
```

---

## Summary 

| Type              | Source Example        | Sink Example           | Mitigation                      |
| ----------------- | --------------------- | ---------------------- | ------------------------------- |
| Reflected DOM XSS | `location.hash`       | `innerHTML`            | Use `textContent`               |
| Stored DOM XSS    | server-stored comment | `insertAdjacentHTML()` | Use sanitizers like DOMPurify   |
| jQuery-based      | URL param in `html()` | `$(...).html(...)`     | Use `.text()` or validate input |

