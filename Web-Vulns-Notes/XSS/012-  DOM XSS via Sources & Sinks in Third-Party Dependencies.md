Modern web applications heavily rely on **third-party JavaScript libraries** and **front-end frameworks** such as jQuery, AngularJS, React, etc. While these libraries simplify development, they also introduce **new attack surfaces**, especially when developers handle user input carelessly.

This write-up focuses on DOM-based XSS vulnerabilities that arise due to **untrusted sources** being passed into **dangerous sinks** exposed by third-party libraries. We’ll take a detailed look at real-world examples using **jQuery**.

---

##  DOM XSS Recap

DOM XSS occurs when **untrusted data from the user (source)** is read and then **written unsafely into the page (sink)** in a way that allows JavaScript execution **inside the browser**, without server involvement.

---

##  DOM XSS in jQuery – Real World Example

jQuery exposes multiple functions that act as **DOM sinks**, such as:

- `.attr()`
- `$() selector`
- `.html()`
- `.append()` / `.prepend()`
- `.val()` (when used inappropriately)

If **user-controlled data** is passed into any of these without proper validation or sanitization, **DOM XSS** becomes a real possibility.

---

##  Example 1: jQuery `.attr()` sink with `window.location.search` source

###  Vulnerable Code:

```js
$(function() {
  $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnUrl'));
});
````

###  What’s Happening?

* Source: `window.location.search`
* Sink: `attr("href", ...)`

The code extracts a `returnUrl` parameter from the URL and sets it as the `href` of a `<a>` element.

###  Exploit:

```text
https://vulnerable.com/?returnUrl=javascript:alert(document.domain)
```

When the user clicks on the back link, the `javascript:` payload is executed. The attacker doesn’t need script tags or event handlers — just a malicious URL.

###  Fixes:

* Whitelist protocols (only allow `https`, `http`)
* Sanitize user input before applying to attributes
* Avoid assigning `javascript:` URLs dynamically

---

##  Example 2: jQuery `$()` sink with `location.hash` source

###  Vulnerable Code:

```js
$(window).on('hashchange', function() {
  var element = $(location.hash);
  element[0].scrollIntoView();
});
```

###  What’s Happening?

* Source: `location.hash`
* Sink: `$()` selector

If `location.hash` is attacker-controlled (e.g., `#<img src=x onerror=alert(1)>`), it will be **directly interpreted as a jQuery selector**, which injects it into the DOM.

This allows injection of malicious HTML/JS if not properly handled.

###  Exploit using an iframe (trigger without interaction):

```html
<iframe src="https://vulnerable.com#" onload="this.src += '<img src=1 onerror=alert(1)>'"></iframe>
```

* The iframe first loads the target page with an empty hash (`#`).
* Then appends a malicious string to the hash (`#<img src=...>`).
* The `hashchange` event is triggered automatically.
* DOM XSS is executed without user interaction.

###  Notes:

* **Modern jQuery versions block HTML injection when the input starts with `#`**.
* But if the developer feeds data without `#`, e.g., `$(userInput)` where input is not a selector but full HTML, the attack still works.

---

##  Key Terms

| Term    | Description                                                                             |
| ------- | --------------------------------------------------------------------------------------- |
| Source  | Where user input comes from (e.g., `location.hash`, `location.search`)                  |
| Sink    | A function that injects that input into the DOM (e.g., `attr()`, `$()`, `.html()`)      |
| DOM XSS | Triggered when untrusted input is written to a sink in a way that leads to JS execution |

---

##  How to Prevent DOM XSS in jQuery

1. **Never trust input from the URL** – sanitize/validate all sources.
2. **Avoid using raw user input in dangerous sinks** like `.html()` or `$()`.
3. Use **safe DOM manipulation** methods (`text()` instead of `html()`, etc.).
4. Enforce **Content Security Policy (CSP)**.
5. Upgrade to modern jQuery and avoid legacy usage patterns.

---

##  References

* [PortSwigger – DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
* [OWASP DOM XSS Guide](https://owasp.org/www-community/attacks/DOM_Based_XSS)
* [jQuery API Docs](https://api.jquery.com/)
