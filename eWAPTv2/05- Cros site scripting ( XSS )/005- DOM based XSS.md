<img width="1454" height="560" alt="Screenshot 2025-07-21 100545" src="https://github.com/user-attachments/assets/a18687b3-ab60-469a-97aa-a1c342e0cc14" />

##  What is the DOM?

**DOM** stands for **Document Object Model**.
It’s a **programming interface** provided by the browser that allows JavaScript to interact with and modify the structure, style, and content of a web page dynamically.

Think of the DOM as a **tree-like structure** representing every HTML element on the page. For example:

```html
<html>
  <body>
    <h1>Hello</h1>
    <script>
      document.body.innerHTML = "Hi there!";
    </script>
  </body>
</html>
```

Here, `document.body` is part of the DOM. JavaScript can use it to change the page content, structure, or behavior.

---

## What is DOM-based XSS?

**DOM XSS** is a type of Cross-Site Scripting attack that happens **entirely on the client side**, without any change to the HTTP response from the server.

* In **Reflected XSS**, the malicious input is sent to the server and reflected back in the HTML.
* In **Stored XSS**, the input is stored on the server and served to users later.
* But in **DOM XSS**, the malicious input is **not processed by the server at all**. Instead, it's handled **directly by JavaScript in the browser**.

### Example:

Let's say we have the following URL:

```
https://example.com/#username=ahmed
```

And this JavaScript code:

```javascript
let username = location.hash.substring(10);
document.getElementById("welcome").innerHTML = "Hello " + username;
```

If an attacker sends:

```
https://example.com/#username=<img src=x onerror=alert(1)>
```

Then the page will render:

```html
<div id="welcome">Hello <img src=x onerror=alert(1)></div>
```

The JavaScript **injected through the DOM** will execute immediately – **without any server-side interaction**. That's DOM XSS.

---

##  Dangerous Sources and Sinks

###  Common **Sources** (where untrusted data can come from):

These are DOM properties where user input may enter the application:

* `location.hash`
* `location.search`
* `location.href`
* `document.URL`
* `document.documentURI`
* `document.referrer`
* `window.name`

---

###  Common **Sinks** (dangerous places to insert untrusted data):

These are functions or properties that can **execute** or **render** JavaScript. If user-controlled data reaches one of them, XSS is possible:

| Sink Function            | Description                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| `eval()`                 | Executes a string as code (very dangerous)                        |
| `setTimeout()`           | If passed a string, executes it as code                           |
| `setInterval()`          | Same as above                                                     |
| `Function()`             | Similar to `eval`, creates new functions from strings             |
| `document.write()`       | Directly writes HTML into the page                                |
| `element.innerHTML`      | Renders raw HTML inside the element                               |
| `element.outerHTML`      | Replaces the whole element with HTML                              |
| `location`               | Redirecting the browser to a URL                                  |
| `element.setAttribute()` | If used with `on*` attributes like `onclick`, it can execute code |

---

##  Real-World DOM XSS Example

### Example JavaScript:

```javascript
let q = new URLSearchParams(location.search).get('q');
document.getElementById("result").innerHTML = q;
```

If you open:

```
https://vulnerable.com/?q=<script>alert(1)</script>
```

The page will run the `alert` script. **No server is involved.** The page just reads the URL and writes the value into the DOM using `innerHTML`.

---

##  Safe Example:

```javascript
let username = new URLSearchParams(location.search).get('user');
document.getElementById("welcome").textContent = "Hello " + username;
```

Using `textContent` ensures no code will execute, even if the user input contains `<script>` tags.

---


### DOM XSS HackerOne Reports

| Vulnerability & Company                                    | Description                                                                                | Report ID                                                        |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- |
| **Grab / parcel.grab.com – DOM XSS via fragment**          | Client-side script reads `location.hash` unsafely and injects it into the DOM, causing XSS | [#248560](https://hackerone.com/reports/248560)  |
| **MyCrypto – DOM XSS in "connected successfully" message** | The success message prints unfiltered input from URL, leading to XSS                       | [#324303](https://hackerone.com/reports/324303) |
| **Uber – DOM XSS via PrettyPhoto plugin**                  | Vulnerable plugin on eng.uber.com allows execution via crafted input                       | [#125498](https://hackerone.com/reports/125498)  |
| **SecNews – Search page DOM XSS**                          | Search query inserted into HTML without proper encoding, enabling DOM XSS                  | [#168165](https://hackerone.com/reports/168165)  |
| **DuckDuckGo – DOM XSS on 50x.html**                       | `location.search` is inserted via `innerHTML` into error page, triggering XSS              | [#405191](https://hackerone.com/reports/405191)  |
| **HackerOne – Self DOM XSS in contact form**               | The contact form on hackerone.com reads user input and injects it without sanitization     | [#406587](https://hackerone.com/reports/406587)  |

---
