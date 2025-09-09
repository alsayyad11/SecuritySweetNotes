
## 1. Introduction to Encoding

### What is Encoding?

Encoding is the process of **transforming data into a different representation** so that it can be:

* **Safely stored** in databases.
* **Transmitted** over the internet without corruption.
* **Interpreted correctly** by computers, servers, and browsers.

Encoding is not about security by itself — its purpose is **compatibility and correctness**.
But in security testing, understanding encoding is critical because:

* Attackers often encode payloads to bypass filters.
* Web applications sometimes fail to decode/normalize data properly, leading to vulnerabilities.

---

### Encoding vs Encryption vs Hashing

* **Encoding** → Change format for transport/display. Example: `"<"` → `"&lt;"`.
* **Encryption** → Protect confidentiality using a secret key. Example: AES encryption.
* **Hashing** → One-way transformation for integrity. Example: SHA-256 hash of a password.

---

## 2. HTML Encoding

### What is HTML Encoding?

HTML encoding (also called **HTML entity encoding**) converts special characters into **HTML entities** so that browsers:

* Display them as text.
* Don’t interpret them as HTML/JavaScript code.

This is essential to prevent **XSS (Cross-Site Scripting)**.

---

### How HTML Entities Work

* Entities start with `&` and end with `;`.
* Example:

  * `<` → `&lt;`
  * `>` → `&gt;`
  * `&` → `&amp;`

---

### Example 1: Displaying Script Tags

```html
<p>User input: <script>alert('XSS')</script></p>
```

If inserted directly, this runs JavaScript (bad).

Encoded version:

```html
<p>User input: &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
```

Now it shows `<script>alert('XSS')</script>` as text — not code.

---

### Example 2: Showing Special Characters

* `Tom & Jerry` → Encoded: `Tom &amp; Jerry`
* `"Hello"` → Encoded: `&quot;Hello&quot;`

---

### Why It Matters in Security

* Prevents **user input** from being executed as HTML/JS.
* Helps developers sanitize output safely.

---

## 3. URL Encoding (Percent-Encoding)

<img width="1087" height="369" alt="S" src="https://github.com/user-attachments/assets/ac6fb6db-13e0-4726-981f-1f48c7fbc408" />


### What is URL Encoding?

URLs can only contain a **restricted set of characters** (letters, digits, and a few symbols).
Unsafe characters are replaced with `%` followed by their **ASCII hex value**.

---

### Rules

* **Unreserved characters** (safe, no need to encode):
  `a-z, A-Z, 0-9, -, ., _, ~`

* **Reserved characters** (have special meaning):
  `: / ? # [ ] @ ! $ & ' ( ) * + , ; = %`

If you want to send them as **data**, you must encode them.

---

### Example 1: Encoding a Space

* Original:

  ```
  http://example.com/search?query=hello world
  ```
* Encoded:

  ```
  http://example.com/search?query=hello%20world
  ```

---

### Example 2: Encoding HTML in a URL

* Original:

  ```
  http://example.com/search?query=<script>alert(1)</script>
  ```
* Encoded:

  ```
  http://example.com/search?query=%3Cscript%3Ealert(1)%3C/script%3E
  ```

---

### How Browsers Handle URL Encoding

* Modern browsers (Chrome, Firefox, Opera): automatically encode unsafe characters.
* Older Internet Explorer: sometimes sends raw characters, which attackers could exploit.

---

### Why It Matters in Security

* Attackers can use **encoded payloads** to bypass weak filters.
* Example: If a filter blocks `<script>`, an attacker might try `%3Cscript%3E`.
* Double-encoding (e.g., `%253C` → `%3C` → `<`) is a common evasion technique.

---

## 4. Base64 Encoding

### What is Base64?

Base64 encodes **binary data** (images, files, audio) into **text form**.
Why? Because some systems (like HTML, JSON, or email) only accept text.

---

### How Base64 Works

1. Take **3 bytes** (24 bits) of binary data.
2. Split into **4 groups of 6 bits**.
3. Map each group to a character from the Base64 alphabet.
4. If data isn’t divisible by 3, add `=` padding.

---

### Base64 Alphabet

* `A-Z` → 26 characters
* `a-z` → 26 characters
* `0-9` → 10 characters
* `+` and `/` → 2 characters
  \= 64 characters total

---

### Example: Encoding "Hi"

1. "H" = 72 → Binary: `01001000`
   "i" = 105 → Binary: `01101001`

Combined = `01001000 01101001`

2. Add padding to make 24 bits:
   `01001000 01101001 00000000`

3. Split into 6-bit chunks:
   `010010 000110 100100 000000`

4. Map to Base64 table: `SGk=`

So, `"Hi"` → `"SGk="`.

---

### Example: Embedding an Image

Instead of linking an image file:

```html
<img src="logo.png" />
```

We can embed it directly:

```html
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg..." />
```

---

### Use Cases

* **Email attachments** → binary files converted to Base64 text.
* **JWT tokens** → JSON Web Tokens use Base64 to encode header & payload.
* **Data URLs** → embed small images directly in HTML/CSS.

---

### Why It Matters in Security

* Attackers may encode payloads in Base64 to **hide malicious input**.
* Example: An XSS payload `<script>alert(1)</script>` → Base64: `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`
  If the app decodes it later, the payload executes.

---

## 5. Checklist for Encoding

When testing a web application, always check:

* **HTML Encoding**

  * Does the app correctly encode `<`, `>`, `"`, `'`, and `&`?
  * Can you bypass output encoding using double-encoding?

* **URL Encoding**

  * Try `%3Cscript%3E` instead of `<script>`.
  * Test double-encoding: `%253Cscript%253E`.
  * Check if filters only block raw characters.

* **Base64 Encoding**

  * Look for parameters that accept Base64 input.
  * Decode suspicious Base64 strings in requests/responses.
  * Try injecting payloads inside Base64 data (e.g., JWT header/payload).

---


* **HTML Encoding** protects web content from being misinterpreted as HTML or JS.
* **URL Encoding** makes URLs safe and reliable across browsers/servers.
* **Base64 Encoding** makes binary data usable in text-based systems.

From a **security testing perspective**, encoding is a **double-edged sword**:

* It protects apps when used properly.
* It becomes a weapon when attackers use encoding tricks to bypass filters.
