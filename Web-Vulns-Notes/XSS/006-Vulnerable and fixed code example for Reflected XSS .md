
## 1. Vulnerable HTML Page (Reflected XSS)

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Vulnerable Search Page</title>
</head>
<body>
  <h1>Search Page</h1>

  <!-- Search form -->
  <form method="GET" action="">
    <input type="text" name="term" placeholder="Type something..." />
    <button type="submit">Search</button>
  </form>

  <hr>

  <div id="results"></div>

  <script>
    // Get "term" value from the URL
    const params = new URLSearchParams(window.location.search);
    const term = params.get("term");

    if (term) {
      // Vulnerable reflection without sanitization
      const resultsDiv = document.getElementById("results");
      resultsDiv.innerHTML = `<p>You searched for: ${term}</p>`;
    }
  </script>
</body>
</html>
```

### Why this code is vulnerable

**1. Input is taken directly from the URL without validation**

```javascript
const term = params.get("term");
```

The code retrieves the value of the `term` parameter directly from the URL query string. For example:

```
?term=<img src=x onerror=alert(1)>
```

**2. User input is inserted into the page using `innerHTML`**

```javascript
resultsDiv.innerHTML = `<p>You searched for: ${term}</p>`;
```

The `innerHTML` property allows the inserted content to be interpreted as real HTML. If the user input contains a script, it will be executed immediately by the browser.

**3. Result**

If the input is something like `<script>alert(1)</script>`, the page will return:

```html
<p>You searched for: <script>alert(1)</script></p>
```

This script will execute when the page loads, causing a reflected XSS vulnerability.

---

## 2. Fixed (Secure) HTML Page

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Safe Search Page</title>
</head>
<body>
  <h1>Search Page</h1>

  <!-- Safe Search form -->
  <form method="GET" action="">
    <input type="text" name="term" placeholder="Type something..." />
    <button type="submit">Search</button>
  </form>

  <hr>

  <div id="results"></div>

  <script>
    // Get "term" value from the URL
    const params = new URLSearchParams(window.location.search);
    const term = params.get("term");

    if (term) {
      const resultsDiv = document.getElementById("results");

      // Safely display user input as plain text
      const p = document.createElement("p");
      p.textContent = `You searched for: ${term}`;
      resultsDiv.appendChild(p);
    }
  </script>
</body>
</html>
```

### Why this code is secure

**1. Input is still read from the URL**

```javascript
const term = params.get("term");
```

Same as before, the code retrieves the user input from the URL.

**2. The value is inserted using `textContent`**

```javascript
p.textContent = `You searched for: ${term}`;
```

This is the key difference. `textContent` treats everything as plain text, so HTML or JavaScript characters are not interpreted. For example, if the input is:

```
<script>alert(1)</script>
```

It will be displayed exactly as text on the page:

```
You searched for: <script>alert(1)</script>
```

But it will not be executed, because the browser does not treat it as code.

**3. DOM API is used safely**

```javascript
const p = document.createElement("p");
resultsDiv.appendChild(p);
```

The element is created and inserted using the DOM API, not through unsafe string concatenation.

---

### Summary

| Version    | Behavior                                                          | Secure? |
| ---------- | ----------------------------------------------------------------- | ------- |
| Vulnerable | Inserts raw user input using `innerHTML`, executes scripts        | No      |
| Fixed      | Uses `textContent` to treat input as plain text, avoids execution | Yes     |

