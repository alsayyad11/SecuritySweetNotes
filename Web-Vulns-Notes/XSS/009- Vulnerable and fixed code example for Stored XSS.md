
##  Vulnerable Stored XSS Example

```html
<!-- vulnerable-stored-xss.html -->
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Vulnerable Comment Page</title>
</head>
<body>
  <h2>Leave a Comment</h2>
  <form id="commentForm">
    <input type="text" id="comment" placeholder="Your comment" required>
    <button type="submit">Submit</button>
  </form>

  <h3>Comments:</h3>
  <div id="commentsSection"></div>

  <script>
    const form = document.getElementById('commentForm');
    const commentInput = document.getElementById('comment');
    const commentsSection = document.getElementById('commentsSection');

    // Load and render comments from localStorage
    const comments = JSON.parse(localStorage.getItem('comments') || '[]');
    comments.forEach(c => {
      commentsSection.innerHTML += `<p>${c}</p>`; // ❌ UNSAFE: Direct HTML injection
    });

    // Handle form submission
    form.onsubmit = (e) => {
      e.preventDefault();
      const newComment = commentInput.value;

      comments.push(newComment);
      localStorage.setItem('comments', JSON.stringify(comments));
      location.reload(); // Refresh to display the new comment
    };
  </script>
</body>
</html>
```

###  Why this is vulnerable:

* It uses `innerHTML` to insert user input directly into the page:

  ```js
  commentsSection.innerHTML += `<p>${c}</p>`;
  ```
* If an attacker submits this payload:

  ```html
  <img src=x onerror=console.log('XSS triggered')>
  ```

  it will be stored in `localStorage` and later injected into the page as:

  ```html
  <p><img src=x onerror=console.log('XSS triggered')></p>
  ```
* The script will execute whenever the page is loaded by **any user**, making it a **Stored XSS attack**.
* In modern Chrome, `alert()` might be blocked inside iframes, so `console.log()` or `print()` is recommended in simulation.

---

##  Fixed (Sanitized) Stored XSS Example

```html
<!-- fixed-stored-xss.html -->
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Secure Comment Page</title>
</head>
<body>
  <h2>Leave a Comment</h2>
  <form id="commentForm">
    <input type="text" id="comment" placeholder="Your comment" required>
    <button type="submit">Submit</button>
  </form>

  <h3>Comments:</h3>
  <div id="commentsSection"></div>

  <script>
    const form = document.getElementById('commentForm');
    const commentInput = document.getElementById('comment');
    const commentsSection = document.getElementById('commentsSection');

    // Escape HTML special characters to prevent XSS
    function escapeHTML(str) {
      return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    const comments = JSON.parse(localStorage.getItem('comments') || '[]');
    comments.forEach(c => {
      const safeComment = escapeHTML(c); //  Encoding input
      const p = document.createElement('p');
      p.textContent = safeComment; //  Inserting as plain text
      commentsSection.appendChild(p);
    });

    form.onsubmit = (e) => {
      e.preventDefault();
      const newComment = commentInput.value;

      comments.push(newComment);
      localStorage.setItem('comments', JSON.stringify(comments));
      location.reload();
    };
  </script>
</body>
</html>
```

###  Why this is secure:

* It sanitizes user input using a custom `escapeHTML()` function, converting dangerous characters like `<`, `>`, `'`, and `"` into safe equivalents.

  ```js
  const safeComment = escapeHTML(c);
  ```
* It uses `textContent` to insert the comment into the page, which treats the text as plain text, **not HTML**.

  ```js
  p.textContent = safeComment;
  ```
* Even if an attacker submits this:

  ```html
  <img src=x onerror=console.log('XSS')>
  ```

  it will be stored and displayed as:

  ```html
  &lt;img src=x onerror=console.log('XSS')&gt;
  ```

  So the code will **not execute**, only show as text.

---
