
![a](https://github.com/user-attachments/assets/8834c17f-29b0-47e9-bc40-518b29dc7b5b)

## 1. What is `curl`?

`curl` stands for **Client URL**. It is a command-line tool that allows you to send and receive data using many different protocols. The most common one is **HTTP/HTTPS**, which makes `curl` extremely useful for web application testing, penetration testing, and API interaction.

Unlike a browser (which automatically renders HTML, loads images, and executes JavaScript), `curl` shows you the **raw request and response**. This makes it an essential tool for **debugging, automation, and security testing**.

Think of `curl` as a **browser without a graphical interface** — you control exactly what request is sent, what headers are included, and how the response is returned.

---

## 2. Why Security Testers Use `curl`

For penetration testers and developers, `curl` is valuable because:

* You can craft custom requests by changing methods, headers, and payloads.
* You can inspect server responses such as headers, status codes, and cookies.
* You can test authentication and session handling by adding tokens or cookies.
* You can reproduce requests captured in tools like Burp Suite or browser dev tools.
* You can attempt method tampering attacks by switching between GET, POST, PUT, DELETE, etc.
* It is available by default in Linux and macOS, and easily installed in Windows.

---

## 3. Basic Usage of `curl`

The simplest form:

```bash
curl https://example.com
```

This sends a **GET request** to `https://example.com` and shows the raw HTML response.

Example output:

```html
<!doctype html>
<html>
<head><title>Example Domain</title></head>
<body>
  <h1>Example Domain</h1>
</body>
</html>
```

This is equivalent to typing the URL in your browser, but instead of rendering, it prints the HTML source.

---

## 4. Using Different HTTP Methods with `curl`

### GET (default)

```bash
curl https://example.com/users/123
```

* Sends a GET request.
* Used for retrieving data.

---

### POST (sending data)

```bash
curl -X POST https://example.com/login \
  -d "username=admin&password=secret"
```

* `-X POST` sets the method.
* `-d` sends data in the body.
* Useful for testing login forms and data submission.

Possible server response:

```json
{ "message": "Login successful", "token": "abcd1234" }
```

---

### PUT (update resource)

```bash
curl -X PUT https://example.com/users/123 \
  -H "Content-Type: application/json" \
  -d '{"email":"newmail@example.com"}'
```

* Updates user with new email.
* Commonly used in REST APIs.

---

### DELETE (remove resource)

```bash
curl -X DELETE https://example.com/users/123
```

* Deletes user `123`.
* Dangerous if authorization is not implemented correctly.

---

### OPTIONS (check allowed methods)

```bash
curl -X OPTIONS -i https://example.com/users
```

* `-i` includes headers in the response.
* Used to discover supported methods.

Example response:

```
HTTP/1.1 200 OK
Allow: GET, POST, PUT, DELETE, OPTIONS
```

If `DELETE` is listed where it should not be, it indicates a potential security issue.

---

## 5. Adding Headers with `curl`

Applications often require headers such as **Content-Type, Authorization, User-Agent, and Cookies**.

### Example: Adding a custom User-Agent

```bash
curl -A "MyCustomAgent/1.0" https://example.com
```

### Example: Sending an Authorization token

```bash
curl -H "Authorization: Bearer abcd1234" https://example.com/profile
```

### Example: Sending Cookies

```bash
curl -b "sessionid=xyz123" https://example.com/dashboard
```

This is crucial for testing authenticated endpoints.

---

## 6. Inspecting Response Details

### Show headers with response

```bash
curl -i https://example.com
```

Output:

```
HTTP/1.1 200 OK
Date: Sat, 30 Aug 2025 12:00:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 1256
```

Useful to check for security headers such as `Content-Security-Policy` or `X-Frame-Options`.

### Only show headers

```bash
curl -I https://example.com
```

---

## 7. File Uploads with `curl`

Testing file upload endpoints:

```bash
curl -X POST https://example.com/upload \
  -F "file=@/path/to/test.png"
```

* `-F` simulates form file upload.
* Useful for testing file upload restrictions.

---

## 8. Method Tampering with `curl`

One of the most practical uses of `curl` in security testing is checking for HTTP Method Tampering.

### Example 1: GET to DELETE

```bash
curl -X DELETE https://example.com/orders/123
```

If the server processes this and deletes order `123`, then the application is not validating request methods properly.

---

### Example 2: POST to GET

```bash
curl -X GET "https://example.com/login?username=admin&password=secret"
```

If login works via GET, credentials may leak into logs or browser history.

---

### Example 3: GET to POST

```bash
curl -X POST https://example.com/profile \
  -d "email=hacker@example.com"
```

If profile changes without proper validation, this indicates a vulnerability.

---

## 9. Advanced Features

* **Verbose mode (debugging):**

  ```bash
  curl -v https://example.com
  ```

  Displays the full request and response, including headers.

* **Follow redirects:**

  ```bash
  curl -L https://example.com
  ```

  Automatically follows redirections (3xx responses).

* **Save response to a file:**

  ```bash
  curl -o output.html https://example.com
  ```

* **Replay request from a file:**

  ```bash
  curl -K request.txt
  ```

---

## 10. Security Testing Checklist with `curl`

When testing an endpoint with `curl`:

* Try all HTTP methods (GET, POST, PUT, DELETE, OPTIONS).
* Use the OPTIONS method to see allowed actions.
* Test with and without authentication headers.
* Try tampered methods such as POST instead of GET.
* Add unusual headers like `X-HTTP-Method-Override`.
* Check if sensitive data appears in GET requests (logs, URLs).

---

# Summary

* `curl` is a versatile tool for HTTP testing.
* It allows manual crafting of requests, making it ideal for method tampering, authentication testing, and debugging.
* With `curl`, you can discover hidden functionality, identify misconfigurations, and replicate attacks.
* Mastering `curl` is an essential skill for web penetration testers.



