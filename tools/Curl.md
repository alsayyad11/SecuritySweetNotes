<div align="center">
  <img src="https://github.com/user-attachments/assets/f61a00e3-70cb-422c-8655-2a62413d7a47" alt="image">
</div>

---

## What is `curl`?

`curl` is a command-line tool used to transfer data to or from a server using various internet protocols, most commonly HTTP and HTTPS.
The name "curl" stands for **Client URL**.

It allows you to send requests to web servers directly from your terminal or command prompt, which is extremely useful for:

* Testing APIs
* Debugging HTTP requests
* Downloading files
* Sending data in requests (like JSON or form data)

---

## Why is `curl` important?

If you're working with web applications, APIs, or any form of networking or cybersecurity, you’ll find `curl` essential because:

* It gives you full control over the request.
* You can see exactly what is being sent and received.
* It's scriptable and works in almost any environment.

---

## Basic Syntax

```bash
curl [options] [URL]
```

You type `curl`, then some options (like `-X` or `-H`), then the URL you want to request.

---

## Example 1: Simple GET Request

```bash
curl https://example.com
```

This sends a GET request to `https://example.com` and shows the raw HTML response.

---

## Common `curl` Options Explained

Here are the most important and commonly used options with `curl`:

### 1. `-X` (Request Method)

Specifies the HTTP method (GET, POST, PUT, DELETE, etc.)

```bash
curl -X POST https://example.com/login
```

By default, `curl` sends a GET request, so `-X` is only needed when you want to use another method.

---

### 2. `-H` (Custom Headers)

Adds custom headers to the request (like `Authorization`, `Content-Type`, etc.)

```bash
curl -H "Content-Type: application/json" https://example.com/api
```

You can include multiple headers by repeating `-H`.

---

### 3. `-d` (Request Data)

Sends data in the body of the request. Used mostly with POST or PUT.

```bash
curl -X POST -H "Content-Type: application/json" \
-d '{"username":"admin","password":"1234"}' \
https://example.com/api/login
```

This sends a JSON payload to the API endpoint.

---

### 4. `-i` (Include Response Headers)

Displays the response headers along with the body.

```bash
curl -i https://example.com
```

---

### 5. `-L` (Follow Redirects)

If the server responds with a redirect (like 301 or 302), `curl` won’t follow it by default. Use `-L` to tell it to follow the redirection.

```bash
curl -L http://example.com
```

---

### 6. `-o` (Output to File)

Saves the response to a file instead of printing it to the terminal.

```bash
curl https://example.com/image.jpg -o image.jpg
```

---

### 7. `-u` (Basic Authentication)

Sends a username and password for HTTP Basic Auth.

```bash
curl -u admin:password https://example.com/protected
```

---

### 8. `-s` (Silent Mode)

Suppresses progress meter and errors. Often used in scripts.

```bash
curl -s https://example.com
```

---

## Example 2: Full Request with Headers and JSON Body

```bash
curl -X POST https://api.example.com/login \
-H "Content-Type: application/json" \
-H "Accept: application/json" \
-d '{"email":"test@example.com", "password":"123456"}'
```

This sends a JSON POST request with appropriate headers and prints the server response.

---

## Viewing Only the Response Code

Use `-w` with `%{http_code}` to print just the status code:

```bash
curl -s -o /dev/null -w "%{http_code}" https://example.com
```

This is useful when checking if a site is up (200 OK), moved (301), or down (500).

---

## Summary of Options

| Option | Purpose                               |
| ------ | ------------------------------------- |
| `-X`   | Set the HTTP method (GET, POST, etc.) |
| `-H`   | Add headers                           |
| `-d`   | Add body data                         |
| `-i`   | Include headers in response           |
| `-L`   | Follow redirects                      |
| `-o`   | Save output to file                   |
| `-u`   | Basic authentication                  |
| `-s`   | Silent mode                           |
| `-w`   | Custom output (e.g., status code)     |

---

## Final Tips

* Always start with simple requests (like just `curl URL`) and build up.
* Use `-i` to see full response headers for debugging.
* Use `-v` for verbose mode if you want to see what curl is doing behind the scenes.
* Practice with free public APIs like: `https://jsonplaceholder.typicode.com`

---
