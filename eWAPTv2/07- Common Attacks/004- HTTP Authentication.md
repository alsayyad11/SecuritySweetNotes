

## What is Authentication?

Authentication is the process of verifying the identity of a user or a system that is trying to access a resource. In simple words, it answers the question: **“Who are you?”**.

When you log in to a website with your username and password, that’s authentication. Once authenticated, the server can decide what actions or resources you’re allowed to access (that’s **authorization**, a separate concept).

Without authentication, anyone could access sensitive data or perform operations without restrictions. That’s why authentication is one of the most important aspects of web security.

---

## Types of HTTP Authentication

There are several types of authentication used in HTTP. Let’s go through the main ones step by step.

---

### 1. Basic Authentication

* **How it works**:

  * The client sends the username and password with every request.
  * The credentials are encoded using **Base64** (not encrypted, just encoded).
  * The server checks if the credentials are valid, and if yes, grants access.

* **Weakness**:

  * Since Base64 is easily reversible, if someone intercepts the traffic (especially over HTTP instead of HTTPS), they can easily decode the credentials.
  * Example:

    ```
    GET /admin HTTP/1.1
    Host: example.com
    Authorization: Basic YWRtaW46cGFzc3dvcmQ=
    ```

    Here, `YWRtaW46cGFzc3dvcmQ=` is just Base64 for `admin:password`.

* **Practical Example**:
  Imagine you are testing a login panel that uses Basic Authentication. If you intercept the request with **Burp Suite**, you can decode the `Authorization` header and immediately see the username and password in plain text.

  ```
  echo YWRtaW46cGFzc3dvcmQ= | base64 -d
  ```

  Output: `admin:password`

---

### 2. Digest Authentication

* **How it works**:

  * To improve Basic Auth, Digest Authentication uses hashing (usually MD5) to protect credentials.
  * The server sends a **nonce** (a random value).
  * The client responds with a hashed combination of username, password, nonce, and other data.
  * The server checks if the hash matches.

* **Why it’s better than Basic**:

  * Passwords are not sent in cleartext or simple Base64.
  * The attacker cannot directly reuse intercepted credentials unless they can recreate the correct hash.

* **Weakness**:

  * Still vulnerable to some attacks (like replay attacks if nonce reuse is not handled properly).
  * If MD5 is used, it is weak by modern standards.

* **Practical Example**:
  Request with Digest Auth might look like this:

  ```
  GET /admin HTTP/1.1
  Host: example.com
  Authorization: Digest username="admin",
                 realm="Secure Area",
                 nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
                 uri="/admin",
                 response="6629fae49393a05397450978507c4ef1"
  ```

  Here, the `response` field is an MD5 hash computed using the shared secret (the password).

---

### 3. Token-Based Authentication

* **How it works**:

  * Instead of sending credentials with each request, the server issues a **token** after the user logs in.
  * The token (often a long random string or JWT) is then sent by the client with every request, usually in the `Authorization` header.
  * Example:

    ```
    Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    ```
  * Tokens usually have an expiration time.

* **Advantages**:

  * Credentials are not sent repeatedly.
  * Tokens can expire, limiting damage if stolen.
  * Common in modern APIs and mobile apps.

* **Practical Example**:
  Suppose a user logs in through `/login` with their email and password. The server responds with:

  ```json
  { "token": "abc123xyz" }
  ```

  Then the user accesses `/profile` by including:

  ```
  GET /profile
  Authorization: Bearer abc123xyz
  ```

---

### 4. Session-Based Authentication

* **How it works**:

  * After a successful login, the server creates a **session** and stores it in memory or a database.
  * The client receives a **session ID** (usually in a cookie).
  * On each request, the session ID is sent back to the server.
  * Example:

    ```
    Cookie: PHPSESSID=1234567890abcdef
    ```

* **Advantages**:

  * More secure than Basic Auth since the password isn’t sent every time.
  * Server has full control to invalidate sessions.

* **Practical Example**:

  * You log into a website.
  * Your browser gets a cookie: `Set-Cookie: JSESSIONID=abc123; HttpOnly; Secure`
  * Every time you refresh or move to another page, the browser sends this cookie back automatically.

---

### 5. OAuth (Open Authorization)

* **How it works**:

  * OAuth allows users to grant access to their data without sharing their credentials.
  * Common in “Login with Google/Facebook” flows.
  * Instead of giving your password to a third-party app, you give it permission to access some of your data using a token.

* **Practical Example**:

  * You want to use a third-party calendar app.
  * Instead of giving the app your Google username/password, you log in to Google, which then gives the app a token.
  * The app can now access your calendar data through Google’s API using:

    ```
    Authorization: Bearer ya29.a0AfH6SMBexampleToken
    ```
