
## 1. What is HTTP?

**HTTP (HyperText Transfer Protocol)** is an application-layer protocol used by clients (usually browsers or API clients) to communicate with servers. It defines how requests and responses are formatted, transmitted, and interpreted. HTTP is **stateless** (each request is independent) and text-based (the wire format is ASCII/UTF-8 text for headers and initial lines, with binary-safe bodies).

Key points:

* Client → Server communication (requests).
* Server → Client communication (responses).
* Works over TCP (normally port 80) or TLS/TCP (HTTPS; port 443).
* Designed for hypermedia (web pages) but used by APIs, microservices, IoT, etc.

---

## 2. URL (Uniform Resource Locator) — anatomy and meaning

A **URL** identifies a resource on the web. Its components:

```
scheme://userinfo@host:port/path?query#fragment
```

Example:

```
https://alice:pw@example.com:8443/store/products/42?color=red&size=m#reviews
```

Breakdown:

* **scheme** (`https`) — transport protocol (http or https).
* **userinfo** (`alice:pw`) — rarely used in browsers; contains username/password (avoid in practice).
* **host** (`example.com`) — domain name or IP.
* **port** (`8443`) — optional; default is 80 for HTTP and 443 for HTTPS.
* **path** (`/store/products/42`) — resource path on the server.
* **query** (`color=red&size=m`) — key/value parameters; server receives raw query string.
* **fragment** (`#reviews`) — client-side only (not sent to server); used for in-page navigation.

Notes:

* Query parameters are often used to pass filters, pagination, or identifiers. Example: `/search?q=shoes&page=2`.
* Percent-encoding: spaces and reserved characters are URL-encoded (` ` → `%20`).
* The URL’s **origin** is `scheme://host:port`. Origin is important for same-origin policy in browsers.

---

## 3. HTTP request — structure and example

An HTTP request has three parts:

1. **Start line** (request line): method, request-target (path + optional query), and HTTP version.
2. **Headers**: key-value pairs that describe request meta (User-Agent, Accept, Host, etc.).
3. **Body** (optional): payload for methods like POST/PUT (form data, JSON, files).

### Raw HTTP/1.1 request example

```
POST /api/v1/login?redir=/dashboard HTTP/1.1
Host: example.com
User-Agent: curl/7.85.0
Accept: application/json
Content-Type: application/json
Content-Length: 47
Connection: keep-alive

{"username":"alice","password":"s3cret123"}
```

Explanation:

* `POST /api/v1/login?redir=/dashboard HTTP/1.1` — method `POST`, path and query `?redir=...`, HTTP version 1.1.
* `Host` header is required in HTTP/1.1 to support virtual hosting.
* Body contains a JSON payload; `Content-Length` must match the byte length of the body (or use chunked transfer).

### Simple GET request (browser-like)

```
GET /search?q=shoes&size=10 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9
Accept-Language: en-US,en;q=0.5
Connection: keep-alive
```

---

## 4. HTTP response — structure and example

An HTTP response has:

1. **Status line**: protocol version, status code, reason phrase.
2. **Headers**: response metadata (Content-Type, Content-Length, Set-Cookie, Cache-Control, etc.).
3. **Body**: resource content (HTML, JSON, image, etc.).

### Raw HTTP/1.1 response example

```
HTTP/1.1 200 OK
Date: Tue, 09 Oct 2025 12:00:00 GMT
Server: nginx/1.22.0
Content-Type: application/json; charset=utf-8
Content-Length: 132
Cache-Control: no-store
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax

{"user":{"id":42,"name":"Alice"},"token":"eyJhbGciOi...","expires_in":3600}
```

Explanation:

* `200 OK` — success status code.
* `Content-Type` tells client how to interpret the response body.
* `Set-Cookie` sets an HttpOnly secure cookie for session management.

---

## 5. Common HTTP methods (verbs) and behavior

HTTP defines methods that express action semantics. Important attributes: **safe** (does not change server state), **idempotent** (repeating has same effect), and **cacheable**.

| Method  | Safe? | Idempotent?     | Typical use                                        |
| ------- | ----- | --------------- | -------------------------------------------------- |
| GET     | yes   | yes             | Retrieve resource; no side effects.                |
| HEAD    | yes   | yes             | Same as GET but no body; check headers/metadata.   |
| POST    | no    | no              | Create a resource or submit data (non-idempotent). |
| PUT     | no    | yes             | Replace resource at URI (idempotent).              |
| PATCH   | no    | no (usually)    | Partial update of resource.                        |
| DELETE  | no    | yes (typically) | Delete resource at URI.                            |
| OPTIONS | yes   | yes             | Discover allowed methods / CORS preflight.         |

Examples:

* `GET /articles/10` — read.
* `POST /articles` with JSON body — create new article.
* `PUT /articles/10` — replace article 10 with the provided content.
* `PATCH /articles/10` — modify fields on article 10.
* `DELETE /articles/10` — delete the article.

Notes:

* Being idempotent doesn’t guarantee safety — `PUT` is idempotent but may change resource.
* Servers may implement semantics differently; APIs should document expected behavior.

---

## 6. HTTP status codes — categories and common codes

Status codes are grouped by class (first digit):

### 1xx — Informational

* `100 Continue` — provisional; client should continue sending body.
* `101 Switching Protocols` — server agrees to switch protocols (e.g., HTTP → WebSocket).

### 2xx — Success

* `200 OK` — generic success.
* `201 Created` — resource created; typically includes `Location` header.
* `202 Accepted` — request accepted for asynchronous processing.
* `204 No Content` — success but no body.

### 3xx — Redirection

* `301 Moved Permanently` — resource permanently moved to new URI.
* `302 Found` — temporary redirect (commonly used but sometimes ambiguous).
* `303 See Other` — redirect after POST to GET location.
* `304 Not Modified` — client cache is fresh (conditional GET with `If-Modified-Since` / `If-None-Match`).
* `307 Temporary Redirect` and `308 Permanent Redirect` — preserve method semantics (POST → POST).

### 4xx — Client error

* `400 Bad Request` — malformed request.
* `401 Unauthorized` — authentication required or failed (WWW-Authenticate challenge).
* `403 Forbidden` — authenticated but not allowed.
* `404 Not Found` — resource not found.
* `405 Method Not Allowed` — method not allowed for resource.
* `409 Conflict` — conflict with current state (e.g., duplicate).
* `429 Too Many Requests` — rate-limiting.

### 5xx — Server error

* `500 Internal Server Error` — generic server error.
* `502 Bad Gateway` — upstream error / invalid response from backend.
* `503 Service Unavailable` — server overloaded or in maintenance.
* `504 Gateway Timeout` — upstream timeout.

Practical notes:

* Use `201` with `Location` when creating resources.
* Use `401` when authentication is required; `403` when authenticated but unauthorized.
* Use `304` to reduce bandwidth with caching; set `ETag` and `Last-Modified`.

---

## 7. HTTP headers — purpose and common headers

Headers are metadata for requests/responses. Some are general, some request-only or response-only, others entity headers.

### Important request headers

* `Host` — host (and optional port). Required in HTTP/1.1.
* `User-Agent` — client identity string.
* `Accept` — media types client can accept (`text/html`, `application/json`).
* `Accept-Encoding` — `gzip, br` compression client accepts.
* `Accept-Language` — preferred language(s).
* `Authorization` — credentials (e.g., `Bearer <token>`, `Basic <base64>`).
* `Cookie` — cookies sent to server.
* `Content-Type` — media type of body (e.g., `application/json`, `multipart/form-data`).
* `Content-Length` — body size in bytes (or `Transfer-Encoding: chunked`).
* `If-None-Match` / `If-Modified-Since` — conditional requests to support caching.
* `Referer` — previous page (note spelling) — origin of request.
* `Origin` — origin for CORS checks.
* `X-Forwarded-For` — client IP forwarded by proxies (not standardized).

### Important response headers

* `Content-Type` — type of returned content.
* `Content-Length` — size of body.
* `Content-Encoding` — e.g., `gzip`, `br`.
* `Cache-Control` — caching directives (e.g., `no-cache`, `max-age=3600`, `public`, `private`).
* `ETag` — entity tag for cache validation.
* `Last-Modified` — last modification date for resource.
* `Set-Cookie` — set cookie value and attributes (HttpOnly, Secure, SameSite).
* `Location` — redirect target (with 3xx) or created resource URI (201).
* `WWW-Authenticate` — challenge for authentication (401).
* `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods` — CORS response headers.

### Example header usage in a response

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4520
Cache-Control: public, max-age=3600
ETag: "v1.2-9ab3"
Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Lax
```

Notes:

* `Set-Cookie` attributes: `HttpOnly` (not accessible via JS), `Secure` (only over TLS), `SameSite` (`Lax` or `Strict` reduces CSRF risk).
* `Cache-Control` controls proxies and client caching; never rely solely on client caching for security-sensitive content.

---

## 8. Request/response lifecycle and additional features

### Keep-Alive and connection reuse

* `Connection: keep-alive` allows reusing TCP connection for multiple HTTP requests to reduce latency.
* HTTP/2 improves multiplexing — multiple concurrent requests/responses over a single connection.

### Chunked transfer encoding

* `Transfer-Encoding: chunked` allows streaming a response when total size is unknown. Body is sent in chunks with hex-size headers.

### Compression

* `Accept-Encoding: gzip, deflate, br` tells server it accepts compressed content. Server responds with `Content-Encoding: gzip` if compressed.

### Content negotiation

* Server can choose response type based on `Accept` header. Example: `Accept: application/json` → APIs usually return JSON; `Accept: text/html` → HTML.

### Cookies & sessions

* Traditional web sessions: server creates session ID, sends `Set-Cookie`, client returns `Cookie` on subsequent requests. Session data is stored server-side.
* JWT/stateless sessions: server issues JWT in response; client stores it and sends it in `Authorization` header (or cookies). Session invalidation is harder with stateless tokens.

### CORS (Cross-Origin Resource Sharing)

* Browser security model restricts cross-origin requests. Server opts-in using response headers such as:

  * `Access-Control-Allow-Origin: https://app.example.com`
  * `Access-Control-Allow-Methods: GET, POST`
  * `Access-Control-Allow-Credentials: true`
* Preflight `OPTIONS` requests are used for certain cross-origin requests.

---

## 9. HTTPS and TLS — what changes when using HTTPS

**HTTPS = HTTP over TLS (Transport Layer Security).** TLS secures transport with confidentiality (encryption), integrity (MAC/AEAD), and server authentication (certificates).

### TLS handshake basics (simplified)

1. **ClientHello**: client proposes TLS version, cipher suites, and sends random bytes and SNI (Server Name Indication) to indicate the target hostname.
2. **ServerHello**: server picks TLS version and cipher, returns server certificate and server key exchange information.
3. **Certificate verification**: client validates certificate chain (root CA trust), checks `CN`/`SAN` for hostname, validates `notBefore`/`notAfter`.
4. **Key exchange**: client & server derive shared symmetric keys (using ECDHE for forward secrecy).
5. **Finished** messages confirm handshake integrity.
6. **Application data**: encrypted HTTP traffic flows over the established TLS session.

### Important TLS concepts

* **Certificates**: issued by Certificate Authorities (CA). Contain public key and identity information. Browsers verify trust chain.
* **SNI (Server Name Indication)**: allows multiple hostnames on a single IP/TLS endpoint (modern clients send SNI in ClientHello).
* **Forward secrecy**: ephemeral key exchange (ECDHE) ensures past sessions can’t be decrypted if server private key is compromised later.
* **HSTS (HTTP Strict Transport Security)**: response header `Strict-Transport-Security` tells browsers to always use HTTPS for the domain.
* **Mixed content**: loading HTTP resources in an HTTPS page breaks security and is blocked by modern browsers.

### Example HTTPS `curl` command

```bash
curl -v https://example.com/api/profile -H "Accept: application/json"
```

`-v` prints TLS handshake and certificate information.

Security notes:

* Never send sensitive credentials over plain HTTP. Always require HTTPS for login, APIs, and tokens.
* Be cautious about certificate validation bypass (never disable verification in production).

---

## 10. HTTP/2 and HTTP/3 — evolution notes

* **HTTP/2**: binary framing, multiplexing, header compression (HPACK), server push, typically over TLS. Reduces head-of-line blocking at HTTP layer.
* **HTTP/3**: uses QUIC (UDP-based transport) for faster connection setup and improved loss recovery. Also runs encrypted by default and supports multiplexing without TCP head-of-line blocking.
* Header semantics (methods/status codes/headers) remain mostly the same; only transport and framing change.

---

## 11. Debugging and examples (curl, raw and practical tips)

### Example 1 — Raw GET with headers (curl + raw)

```bash
curl -i -H "Accept: application/json" "https://api.example.com/products?category=books&page=2"
```

`-i` shows response headers.

### Example 2 — POST JSON

```bash
curl -i -X POST "https://api.example.com/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"s3cret"}'
```

### Example 3 — Follow redirects and show final URL

```bash
curl -L -v http://example.com/old-page
```

`-L` follows redirects. `-v` prints each request/response.

### Example 4 — Check TLS certificate chain

```bash
openssl s_client -connect example.com:443 -servername example.com
```

This prints certificate details and handshake information.

---

## 12. Best practices & security considerations

* **Always use HTTPS** (redirect HTTP → HTTPS; set HSTS).
* **Validate and sanitize input**: never trust query parameters or headers — validate server-side.
* **Use secure cookie attributes** (`Secure`, `HttpOnly`, `SameSite`) and consider `SameSite=Lax`/`Strict` according to app behavior.
* **Expire sessions** and use short-lived access tokens; rotate refresh tokens.
* **Protect against CSRF** (use SameSite cookies, CSRF tokens) when using cookies for auth.
* **Avoid tokens in URLs** (GET parameters) because logs and referrers can leak them.
* **Use Content Security Policy (CSP)** to mitigate XSS and reduce token theft risk.
* **Implement rate limiting** and `429` responses to mitigate brute-force and DoS.
* **Log and monitor** authentication failures, unusual user agents, and geo anomalies.

---

## 13. Quick reference tables

### URL components (example)

| Part     | Example       | Sent to server?  |
| -------- | ------------- | ---------------- |
| Scheme   | `https`       | used by client   |
| Host     | `example.com` | yes              |
| Port     | `443`         | yes              |
| Path     | `/api/items`  | yes              |
| Query    | `?q=term`     | yes              |
| Fragment | `#section`    | no (client-only) |

### Common request headers

`Host`, `User-Agent`, `Accept`, `Accept-Encoding`, `Authorization`, `Cookie`, `Content-Type`, `Content-Length`, `If-None-Match`, `Origin`, `Referer`

### Common response headers

`Content-Type`, `Content-Length`, `Content-Encoding`, `Cache-Control`, `ETag`, `Set-Cookie`, `Location`, `WWW-Authenticate`, `Strict-Transport-Security`, CORS headers.

### Status codes summary

* 2xx: success — `200`, `201`, `204`.
* 3xx: redirect — `301`, `302`, `307`, `308`, `304`.
* 4xx: client error — `400`, `401`, `403`, `404`, `405`, `409`, `429`.
* 5xx: server error — `500`, `502`, `503`, `504`.

---

## 14. Example end-to-end flow (browser login)

1. Browser GET `/login` → server returns HTML form with CSRF token.
2. Browser POST `/login` with credentials + CSRF token (HTTPS). Server validates credentials and CSRF.
3. Server responds `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax` and `200 OK` or `302` redirect.
4. Browser stores the cookie and sends it automatically for subsequent requests to same origin.
5. For APIs, server might return JSON with `access_token` (short) and `refresh_token` (long) — client stores refresh token in secure storage and uses access token in `Authorization: Bearer` header.

---
