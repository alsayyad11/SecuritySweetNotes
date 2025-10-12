
## Purpose (why this test exists)

Ensure that **all authentication credentials and other sensitive authentication material** (passwords, one-time passwords, session tokens, refresh tokens, secret answers, API keys used for login, etc.) are transmitted only over **an encrypted channel** (HTTPS/TLS). If credentials travel over plaintext (HTTP) or through channels that can be observed (unprotected redirects, insecure referrers, mixed content), attackers can capture them and take over accounts. ([OWASP Foundation][1])

---

## Scope: what to check

* Web login forms and AJAX/API login endpoints.
* Password-reset and account recovery forms (submission of verification codes).
* SSO/OAuth/OpenID Connect flows (authorization code / token exchange).
* Mobile app authentication endpoints.
* Embedded third-party login widgets.
* Any page that returns credentials or session tokens in responses.
* Redirects from HTTPS to HTTP, or forms that submit to HTTP URLs. ([OWASP Foundation][1])

---

## Expected secure behavior (pass criteria)

* All authentication interactions use HTTPS (TLS) end-to-end (no HTTP endpoints).
* The server enforces HTTPS (redirects HTTP → HTTPS and uses HSTS where appropriate).
* Cookies used for sessions are set with `Secure` so they are not sent over HTTP.
* No credentials appear in URL query strings, fragments, or referer headers to third parties.
* TLS configuration uses modern versions/ciphers (see TLS testing guidance). ([OWASP Foundation][2])

---

## How to test — practical step-by-step

### 1) Intercept and inspect login flows (Burp/OWASP ZAP)

1. Configure Burp or ZAP as proxy and point browser or mobile device at it.
2. Perform a login using valid credentials (test account).
3. Inspect the intercepted requests and responses.

What to look for:

* Is the form submitted to `https://`? If you see `http://`, fail.
* Are credentials in POST body or Authorization header over HTTPS? OK.
* Are credentials sent in URL (GET query string)? FAIL — never send passwords in URL.
* Is any response setting cookies without `Secure` when over HTTPS? That’s a risk if the app later serves HTTP. Prefer `Secure` flag. ([OWASP Foundation][1])

**Example vulnerable request (bad):**

```http
GET http://example.com/login?username=alice&password=123456 HTTP/1.1
Host: example.com
```

Credentials are visible in URL and sent over HTTP — high severity.

**Example secure request (good):**

```http
POST https://example.com/login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=alice&password=Tr0ub4dor!
```

Request and credentials are carried over TLS (assuming TLS is correctly configured). ([OWASP Foundation][1])

---

### 2) Verify there are no insecure redirects or mixed-content

* After authentication, does the application redirect the browser to an `http://` URL? Follow the full redirect chain and check each hop.
* Check pages for mixed content: pages served over HTTPS that load scripts/forms over HTTP can expose credentials or allow an attacker to modify the page (leading to credential theft).

**Test step:** In Burp, right-click the response → “Show response in browser” or check the “Location” header on 3xx responses. Also open browser console for mixed-content warnings.

---

### 3) Check for credentials in Referer headers

* If a login form POSTS to a third-party (or redirects with query parameters), sensitive data can leak in the `Referer` header to external sites.
* Ensure the site does not redirect with sensitive query parameters. Use `Referrer-Policy` and don't place secrets in URLs.

**Example dangerous flow:**

1. `https://app.example.com/login?next=https://third.example.com/welcome&username=alice&token=...`
2. Browser follows redirect and sends the referer including query string to `third.example.com` — secrets leak.

---

### 4) Test API endpoints and mobile clients

* Use a proxy or the mobile app’s debug log to capture API calls.
* Check that API endpoints accept only `https://` and reject HTTP.
* For mobile apps, ensure certificate pinning or verify TLS config (if pinning is used, proxying may require installing app certs).

---

### 5) Validate cookie settings

* Check `Set-Cookie` headers for session cookies and tokens. Ensure `Secure` is present; prefer `HttpOnly` and `SameSite` as well.
* If session cookie lacks `Secure`, it could be sent over HTTP in some flows or be more easily intercepted if the domain also serves HTTP content.

**Example cookie header (good):**

```
Set-Cookie: sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

**If `Secure` missing:** note as issue—cookie could be exposed over unencrypted transport if an HTTP request is ever used. ([OWASP Foundation][1])

---

### 6) Check TLS configuration (certificate, versions, ciphers)

* While credential transport depends on using TLS, the strength of TLS matters. Weak TLS (old versions or weak ciphers) undermines encryption.
* Use tools: `sslyze`, `testssl.sh`, or online scanners to inspect server certificate chain, supported TLS versions, key sizes, and vulnerability to known issues (e.g., POODLE, BEAST, weak RSA keys).
* Confirm certificate is valid (not self-signed in production), correct CN/SAN, and trusted by clients.

**Quick test example (openssl):**

```bash
openssl s_client -connect example.com:443 -servername example.com
```

Look for certificate chain and negotiated protocol (TLSv1.2/1.3 expected). ([OWASP Foundation][2])

---

### 7) Check failures & fallback to non-TLS

* Some servers or proxies may accept HTTPS but allow downgrade to HTTP or weak ciphers on fallback. Attempt to connect over HTTP and observe if the server redirects to HTTPS or serves content.
* Test whether HSTS (Strict-Transport-Security) is used to instruct browsers to always use HTTPS.

**HSTS header example (recommended):**

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

If missing, include as remediation.

---

## What to record as evidence

* Captured HTTP(s) request/response showing credentials (both request line and body).
* Any redirect chain where credentials or cookies cross from HTTPS to HTTP.
* Screenshots of browser console showing mixed-content warnings.
* `Set-Cookie` header snapshots showing missing `Secure`.
* TLS scan report showing weak protocol/cipher or certificate issues.
* A short explanation of impact (e.g., "Credentials transmitted in cleartext over HTTP — full account takeover risk via network sniffing").

---

## Severity and risk reasoning

* **High severity** if credentials are sent in plaintext (HTTP) or placed in URLs (query strings) where logs or proxies can capture them.
* **Medium severity** if TLS is used but misconfigured (deprecated versions/ciphers) or session cookies lack `Secure`.
* **Low severity** if minor issues like missing HSTS but all credentials are still sent over TLS and cookie `Secure` is present. Use risk context: public Wi-Fi, client population, sensitivity of the application. ([OWASP Foundation][1])

---

## Common pitfalls & tricky cases

1. **Credentials in URLs** — occurs in poorly designed OAuth redirects, or apps that use GET for login. Even if over HTTPS, query strings may be logged by servers/proxies.
2. **Mixed content** — a main page served over HTTPS loads an HTTP script that can modify forms and steal credentials.
3. **API endpoints** — developers sometimes leave API endpoints on HTTP for testing; mobile apps can still hit them.
4. **Third-party widgets** — forms that submit to third-party domains without TLS or that leak referer headers.
5. **Legacy TLS support** — servers that accept TLS 1.0 or weak ciphers; attackers may exploit downgrade attacks.
6. **Load balancer / CDN misconfiguration** — front-end TLS may be fine, but internal connections to app servers could use HTTP; ensure end-to-end encryption when necessary.

---

## Practical remediation (how developers should fix issues)

* **Enforce HTTPS everywhere**. Redirect HTTP → HTTPS and implement HSTS with `includeSubDomains` and `preload` where appropriate.
* **Never transmit credentials in URLs** (use POST with body and appropriate content-type).
* **Set cookie attributes**: `Secure`, `HttpOnly`, `SameSite` as appropriate.
* **Use modern TLS** (TLS 1.2+ or TLS 1.3), disable old protocols and weak ciphers, use strong certificates from trusted CAs.
* **Avoid mixed content**: host all scripts/CSS/XHR over HTTPS.
* **Use `Referrer-Policy`** to reduce referer leakage and never include secrets in query strings.
* **Certificate pinning** for mobile apps (with care) or ensure proper certificate validation.
* **Review third-party integrations** to ensure they accept and return only TLS-protected data.
* **Implement secure token handling**: short-lived access tokens, refresh tokens stored securely (HttpOnly cookie or server-side), and server-side revocation mechanisms.

---

## Example report snippet (how you might present this in findings)

**Title:** Credentials transmitted over unencrypted channel (HTTP)
**ID:** WSTG-ATHN-01 / High
**Description:** Login form submits user credentials to `http://example.com/login`, allowing an attacker on the same network to capture credentials.
**Proof:** Intercepted request (Burp) shows:

```
GET http://example.com/login?username=alice&password=123456
```

**Impact:** An attacker can capture credentials and login as the user → account takeover, data theft.
**Recommendation:** Serve the login page and all authentication endpoints over HTTPS only. Configure redirect from HTTP to HTTPS and set HSTS header. Ensure cookies are set with `Secure; HttpOnly`. Validate TLS config per OWASP TLS guidance. ([OWASP Foundation][1])

---

## [OWASP reference](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel)

* OWASP Web Security Testing Guide — Testing for Credentials Transported over an Encrypted Channel (WSTG-ATHN-01). ([OWASP Foundation][1])
* OWASP WSTG — Testing for Weak Transport Layer Security (guidance on TLS versions/ciphers). ([OWASP Foundation][2])

---
