
<img width="1536" height="1024" alt="v" src="https://github.com/user-attachments/assets/e66860f2-6ad5-4339-89c3-8435a192a465" />

---

## 1. What is HTTP?

HTTP — Hypertext Transfer Protocol — is the communication protocol used by web browsers, mobile apps, scripts and servers to exchange messages across the internet. It defines a simple request/response model:

* A **client** (for example a browser) sends an **HTTP request** to the **server**.
* The server processes the request and sends back an **HTTP response**.

An HTTP request contains a set of important parts:

* **Method (verb)**: the action the client wants the server to perform (GET, POST, PUT, DELETE, OPTIONS, PATCH, etc.). The method expresses intent.
* **URL / Path**: identifies the resource (e.g., `/users/123`, `/api/invoices/101`).
* **Headers**: metadata such as `Host`, `User-Agent`, `Content-Type`, `Cookie`, `Authorization`, custom headers.
* **Body**: optional payload (JSON, form data, files) usually present with POST/PUT/PATCH.

A simple example of a complete request and response:

**Request**

```
GET /index.html HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
```

**Response**

```
HTTP/1.1 200 OK
Content-Type: text/html

<html> ... </html>
```

The HTTP **method** is central: it tells servers (and intermediaries like proxies or caches) what the client intends. Correctly implementing and enforcing method semantics is critical to application security.

---

## 2. HTTP Methods: what they mean, how they’re used, and the security implications

Below is a detailed explanation of the commonly used HTTP methods. For each method I will explain: formal meaning, how it is commonly used, the security expectations, practical example requests/responses, and what goes wrong when the method semantics are violated.

### GET — read-only retrieval

**Meaning:** GET requests are used to retrieve a resource representation. According to HTTP standards, GET is a “safe” method — it should not have side effects. Clients, caches, crawlers and other systems rely on this property.

**Common use:** Load pages, fetch JSON, download images — any operation that only reads data.

**Request example**

```
GET /api/users/123 HTTP/1.1
Host: api.example.com
Accept: application/json
```

**Response example**

```json
HTTP/1.1 200 OK
Content-Type: application/json

{ "id": 123, "name": "Alice" }
```

**Security expectations:** GET must not modify server state. If a GET endpoint changes data (for example, deletes a record or updates a flag), attackers can exploit that by forcing a victim to request the URL (for instance by embedding it in an `<img>` tag, an `<iframe>`, or a link). This leads to CSRF-like effects because simply loading a link or viewing content can cause state changes.

**What goes wrong often:** Developers sometimes create “action URLs” that are accessible with GET (for convenience), e.g., `GET /subscribe?user=1` that toggles subscription state. This is a mistake. Caches or prefetchers might trigger these URLs, and attackers can trigger them by luring users to click or load a page.

---

### POST — submit data, non-idempotent operations

**Meaning:** POST is used to submit data that results in creation or processing on the server. It is not idempotent: the same POST sent multiple times can create multiple resources or trigger repeated actions.

**Common use:** Form submissions, file uploads, API operations that create resources (e.g., create order, create comment).

**Request example**

```
POST /api/orders HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer <token>

{ "product_id": 7, "quantity": 2 }
```

**Response example**

```json
HTTP/1.1 201 Created
Content-Type: application/json

{ "order_id": 9876, "status": "created" }
```

**Security expectations:** POSTs change server state and therefore should be protected (for web interfaces this generally means CSRF protection). Logging and monitoring must handle potentially sensitive data carefully because body content can contain secrets.

**What goes wrong often:** If an operation that should be POST is also accessible via GET or if POST endpoints accept parameters in the URL without CSRF check, attackers may cause unwanted transactions. Also, if the server accepts multiple content types without validation, attackers can use unexpected encodings to bypass server-side checks.

---

### PUT — replace or update resource (idempotent)

**Meaning:** PUT replaces the target resource with the provided representation. It is expected to be idempotent: making the same PUT request multiple times should yield the same result as making it once.

**Common use:** Update a complete resource (e.g., replace a user profile with a new JSON object).

**Request example**

```
PUT /api/users/123 HTTP/1.1
Host: api.example.com
Content-Type: application/json
Authorization: Bearer <token>

{ "id": 123, "name": "Alice B.", "email": "alice@example.com" }
```

**Response example**

```json
HTTP/1.1 200 OK
{ "message": "User updated" }
```

**Security expectations:** PUT modifies state and must be protected with authentication and authorization. Idempotency allows safe retries, but if developers implement side effects (e.g., incrementing audit counters) for each PUT, it breaks idempotency and can cause issues.

**What goes wrong often:** When backend logic puts side effects in the same transaction as the resource replace. If an attacker can change which HTTP method is applied (for example, by method override), they may attempt to update resources they are not authorized to change.

---

### DELETE — remove resource

**Meaning:** DELETE requests remove the identified resource. DELETE is intended to be idempotent (deleting an already-removed resource results in the same final state).

**Common use:** Delete accounts, delete files, cancel orders.

**Request example**

```
DELETE /api/users/123 HTTP/1.1
Host: api.example.com
Authorization: Bearer <token>
```

**Response example**

```
HTTP/1.1 204 No Content
```

**Security expectations:** Deletion is destructive and therefore must have strict authorization checks and logging. In high-risk systems, you may require additional confirmation steps, soft-deletes or admin review.

**What goes wrong often:** If DELETE is exposed through GET-equivalent channels or insecure overrides, attackers can trigger deletions. If object-level authorization is missing, a user might delete other users’ resources.

---

### OPTIONS — query allowed methods and CORS preflight

**Meaning:** OPTIONS asks the server which methods and request headers are supported for a resource. Browsers use OPTIONS as a CORS preflight check before issuing non-simple cross-origin requests.

**Request example**

```
OPTIONS /api/users HTTP/1.1
Host: api.example.com
Origin: https://evil.example
Access-Control-Request-Method: DELETE
```

**Response example**

```
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Methods: GET, POST, DELETE
```

**Security expectations:** OPTIONS should not perform state changes. CORS configuration must be restrictive: `Access-Control-Allow-Origin` should be limited to trusted origins; `Allow` should not reveal internal-only methods to arbitrary clients.

**What goes wrong often:** Permissive CORS (`*` or echoing Origin) combined with method override acceptance can enable cross-origin method tampering.

---

### Other methods briefly

* **PATCH** — partial update; similar security requirements to PUT.
* **HEAD** — like GET but returns headers only.
* **TRACE** — echoes request; usually disabled because it can enable cross-site tracing vulnerabilities.
* **CONNECT** — used to create a network tunnel to a server (used in proxies); rarely needed at application layer.

---

## 3. What is HTTP Method Tampering (aka HTTP Verb Tampering)?

**Definition:** HTTP Method Tampering is a vulnerability where an attacker manipulates the HTTP **method** or convinces the server to treat a request as a different method in order to cause unintended behavior by the web application.

In practice this happens when:

* The application trusts a client-controlled value that dictates the action (for example, a `_method` form field or an `action` property in JSON), or
* Middleware or proxies honor override headers/parameters from untrusted sources, or
* Endpoint logic branches on input rather than on the actual HTTP method, or
* Authorization checks are missing or insufficient for actions triggered by a changed method.

This allows examples such as:

* Changing GET to DELETE so a resource is removed when it should only be retrievable.
* Changing POST to GET so credentials or sensitive parameters end up in URLs and logs.
* Changing GET to POST/PUT to cause unintended data modification.

---

## 4. Method tampering techniques and detailed examples

Below are the primary tampering techniques attackers use, explained in depth with examples and how to test them.

### 4.1 Direct method change (tamper the verb)

**How:** Use `curl` with `-X`, a proxy such as Burp Repeater, or a custom client to change the HTTP method directly.

**Example (test):**

```
curl -v -X DELETE 'https://app.example/api/invoices/101' -H 'Cookie: session=<victim-session>'
```

If this request deletes invoice 101 while the session belongs to an ordinary authenticated user and the application did not expect a client to be able to delete invoices, this is a problem.

**What to look for:** Endpoints responding 200 or 204 to methods they should reject (405 Method Not Allowed or 403 Forbidden). Logs that show `GET` requests followed by database writes are suspicious.

---

### 4.2 Method override via `_method` parameter

**Context:** HTML forms only support GET and POST. Many frameworks emulate PUT/DELETE in forms by using a hidden `_method` field (Rails, many Express setups). Middleware reads `_method` from the body or query string and treats the request as the specified method.

**Vectors:**

* Query parameter: `GET /resource/5?_method=DELETE`
* Form body: `<input type="hidden" name="_method" value="DELETE">`
* JSON field or custom parameter sometimes used by poorly designed APIs: `{ "method": "DELETE" }`

**LAB Example (vulnerable server behavior):**

Vulnerable pseudo-code:

```js
app.get('/invoices/:id', (req, res) => {
  if (req.query._method === 'DELETE') {
    deleteInvoice(req.params.id);
    return res.send('deleted');
  }
  res.json(getInvoice(req.params.id));
});
```

Attack:

```
curl 'http://localhost:3000/invoices/101?_method=DELETE'
```

If the server deletes the invoice, it is vulnerable.

**Defenses:**

* Do not accept `_method` from arbitrary requests.
* If you must support it, accept only from server-generated forms with CSRF tokens and validate token presence.
* Prefer proper method-based routing (e.g., `app.delete('/invoices/:id', ...)`) and disable method-override middleware for public APIs.

---

### 4.3 Header override — `X-HTTP-Method-Override`

**How:** Some clients or proxies that cannot use all HTTP verbs in an environment tunnel the intended method in a header `X-HTTP-Method-Override` while using POST on the wire. If the backend honors this header for any request it accepts, attackers may change POST requests into PUT/DELETE.

**Example request:**

```
POST /invoices/101 HTTP/1.1
Host: app.example
X-HTTP-Method-Override: DELETE
Authorization: Bearer <token>
Content-Type: application/json
```

**Risk:** If the backend does not validate where the header came from or whether the client is authorized to request DELETE, the operation might proceed.

**Defenses:**

* Avoid honoring this header for public clients.
* If necessary, only trust it from an internal reverse proxy that strips client-supplied override headers and adds its own trusted header.

---

### 4.4 Business-logic action fields (dangerous pattern)

**How:** Some APIs use a single endpoint that performs different actions depending on an `action` parameter in the request body, e.g.,

```json
POST /api/action
{ "action": "deleteUser", "userId": 100 }
```

If such logic is used, attackers can send malicious bodies to command destructive operations.

**Why it is bad:** Permits attackers to instruct the server to run arbitrary operations, with no reliance on HTTP method semantics. Centralized action endpoints frequently bypass per-method and per-route authorization mappings.

**Fix:** Use RESTful routes with explicit methods, e.g., `DELETE /users/100`, and ensure authorization checks are per-route and per-object.

---

### 4.5 Proxy or load balancer rewriting issues

**How:** Reverse proxies or gateways sometimes modify requests (rewrite paths or methods) for compatibility. If a proxy accepts override headers from the client and forwards them, the backend may receive rewritten methods it should not trust.

**Example risk:** Client sends `X-Forwarded-Method: DELETE`, the proxy translates to DELETE and forwards; the backend receives DELETE and executes it even though the client should not be allowed to request DELETE.

**Defenses:**

* Make sure only the proxy is allowed to rewrite; ensure the proxy strips client-provided override headers and inserts its own internal-only header.
* Backend should only trust override headers from trusted internal network addresses.

---

## 5. Real-world exploitation scenarios (step-by-step lab walkthroughs)

**Important:** All below attack commands are **LAB ONLY**. Do not use against systems without authorization.

### Scenario A — GET turned into destructive DELETE via `_method` (LAB ONLY)

1. **Vulnerable server behavior**: A GET endpoint checks `_method` and performs delete.
2. **Exploit command**

   ```bash
   curl -v 'http://localhost:3000/invoices/101?_method=DELETE' -b 'session=...'
   ```
3. **Observation**

   * If response says invoice deleted, vulnerability confirmed.
   * Check server logs: a GET request caused deletion — a red flag.

**Why effective:** Many browsers and email clients will fetch GET URLs. If a user loads content (sight unseen) the deletion could occur.

---

### Scenario B — Header override (LAB ONLY)

1. **Exploit command**

   ```bash
   curl -v -X POST 'http://localhost:3000/invoices/101' \
     -H 'X-HTTP-Method-Override: DELETE' \
     -H 'Authorization: Bearer <victim-token>'
   ```
2. **Observation**

   * If the server interprets the request as DELETE and performs deletion with the supplied token, it accepts the override incorrectly.

**Mitigation check:** Verify that `X-HTTP-Method-Override` is ignored for external clients or only accepted from a trusted proxy.

---

### Scenario C — CSRF-style trick using an image tag (LAB ONLY)

1. Assume the application erroneously performs deletion when receiving `GET /orders/5?_method=DELETE` and the victim is authenticated.
2. Create a local HTML page:

   ```html
   <html><body>
   <img src="http://localhost:3000/orders/5?_method=DELETE" />
   </body></html>
   ```
3. Open the page while authenticated to the app in the same browser. If the order is deleted, CSRF with method tampering is possible.

**Fix:** Ensure GET is safe; require CSRF tokens for state-changing operations; disable method overrides or require token validation.

---

## 6. Detection techniques and testing checklist (for pentesters and devs)

**Always ensure you have explicit permission to test.**

1. **Enumerate supported methods**

   * `curl -I -X OPTIONS https://target/resource`
   * Inspect `Allow:` header and response codes.

2. **Try direct verb changes**

   * `curl -v -X DELETE https://target/resource/123`
   * `curl -v -X PUT https://target/resource/123 -d '{...}' -H 'Content-Type: application/json'`

3. **Try override parameters and headers**

   * Query param override:

     ```
     curl 'https://target/resource/123?_method=DELETE'
     ```
   * Body override:

     ```
     curl -X POST 'https://target/resource/123' -d '_method=DELETE'
     ```
   * Header override:

     ```
     curl -X POST 'https://target/resource/123' -H 'X-HTTP-Method-Override: DELETE'
     ```

4. **Use Burp**

   * Repeater: intercept a request, change verb or add `_method`/X header, re-send.
   * Intruder: automate method fuzzing to find endpoints accepting unexpected verbs.

5. **Combine with authentication and IDOR tests**

   * Use a low-priv credentials and attempt destructive overrides on other users’ resources.

6. **CORS and preflight checks**

   * Send an `OPTIONS` request with `Access-Control-Request-Method` set to DELETE or PUT; inspect `Access-Control-Allow-Origin` and `Access-Control-Allow-Methods` headers.

7. **Log analysis**

   * Monitor for `X-HTTP-Method-Override` or `_method` entries in logs. Flag GETs that are followed by DB writes.

8. **Automated checks (lab snippet)**

   ```bash
   for m in GET POST PUT DELETE; do
     echo "$m -> $(curl -s -o /dev/null -w "%{http_code}" -X $m "http://localhost:3000/invoices/101")"
   done
   echo "override param -> $(curl -s -o /dev/null -w "%{http_code}" 'http://localhost:3000/invoices/101?_method=DELETE')"
   ```

---

## 7. Remediation: exactly what to change in code, server, proxy and operations

Remediation must be multi-layered: code-level, server/proxy-level, and operational controls.

### 7.1 Code-level fixes (highest priority)

* **Route by method in the framework**: Do not handle multiple actions in a single handler that branches on client input. Use `GET`, `POST`, `PUT`, `DELETE` handlers provided by the framework.

  * Express example:

    ```js
    app.get('/invoices/:id', getInvoice);
    app.delete('/invoices/:id', authenticate, deleteInvoice);
    ```
* **Never trust client-supplied `action`, `method`, or `_method` fields** for critical operations without validating auth and CSRF tokens.
* **Enforce authorization checks per action and per object**: check ownership and roles before performing DELETE/PUT.
* **Validate Content-Type**: For APIs expect `application/json` and reject form-encoded content unless explicitly supported.
* **Separate side effects**: keep the core update operation idempotent and move non-idempotent side effects (e.g., sending emails) to background jobs with deduplication tokens.

### 7.2 Framework and middleware

* **Remove or restrict method-override middleware**. If the application uses middleware that honors `_method` or `X-HTTP-Method-Override`, configure it to only accept overrides from trusted internal flows, and only when paired with a valid CSRF token.
* **CSRF protection**: For browser-based flows, require CSRF tokens on state-changing operations (POST/PUT/DELETE). GET must never change state.

### 7.3 Server / proxy configuration

* **Deny methods you do not need at Nginx/Apache level.** Example Nginx:

  ```nginx
  location /api/ {
    limit_except GET POST {
      deny all;
    }
  }
  ```

  Adjust allowed list for your actual needs.
* **At reverse proxy / API gateway**, strip client-supplied override headers. If method rewriting is necessary, ensure the proxy injects its own trusted header and the backend checks the proxy origin or internal header.
* **Harden CORS**: do not use `Access-Control-Allow-Origin: *` for sensitive endpoints. Use strict origin whitelists.

### 7.4 WAF and perimeter rules

* Block or log requests that include `_method` in query string or body when they are not expected.
* Block `X-HTTP-Method-Override` header from external clients if not required.
* Example ModSecurity rule (test in detection mode before blocking):

  ```apache
  SecRule ARGS_NAMES:_method "@rx .+" "id:200001,phase:1,log,deny,msg:'Block _method param in request'"
  ```

### 7.5 Logging and monitoring

* Log occurrences of override headers and parameters, and alert when such traffic spikes.
* Log any `GET` requests that cause write operations.
* Log origin IP, session id, account id for destructive actions for auditing and rollback.

### 7.6 Tests and CI

* Add unit/integration tests: ensure GET endpoints do not alter state when `_method=DELETE` param is included.
* Add automated pentest-like tests to CI to test method abuse scenarios.
* Example Jest test:

  ```js
  test('GET /invoices/:id does not delete when _method=DELETE', async () => {
    const res = await request(app).get('/invoices/101?_method=DELETE').expect(200);
    expect(res.body.id).toBe('101');
  });
  ```

### 7.7 Operational policies

* Keep soft-deletes and backups for recovery from accidental or malicious deletions.
* Implement rate limits on destructive endpoints to slow mass-deletion attempts.

---

## 8. Framework-specific guidance and code snippets

### Express (Node.js)

**Bad pattern** (don’t do this)

```js
app.all('/invoices/:id', (req, res) => {
  if (req.query._method === 'DELETE') { deleteInvoice(req.params.id); return res.send('deleted'); }
  if (req.method === 'GET') return res.json(getInvoice(req.params.id));
  res.status(405).send('not allowed');
});
```

**Good pattern**

```js
app.get('/invoices/:id', (req, res) => res.json(getInvoice(req.params.id)));
app.delete('/invoices/:id', authenticate, (req, res) => {
  if (!isOwnerOrAdmin(req.user, req.params.id)) return res.status(403).send('forbidden');
  deleteInvoice(req.params.id);
  res.status(204).send();
});
```

### Django (Python)

* Use `@require_http_methods(["GET"])` or `@require_http_methods(["DELETE"])` decorators.
* Use `CsrfViewMiddleware` for forms.
* Example:

```py
from django.views.decorators.http import require_http_methods
@require_http_methods(["GET"])
def invoice_view(request, id):
    return JsonResponse(get_invoice(id))
@require_http_methods(["DELETE"])
def delete_invoice(request, id):
    if not request.user.has_perm('invoices.delete_invoice'):
        return HttpResponseForbidden()
    # perform delete
```

### Rails (Ruby)

* Rails HTML helpers (`link_to`, `form_for`) emulate PUT/DELETE via `_method` but Rails also includes authenticity tokens (CSRF) by default. Keep `protect_from_forgery` enabled.
* Avoid exposing endpoints that accept `_method` without requiring authenticity tokens.

---

## 9. Common pitfalls and advanced edge cases (do not miss these)

1. **Idempotency misunderstandings**: PUT/DELETE are intended to be idempotent. However, developers sometimes put side effects (e.g., incrementing counters, sending notifications) into the same request handling. That makes retries unsafe and complicates recovery.

2. **Caching pitfalls**: If a GET endpoint performs writes, proxies and caches might inadvertently trigger changes (prefetchers), or cache mutated responses.

3. **CORS & preflight abuse**: A permissive CORS policy combined with method override acceptance exposes sensitive verbs to attacker sites.

4. **Proxy double-handling**: If both proxy and backend honor client-supplied overrides, method rewriting becomes inconsistent and unpredictable. Use a single trusted rewrite point.

5. **Logging sensitive data**: If you permit sensitive actions via GET, parameters (passwords, tokens) may appear in logs and referrer headers.

6. **Hidden forms / CSRF tokens**: If server accepts `_method` without verifying a CSRF token, then CSRF attacks can trigger destructive actions via GET.

---

## 10. Combined attack examples (method tampering + other vulnerabilities)

* **Method tampering + IDOR**: Use `_method=DELETE` and change the resource id to another user’s id. If the application does not perform object-level authorization checks, the attacker deletes other users’ resources.

* **Method tampering + CSRF**: If a GET with `_method=DELETE` performs deletion, simply embedding an image tag or link in a page visited by the user will trigger deletion.

* **Method tampering + permissive CORS**: If CORS allows arbitrary origins and server honors `X-HTTP-Method-Override`, an attacker site can perform cross-origin operations using the override.

---

## 11. Practical quick reference: tester’s cheat-sheet

* **Find methods**: `curl -I -X OPTIONS https://target/path`
* **Direct change**: `curl -v -X DELETE https://target/path/123`
* **Query override**: `curl 'https://target/path/123?_method=DELETE'`
* **Header override**: `curl -X POST https://target/path/123 -H 'X-HTTP-Method-Override: DELETE'`
* **Test as other user**: use session cookies or tokens of low-privilege user to attempt method tampering.
* **Check codebase**: grep for `_method`, `X-HTTP-Method-Override`, `.method`, or any `action` fields processed server-side.
* **Log rule**: alert when `GET` causes DB DELETE operations or when override headers appear.

---

## 12. Recovery and operational suggestions

* **Backups & soft-delete**: Use soft-delete (tombstones) so data can be recovered after an accidental deletion.
* **Audit logs**: Keep immutable logs of destructive actions with user, session, timestamp and request data.
* **Rollbacks**: Implement data recovery playbooks for mass deletion incidents.
* **Incident response**: If method-tampering is abused in production, rotate tokens/sessions, block offending IPs, restore from backup if needed, and fix code/config immediately.

---

## 13. what you must take away

* HTTP methods express intent. Servers and intermediaries rely on method semantics; violating them is dangerous.
* HTTP Method Tampering occurs when an attacker changes which method the server thinks the request uses, or when server code trusts client-supplied method-like inputs.
* Common vectors include direct method changes, `_method` params, `X-HTTP-Method-Override` headers, business-logic action fields, and proxy rewriting.
* Fix by enforcing method-based routing, removing or restricting method overrides, enforcing per-action authorization, hardening proxies and WAFs, adding tests and logging, and using defensive patterns like soft-deletes and CSRF protection.
* Always test method tampering only in authorized environments. Add tests to CI to prevent regressions.

---
