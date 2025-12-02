
## 1. overview

* **Cache**: a temporary storage of responses or assets to speed up future requests and reduce origin load.
* **Cache Key**: the unique identifier the cache uses to decide whether a cached response matches an incoming request.
* **Cache headers** (e.g., `Cache-Control`, `Vary`, `Age`, CDN headers) control caching behavior and reveal whether responses are served from cache.
* **HIT / MISS / EXPIRED / BYPASS / STALE**: common cache statuses that tell you if a cached response was served or if origin was contacted.

Understanding how cache keys are built and how cache headers behave is essential to detect and reason about **Web Cache Poisoning** risks.

---

## 2. What is a **Cache Key**?

A **cache key** is the fingerprint or signature a caching layer computes from an HTTP request in order to index and retrieve cached responses. If a cache contains an entry whose key equals the computed key for an incoming request, it serves the cached response; otherwise it forwards the request to the origin server and may store the resulting response under the computed key.

**In short:**
**Cache Key = how the cache recognizes and differentiates requests.**

---

## 3. Why cache keys matter (security & correctness)

* They determine **which requests share a cached response**.
* If a cache key includes or excludes elements inconsistently with the origin’s logic, the cache can serve incorrect or attacker-controlled content to uninvolved users.
* Cache key misconfiguration or origin/cache mismatch is the fundamental cause of **Web Cache Poisoning**.

---

## 4. Common elements used to build a cache key

Caching systems differ, but keys are commonly built from combinations of:

1. **Host header** (`Host`) — the requested hostname/domain.
2. **URL path** — e.g., `/products/iphone`.
3. **Query string / query parameters** — e.g., `?id=55`. Some caches normalize or ignore specific params (e.g., `utm_*`).
4. **HTTP method** — typically only `GET` responses are cached.
5. **Selected request headers** — e.g., `Accept-Encoding`, `Accept-Language`, sometimes `User-Agent` or custom headers if configured.
6. **Cookies** — often cause requests to be treated as uncacheable; including cookie values in keys is rare but dangerous.
7. **Protocol / scheme** (`http` vs `https`) and occasionally port.
8. **URL normalization rules** — trailing slash, case sensitivity, percent-encoding treatment.

**Example key formula (simple):**

```
CacheKey = Host + Path + FilteredSorted(QueryParams) + VaryHeaders
```

---

## 5. Important caching response headers and their meaning

### `Cache-Control`

* Primary directive for caching behavior.
* Common directives:

  * `public`: response may be cached by shared caches (CDN/proxy) and browser caches.
  * `private`: response intended for a single user; shared caches should not store it.
  * `no-cache`: cache must revalidate with origin before serving.
  * `no-store`: do not store the response.
  * `max-age=<seconds>`: freshness lifetime in seconds.
  * `s-maxage=<seconds>`: overrides `max-age` for shared caches.
* **Security impact:** `public` + reflection of user input is a red flag.

### `Age`

* Indicates how many seconds the response has been stored in the cache.
* `Age: 250` means the cached copy is 250 seconds old. If `Age` < `max-age`, the cache copy is fresh.

### `Expires`

* Legacy HTTP header that sets an explicit expiry timestamp. `Cache-Control` overrides `Expires` if both present.

### `Vary`

* Tells caches which request headers the origin varies on (e.g., `Vary: Accept-Encoding, Accept-Language`).
* Caches should treat requests that differ in listed headers as different entries (include them in keying).
* **Mismatch between origin behavior and `Vary` causes correctness and poisoning risk.**

### `ETag`, `Last-Modified`

* Used for conditional requests (`If-None-Match`, `If-Modified-Since`) to validate freshness without full payload.

### `Set-Cookie`

* Presence often makes shared caches treat the response as uncacheable. If cached erroneously, it may leak user-specific data.

### `Content-Encoding`, `Content-Type`, `Content-Length`

* Metadata; `Content-Encoding` variants (gzip/br) may cause caches to store multiple variants — `Vary` should reflect that.

### CDN / proxy informational headers

* `CF-Cache-Status` (Cloudflare) — `HIT`, `MISS`, `EXPIRED`, `BYPASS`, `STALE`, etc.
* `X-Cache` / `X-Cache-Status` (Varnish/other proxies) — similar semantics.
* `X-Cache-Hits`, `X-Served-By`, `Via` — debugging and routing info.

---

## 6. HIT vs MISS and other statuses — practical interpretation

* **HIT**: cache had a fresh entry for the key and served it without contacting origin. If poisoned, HIT spreads the poisoned content to clients that match the key.
* **MISS**: cache did not have an entry; the request reached origin. Origin response may be cached afterwards.
* **EXPIRED**: cached entry exists but is stale; proxy revalidated or fetched new version.
* **BYPASS**: cache was intentionally bypassed (via config or `Cache-Control` directives).
* **STALE**: cache served stale response, possibly while revalidating with origin (`stale-while-revalidate` behavior).
* **DYNAMIC / UNCACHEABLE**: proxy determined the response should not be cached.

**Note:** In multi-tier or globally distributed CDNs, an attacker might populate one edge (HIT there) while other edges remain MISS until propagation.

---

## 7. How mismatches cause poisoning (core scenarios)

1. **Cache key excludes an element that origin uses** to vary responses (e.g., origin uses `Host` to generate links but cache key ignores it) → attacker injects value and cache stores poisoned response under a shared key.
2. **Cache key includes a user-controlled header** that the origin also uses, enabling an attacker to craft requests that create cached responses that serve attacker content to others.
3. **`Vary` header absent or incorrect** for headers that change content → cache treats different requests as identical and shares wrong response.

---

## 8. Practical testing methodology (authorized labs only)

### Tools

* `curl`
* Burp Suite (Proxy, Repeater, Intruder)
* Browser (incognito)
* Multiple networks / VPNs to simulate geographically different clients (for CDN edges)

### Steps

1. **Confirm caching exists**

   ```bash
   curl -I https://target.example/page
   ```

   Look for `Cache-Control`, `Age`, `CF-Cache-Status`, `X-Cache`.

2. **Detect reflected inputs**

   * Find query params or headers that reflect into the response body: e.g., `/page?test=probe123` and search for `probe123` in HTML.

3. **Probe candidate headers**

   * Test headers like `Host`, `X-Forwarded-Host`, `Accept-Language`, `Accept-Encoding`, `X-Original-URL`.

   ```bash
   curl -i -H "X-Forwarded-Host: attacker.example" "https://target.example/page"
   ```

   * Compare responses and check if the injected value appears.

4. **Attempt to populate cache with a benign marker**

   * Send a request containing a unique marker that will be reflected (e.g., `?marker=poison123`) and whose response is cacheable (`Cache-Control: public`, `200`).

   ```bash
   curl -i "https://target.example/page?marker=poison123"
   ```

5. **Test persistence from a separate client**

   * From another client/network (or incognito) request the same resource without the marker or attacker header:

   ```bash
   curl -i "https://target.example/page"
   ```

   * If the marker appears and `CF-Cache-Status` / `X-Cache` is `HIT`, the cached response was shared — poisoning succeeded for that key/edge.

6. **Observe `Age` growth**

   * Repeated requests should show `Age` increasing for HIT responses, indicating cached serving.

7. **Vary checks**

   * Send requests with different `Accept-Language` / `Accept-Encoding` / `User-Agent` to see if origin sets `Vary` and whether cache creates separate entries.

8. **Multi-edge CDN testing**

   * Test from different geographic regions (VPN or external proxies) to see if propagation occurs globally.

---

## 9. Concrete examples

### Example: cacheable reflected query parameter

1. Attacker requests:

   ```
   GET /page?msg=<h1>POISON</h1> HTTP/1.1
   Host: target.example
   ```

   Response:

   ```
   HTTP/1.1 200 OK
   Cache-Control: public, max-age=3600
   CF-Cache-Status: MISS
   Content-Type: text/html

   <html>...<div>msg: <h1>POISON</h1></div>...</html>
   ```

   The origin produced the page and it is cacheable.

2. Later, a victim requests:

   ```
   GET /page HTTP/1.1
   Host: target.example
   ```

   Response:

   ```
   HTTP/1.1 200 OK
   Cache-Control: public, max-age=3600
   CF-Cache-Status: HIT
   Age: 120

   <html>...<div>msg: <h1>POISON</h1></div>...</html>
   ```

   Indicates the poisoned content was stored and served from cache.

### Example: Host header poisoning

* If origin uses `Host` to build absolute links and responds with `Cache-Control: public`, and cache key ignores `Host` or the CDN/edge uses a different notion of host, sending `Host: attacker.example` may create cached pages containing links to attacker domains that other users receive.

---

## 10. Quick `curl` commands to practice (authorized testing only)

* Inspect headers:

  ```bash
  curl -I https://target.example/page
  ```

* Send header to probe influence:

  ```bash
  curl -i -H "X-Forwarded-Host: attacker.example" "https://target.example/page"
  ```

* Inject marker:

  ```bash
  curl -i "https://target.example/page?marker=poison123"
  ```

* Check from another client/network:

  ```bash
  # different network or VPN
  curl -i "https://target.example/page"
  ```

---

## 11. Testing checklist

**Detection**

* [ ] Does the target return `Cache-Control: public` or `s-maxage`?
* [ ] Is `Age` present and does it increase across requests?
* [ ] Do CDN/proxy headers (`CF-Cache-Status`, `X-Cache`) appear?
* [ ] Which query parameters are reflected?
* [ ] Which headers (Host, X-Forwarded-Host, Accept-Language, Accept-Encoding) affect the response?
* [ ] After injecting a marker, does another client receive it with `HIT`?

**Vary / key checks**

* [ ] Is `Vary` present and accurate for headers used to vary content?
* [ ] Are `Set-Cookie` responses being cached incorrectly?

---

## 12. Remediation & safe configuration (developer checklist)

* **Avoid `Cache-Control: public`** on responses that reflect user-controlled input. Use `private`, `no-cache`, or `no-store` for user-specific content.
* **Explicitly define cache key composition** (Host + path + whitelisted query params + specific headers) in CDN/proxy configuration.
* **Do not build absolute URLs from raw `Host` or `X-Forwarded-Host`** without strict validation and whitelist.
* **Ensure `Vary` is correct** for any header that legitimately changes the response (e.g., `Vary: Accept-Encoding, Accept-Language`).
* **Normalize and whitelist query parameters** used in cache keys; ignore tracking parameters like `utm_*`.
* **Do not cache responses containing `Set-Cookie`** unless intended; configure CDN to bypass caching for such responses.
* **Sanitize any reflected input** before including it in responses.
* **Apply Content Security Policy (CSP)** to mitigate impact of injected scripts.
* **Use CDN features** (edge rules) to prevent caching of dynamic or user-specific HTML.
* **Purge/invalidate caches** on content changes as appropriate.
* **Monitor cache metrics** (`X-Cache`, `CF-Cache-Status`) for anomalies.

---

## 13. Security implications & examples of impact

* **Mass XSS**: cached pages containing attacker JavaScript execute for many users.
* **Phishing/Redirects**: cached absolute links or redirect responses can direct users to attacker domains.
* **Content substitution / misinformation**: brand or content replaced across many users.
* **Data leakage**: if user-specific content is cached and served to others, sensitive data may leak.

---

## 14. Summary 

* The **cache key** determines which requests share a cached response.
* The **cache headers** (`Cache-Control`, `Vary`, `Age`, CDN headers) tell you whether a response is cacheable, how long it’s fresh, and whether an edge served it (`HIT`) or origin was contacted (`MISS`).
* **Cache key / origin logic mismatches** are the root cause of Web Cache Poisoning.
* Practical testing requires: identify reflection points, confirm cacheability, inject unique markers, and verify persistence and `HIT` behavior from separate clients.
* **Remediation** centers on proper `Cache-Control`, correct `Vary`, key composition, input sanitization, and CDN configuration.
