
## **1. Introduction**

Browser caching is a mechanism used by browsers to **store copies of web pages, images, scripts, and responses locally** to improve performance and reduce network load.

While caching improves speed and user experience, it can introduce **serious security vulnerabilities** if **sensitive information** (like authentication tokens, personal data, or session details) gets cached and later accessed by **unauthorized users**.

In other words:

> If private pages or data are cached, attackers could retrieve them from browser history, disk cache, or proxy cache — even after logout.

---

## **2. Objective of the Test**

The goal is to determine whether **sensitive pages or data** are being improperly cached by:

* **User’s browser**
* **Intermediate proxies**
* **CDNs**
* **Shared systems**

You want to make sure that **authenticated or confidential content** is never cached unless absolutely safe.

---

## **3. Why It’s Dangerous**

Caching sensitive content can lead to:

| Scenario                   | Description                                                                                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Shared System Exposure** | On a shared computer, cached pages may be accessible to the next user through the browser’s “Back” or “History” features. |
| **Proxy Cache Leakage**    | If a web proxy or CDN caches private content, other users could retrieve it without authentication.                       |
| **Post-Logout Exposure**   | Sensitive data remains viewable via the browser’s “Back” button even after logging out.                                   |
| **Local File Disclosure**  | Cached files stored on disk can be extracted by malware or local attackers.                                               |

---

## **4. Real-World Example**

Let’s say you log in to a banking portal and navigate to:

```
https://bank.example.com/account/summary
```

If the response headers don’t prevent caching, your browser may store that page.

Now imagine:

* You log out.
* Another person uses the same computer and clicks **Back** in the browser.

They’ll see your account details — even though you’re logged out.

That’s a **browser cache weakness**.

---

## **5. HTTP Caching Mechanism**

Caching behavior is controlled primarily via **HTTP response headers**:

| Header                  | Purpose                                                              |
| ----------------------- | -------------------------------------------------------------------- |
| `Cache-Control`         | Main directive for controlling caching behavior.                     |
| `Pragma`                | Older HTTP/1.0 directive for cache control (used for compatibility). |
| `Expires`               | Sets a specific date/time when cached content becomes invalid.       |
| `ETag`, `Last-Modified` | Used for cache validation and conditional requests.                  |

---

## **6. Sensitive Data That Should Never Be Cached**

* Authentication pages (`/login`, `/logout`)
* Account or profile pages
* Banking or payment data
* Personal identifiable information (PII)
* Password reset forms
* Admin dashboards
* API responses containing confidential data

---

## **7. How to Test**

### **Step 1: Identify Sensitive Pages**

Check all pages after authentication (like `/dashboard`, `/profile`, `/settings`, `/transactions`) — these must not be cached.

---

### **Step 2: Inspect Response Headers**

Use **Burp Suite**, **OWASP ZAP**, or **Browser Developer Tools → Network tab** to check server response headers.

Example (insecure):

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: public, max-age=3600
```

This means the page can be stored in the cache for **one hour**, even if it contains private info.

Example (secure):

```http
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

---

### **Step 3: Check Browser Behavior**

After logging out:

1. Press the **Back** button — does the previous private page appear?
2. Open browser history or cached files.
3. Try reopening the same URL without logging in — is it served from cache?

If yes → caching is misconfigured.

---

### **Step 4: Check Proxy/CDN Cache Behavior**

If the app uses CDNs (e.g., Cloudflare, Akamai), ensure that sensitive responses are not cached at the **edge**.

To test:

* Review CDN configuration.
* Send repeated requests with different session cookies.
* If the same cached response is returned for different users → proxy caching issue.

---

### **Step 5: Test Browser Autocomplete and Form Caching**

Check if input fields (username, password, credit card info) use:

```html
<input type="text" name="cc_number" autocomplete="off">
```

If not, browsers may store these values locally, exposing them to other users.

---

## **8. Practical Example**

### **Scenario:**

An e-commerce admin dashboard page returns:

```http
Cache-Control: private, max-age=3600
```

This instructs the browser to cache it for one hour.
If an admin logs out and another user uses the same device, the dashboard can still be accessed through the browser cache.

### **Exploit:**

1. Login as admin.
2. Visit `/admin/dashboard`.
3. Logout.
4. Click **Back** button → Dashboard reappears.
5. Or view source via `Ctrl + U` → sensitive info still visible.

---

## **9. Common Misconfigurations**

| Misconfiguration                     | Description                           | Risk                                    |
| ------------------------------------ | ------------------------------------- | --------------------------------------- |
| **No Cache-Control Header**          | Browser defaults to caching.          | Sensitive pages stored locally.         |
| **Cache-Control: public**            | Allows proxies to cache private data. | Anyone behind same proxy can access it. |
| **Missing Pragma / Expires Headers** | Older browsers ignore caching rules.  | Legacy exposure.                        |
| **Partial Cache Control**            | Only static assets protected.         | Dynamic HTML cached.                    |

---

## **10. Recommended Security Headers**

To **fully disable caching of sensitive pages**, always include:

```http
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

**Explanation:**

| Header             | Purpose                                                              |
| ------------------ | -------------------------------------------------------------------- |
| `no-cache`         | Forces revalidation before serving cached content.                   |
| `no-store`         | Prevents browsers and proxies from storing any part of the response. |
| `must-revalidate`  | Forces client to obey cache rules strictly.                          |
| `Pragma: no-cache` | Backward compatibility with HTTP/1.0.                                |
| `Expires: 0`       | Ensures immediate expiry.                                            |

---

## **11. Testing Tools and Techniques**

| Tool                        | Usage                                                              |
| --------------------------- | ------------------------------------------------------------------ |
| **Burp Suite / ZAP**        | Inspect HTTP headers, replay requests, and check caching behavior. |
| **Browser DevTools**        | Network tab → check caching headers and responses.                 |
| **Curl / Postman**          | Send requests manually and analyze headers.                        |
| **Proxy / CDN Logs**        | Determine if responses are being cached on the edge.               |
| **Manual Back-Button Test** | Check whether sensitive data reappears post-logout.                |

**Example (using curl):**

```bash
curl -I https://example.com/account
```

Output:

```http
HTTP/1.1 200 OK
Cache-Control: public, max-age=600
```

→ Vulnerable to caching issue.

---

## **12. Real-World Cases**

### **Case 1: Shared Kiosk Exposure**

A university portal allowed students to log in on public kiosks.
After logout, clicking the back button reopened grades and personal info — due to cached pages.

**Fix:** Add proper cache headers and clear session data on logout.

---

### **Case 2: CDN Caching Leak**

An e-commerce site cached dynamic HTML at the CDN level using `Cache-Control: public`.
As a result, one user’s order details were visible to another via cached responses.

**Fix:** Set `Cache-Control: private, no-store` for personalized content.

---

## **13. Securing Against Browser Cache Weaknesses**

### **1. Disable Caching for Sensitive Content**

Add:

```http
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

### **2. Set Cache-Control per Resource Type**

* Allow caching for static resources (images, CSS, JS).
* Disable caching for dynamic or sensitive pages.

Example:

```apache
# Apache .htaccess example
<FilesMatch "\.(html|php)$">
    Header set Cache-Control "no-cache, no-store, must-revalidate"
    Header set Pragma "no-cache"
    Header set Expires "0"
</FilesMatch>
```

### **3. Implement Proper Logout Mechanisms**

When a user logs out:

* Destroy session server-side.
* Invalidate tokens.
* Force re-authentication for sensitive routes.

### **4. Avoid Storing Sensitive Data in GET URLs**

Because URLs may be cached, logged, or stored in browser history.

### **5. Secure Form Data**

Use:

```html
autocomplete="off"
```

for login, credit card, and personal data fields.

---

## **14. Testing Checklist**

| # | Test                                            | Expected Result                       |
| - | ----------------------------------------------- | ------------------------------------- |
| 1 | Check `Cache-Control` header on sensitive pages | `no-cache, no-store, must-revalidate` |
| 2 | Check `Pragma` and `Expires` headers            | `Pragma: no-cache`, `Expires: 0`      |
| 3 | Test browser “Back” button after logout         | Page should not reappear              |
| 4 | Check CDN/proxy caching                         | No sensitive data cached              |
| 5 | Check input fields for `autocomplete`           | Should be `off` for sensitive fields  |
| 6 | Review logout mechanism                         | Session cleared and cache invalidated |

---

## **15. Example of Secure Configuration**

**Secure Response Headers Example:**

```http
HTTP/1.1 200 OK
Content-Type: text/html
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Result:

* Browser does not cache.
* Proxy does not cache.
* User cannot retrieve private data post-logout.

---

## **16. Summary**

| Concept          | Description                                              |
| ---------------- | -------------------------------------------------------- |
| **Goal**         | Prevent caching of private or authenticated content.     |
| **Main Headers** | `Cache-Control`, `Pragma`, `Expires`.                    |
| **Risks**        | Data exposure through history, back button, proxy cache. |
| **Fix**          | Use strict cache control and secure logout mechanisms.   |

---
