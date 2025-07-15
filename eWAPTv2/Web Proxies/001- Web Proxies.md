
<img width="960" height="322" alt="image2-2" src="https://github.com/user-attachments/assets/3c0411b7-491a-4d34-b1e8-748de0eb1525" />

## 1. What is a Web Proxy (Interception Proxy)?

A **web proxy**, or **interception proxy**, is a tool used in web application security testing to **intercept**, **inspect**, and **modify** HTTP and HTTPS requests and responses **in real-time** as they pass between a **client** (typically a browser) and a **web server**.

This allows penetration testers to:

* Observe how web applications behave under different inputs
* Understand the structure and flow of the application
* Discover and exploit vulnerabilities that may not be visible through the frontend

Web proxies operate at the **application layer**, which means they allow detailed inspection of the data being transmitted, including parameters, headers, cookies, JSON bodies, and more.

---

## 2. Why Are Web Proxies Essential in Pentesting?

Web proxies play a **central role** in almost every manual web application penetration test. Here's why:

* **Visibility**: They provide full visibility into the data exchanged between browser and server, including things that are hidden from the user interface (e.g., hidden fields, background requests, APIs).

* **Manipulation**: Testers can intercept and modify both requests and responses before they reach their destination. This helps test for vulnerabilities like parameter tampering, IDOR, authentication bypass, and others.

* **Exploration**: They allow testers to explore unlinked or undocumented endpoints by passively capturing traffic or actively fuzzing.

* **Automation**: Tools like Burp Suite include features such as automated scanning, fuzzing, and session handling that extend the effectiveness of testing.

* **Testing Business Logic**: Proxies make it easy to test multi-step processes such as shopping carts, login flows, password resets, and more.

---

## 3. How Web Proxies Work — Behind the Scenes

### Workflow Overview:

1. The browser is configured to send all HTTP/HTTPS traffic to the proxy.
2. The proxy listens for incoming traffic on a local port (e.g., 127.0.0.1:8080).
3. Each request from the browser is intercepted by the proxy before being sent to the server.
4. The tester can view, modify, forward, or drop the request.
5. The server responds, and the proxy again intercepts the response.
6. The tester can inspect or modify the response before it’s displayed in the browser.

This full-cycle interception provides **two-way visibility and control**.

---

## 4. Intercepting HTTPS Traffic — SSL/TLS Interception

Intercepting HTTPS traffic introduces an additional challenge, since HTTPS encrypts communication using SSL/TLS.

To decrypt this traffic:

* The proxy **generates its own SSL certificate**
* You must install the proxy’s **Root Certificate Authority (CA)** in your browser or system
* The browser will then trust the proxy and allow it to perform **Man-in-the-Middle (MitM)** decryption

This is necessary to view and modify encrypted traffic.

> If the certificate is not installed, HTTPS traffic will trigger browser warnings and cannot be properly intercepted.

---

## 5. Common Features in Web Proxies

### Manual Interception:

* Pause and modify requests or responses before they proceed

### Request/Response History:

* Track every HTTP/S transaction
* Organize them into folders by domain/path

### Site Map:

* Automatically build a visual map of the application's structure
* Group requests by endpoints or functionality

### Repeater:

* Re-send and modify individual requests repeatedly
* Useful for testing payloads and analyzing behavior

### Intruder:

* Automate the sending of multiple payloads
* Used for fuzzing, brute-forcing, and input injection

### Scanner (Burp Suite Pro):

* Automatically detect vulnerabilities (e.g., XSS, SQLi, SSRF)
* Perform passive and active scans

### Extensions:

* Add custom functionality via extensions and plugins
* Burp has BApp Store, ZAP supports scripting and community add-ons

---

## 6. Common Use Cases of Web Proxies in Pentesting

| Task                               | Description                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------------- |
| **Analyzing Web Traffic**          | View all headers, parameters, cookies, and content sent between browser and server    |
| **Parameter Tampering**            | Modify GET/POST/JSON/XML parameters to test for IDOR, privilege escalation, etc.      |
| **Authentication Testing**         | Replay tokens, change roles, test login and session management                        |
| **Cookie and Header Manipulation** | Edit session cookies or headers like `X-Forwarded-For`, `User-Agent`, `Authorization` |
| **File Upload Testing**            | Intercept and modify file metadata, bypass client-side filters                        |
| **CSRF/XSS/SQLi Testing**          | Inject payloads into request fields or headers and observe behavior                   |
| **Forced Browsing**                | Discover and access hidden endpoints or admin panels                                  |
| **Business Logic Testing**         | Interact with multi-step workflows and test logic flaws (e.g., cart manipulation)     |

---

## 7. Web Proxy vs. Proxy Server

These terms are often confused but refer to different technologies.

### Web Proxy (Interception Proxy)

<img width="1913" height="654" alt="S" src="https://github.com/user-attachments/assets/ad7237f8-7695-4a3c-b0c0-026fd5c52d00" />

* Purpose: Analyze and test web application traffic
* Used by: Security researchers and penetration testers
* Examples: Burp Suite, OWASP ZAP
* Traffic Level: HTTP/HTTPS only
* Visibility: Full access to request/response contents
* Operates: On the tester’s machine, local proxy

### Proxy Server

<img width="1908" height="591" alt="Sc" src="https://github.com/user-attachments/assets/9ffad46e-9444-4020-b6db-24a9c7db05d1" />

* Purpose: Route, filter, cache, and monitor internet traffic
* Used by: Network administrators and IT departments
* Examples: Squid, Blue Coat, Privoxy
* Traffic Level: General network traffic (TCP/IP)
* Visibility: Limited to routing headers and metadata
* Operates: On a network gateway or firewall

  ---
  

| Feature             | Web Proxy (Burp/ZAP)        | Proxy Server (Squid)       |
| ------------------- | --------------------------- | -------------------------- |
| Main Use            | Security testing            | Network management         |
| Intercept Traffic   | Yes (full request/response) | Partially (metadata level) |
| Traffic Types       | HTTP/HTTPS                  | Any internet protocol      |
| Configuration Scope | Local (per device)          | Network-wide               |
| Visibility Level    | Application layer           | Transport layer            |

---

## 8. Popular Tools

| Tool              | Type                                     | Description                                                                   |
| ----------------- | ---------------------------------------- | ----------------------------------------------------------------------------- |
| **Burp Suite**    | Commercial (with free Community edition) | Industry standard; includes tools like Repeater, Intruder, Scanner (Pro only) |
| **OWASP ZAP**     | Open-source                              | Beginner-friendly; supports automation and scripting                          |
| **Fiddler**       | Free                                     | Used more for debugging, but supports HTTP/HTTPS interception                 |
| **Charles Proxy** | Paid                                     | GUI-based tool often used by developers and mobile testers                    |

---

## 9. Examples

### IDOR Testing

Intercept the following request:

```
GET /api/users/1001 HTTP/1.1
Authorization: Bearer abc123
```

Modify `1001` to `1002` and observe if unauthorized data is returned.

### Cookie Tampering

Modify the following:

```
Cookie: role=admin
```

to

```
Cookie: role=user
```

Or vice versa, and test for access control flaws.

### Upload Bypass

Change filename in a multipart/form-data request:

```
Content-Disposition: form-data; name="file"; filename="payload.php.jpg"
```

to:

```
Content-Disposition: form-data; name="file"; filename="payload.php"
```

to bypass file extension filters.

---

