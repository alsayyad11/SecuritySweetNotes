
**Evasion** is a crucial concept in web application penetration testing. It refers to techniques that attackers use to **bypass security mechanisms** in web applications to deliver malicious payloads or exploit vulnerabilities.

Before we dive into evasion, it’s important to understand **web application security mechanisms**.

---

## **1. Web Application Security Mechanisms**

Web applications have multiple layers of defense to protect against attacks:

### **1.1 Authentication**

* Verifies user identity to ensure that only legitimate users access resources.
* **Common methods**:

  * Username and password
  * Multi-factor authentication (MFA)
  * Biometrics

**Example:**
A login form checks credentials and allows access only if they match a database record.

---

### **1.2 Authorization**

* Determines what an authenticated user can access.
* Assigns **roles and permissions** to users.

**Example:**

| Role        | Permissions                                   |
| ----------- | --------------------------------------------- |
| Admin       | Full access (users, plugins, settings)        |
| Editor      | Edit and publish content but no plugin access |
| Contributor | Submit posts for review                       |
| Subscriber  | Read-only access                              |

---

### **1.3 Input Validation & Filtering**

* Validates and sanitizes user input to prevent attacks like **SQL Injection, XSS, Command Injection**.

**Example:**
Sanitizing `<script>` tags in user input prevents XSS.

---

### **1.4 Session Management**

* Maintains secure user sessions.
* **Techniques**:

  * Secure session tokens
  * Session expiration
  * Protection against session fixation

---

### **1.5 CSRF Protection**

* Prevents attackers from tricking users into performing actions they didn’t intend.
* **Implementation**: Anti-CSRF tokens in forms.

---

### **1.6 Security Headers**

* **HTTP headers** control browser behavior to enhance security.
* Examples:

  * `Content-Security-Policy (CSP)`
  * `X-Content-Type-Options`
  * `X-Frame-Options`

---

### **1.7 Rate Limiting**

* Limits the number of requests from a user or IP to prevent **brute force attacks** and **DDoS attempts**.

---

### **1.8 Web Application Defense Mechanisms**

* **Web Application Firewall (WAF)**: Monitors and filters malicious web traffic.
* **Intrusion Detection/Prevention Systems (IDS/IPS)**: Detect or block suspicious network traffic.
* **Proxies**: Intermediary servers that manage traffic, caching, and security.

---

## **2. Evasion Techniques**

Evasion is the art of **bypassing these security mechanisms**. Attackers try to deliver malicious payloads without being detected.

### **2.1 Bypassing WAFs and Proxy Rules**

WAFs and proxies inspect traffic and block attacks like SQLi or XSS. Evasion may involve:

* **Encoding**: Converting characters into safe formats (e.g., URL encoding, Base64)
* **Obfuscation**: Hiding payloads in unusual formats
* **Fragmentation**: Splitting payloads across multiple requests

**Example – SQL Injection evasion:**

Normal attack blocked by WAF:

```sql
SELECT * FROM users WHERE username='admin' AND password='password';
```

Encoded payload bypassing WAF:

```
username=admin%27%20OR%201=1-- 
```

---

### **2.2 Evading IDS Systems**

* IDS monitors traffic for suspicious patterns.
* Techniques:

  * Fragmenting packets
  * Using uncommon encodings
  * Altering payload signatures

**Example:**
Sending SQL injection payload split across multiple HTTP requests to avoid detection.

---

### **2.3 Circumventing Input Validation**

* Attackers craft input that **appears legitimate** but exploits vulnerabilities.

**Example – Bypassing a form filter:**

* Filter blocks `<script>` but allows `<scr<script>ipt>` → XSS executes

---

### **2.4 Avoiding Rate Limiting and Authentication Controls**

* Attackers can use:

  * Multiple IP addresses (IP rotation)
  * Delays between requests
  * Automated tools that mimic legitimate behavior

**Example:**
Brute force login using TOR network to bypass rate limiting on `/wp-login.php`.

---

## **3. WAFs vs Proxies**

| Feature             | WAF                          | Proxy                                       |
| ------------------- | ---------------------------- | ------------------------------------------- |
| Primary Purpose     | Web application security     | Versatile (caching, traffic management)     |
| Traffic Handling    | Analyzes/filters web traffic | Intermediary server                         |
| Security Focus      | Specialized in security      | May include security as one of several uses |
| Rule Sets           | Predefined security rules    | Flexible, can be custom                     |
| Deployment Location | In front of web apps         | Various network locations                   |
| Targeted Threats    | SQLi, XSS, etc.              | Content filtering, Geo/IP blocking          |
| Use Cases           | Protect web apps             | Load balancing, caching, traffic control    |

---

## **4. Bypassing Squid Proxy**

**Squid Proxy Overview:**

* Open-source proxy and caching server
* Intermediary between clients and servers
* Features:

  * **Caching**: Stores frequently requested content
  * **Access Control**: Limits sites based on user/IP
  * **Content Filtering**: Blocks websites or categories

**Evasion Example:**

* Squid blocks social media via URL pattern matching
* Evasion: Using **HTTPS tunneling** or **URL encoding** to bypass filtering

  * Example: `https://%77%77%77%2E%66%61%63%65%62%6F%6F%6B.com` (encoded URL bypasses filter)

---

## **5. Practical Step-by-Step Evasion Lab Example**

**Scenario:** XSS attack blocked by WAF and CSP

1. Attempted payload:

```html
<script>alert("XSS")</script>
```

* **Blocked by WAF/CSP**

2. Encode payload:

```html
%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E
```

* Bypasses WAF detection

3. Fragmented payload:

```html
<scr<script>ipt>alert('XSS')</scr<script>ipt>
```

* Confuses input filter, executed by browser

---

##  **Takeaways**

1. Evasion is about **circumventing security controls** to exploit vulnerabilities.
2. Common targets include **WAFs, IDS, input validation filters, authentication, and proxies**.
3. Techniques include **encoding, obfuscation, fragmentation, and rate-limiting circumvention**.
4. WAFs and proxies are **complementary defenses**, but attackers can bypass them with advanced evasion techniques.
5. Practical testing helps **identify weaknesses** and improve web application defenses.
