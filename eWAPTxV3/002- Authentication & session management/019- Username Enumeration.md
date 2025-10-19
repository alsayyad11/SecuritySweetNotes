
## **1. What is Username Enumeration?**

**Username Enumeration** is an **authentication testing technique** where a tester (or attacker) tries to determine if specific usernames exist in a system — by observing differences in the application’s responses during login, registration, or password recovery.

It’s a common weakness because the system unintentionally **reveals information about user existence** through its behavior or responses.

### **Goal of the Test**

To check if it’s possible to collect a list of valid usernames by interacting with authentication mechanisms such as:

* Login forms
* Registration forms
* “Forgot password” or “Reset password” features

Once valid usernames are discovered, an attacker can use them later in:

* **Brute force attacks** (trying many passwords for known usernames)
* **Credential stuffing** (using leaked credentials from other websites)
* **Social engineering** or **phishing** attacks

---

## **2. Why Username Enumeration Happens**

Many web applications reveal whether a username exists through:

* **Error messages**
* **HTTP response codes**
* **Differences in page content**
* **Response time**
* **Password reset flows**
* **Behavior of multi-step authentication (like 2FA prompts)**

This usually happens due to **misconfiguration** or **poor security design decisions**.

---

## **3. Example Scenarios**

Let’s take some real-world style examples.

### **Example 1 – Login Form Messages**

#### Case 1 (Vulnerable)

A web app returns different error messages:

* For non-existing user:
  `"Username does not exist."`
* For existing user but wrong password:
  `"Incorrect password."`

An attacker can automate requests with a list of usernames and check which ones produce `"Incorrect password"` — confirming valid usernames.

#### Case 2 (Secure)

A secure app returns a **generic message** for all failed logins:

> `"Invalid username or password."`

Now, the attacker cannot tell which part (username or password) failed.

---

### **Example 2 – Password Reset Function**

#### Case 1 (Vulnerable)

When you type an email that doesn’t exist:

> `"No account associated with this email."`

When you type a valid one:

> `"A password reset link has been sent to your email."`

The attacker now knows exactly which emails are registered.

#### Case 2 (Secure)

The app always says:

> `"If the account exists, a password reset link will be sent."`

No information leakage — attacker can’t differentiate between valid and invalid accounts.

---

### **Example 3 – HTTP Response Behavior**

Even if messages are the same, **response patterns** might differ.

| Condition        | Response Time | HTTP Status |
| ---------------- | ------------- | ----------- |
| Valid Username   | 450 ms        | 200         |
| Invalid Username | 220 ms        | 401         |

Attackers can measure timing differences or HTTP status codes to infer user existence.

---

## **4. How Username Enumeration Works**

The process is based on observing **differences in server responses**:

| Indicator                  | Description                                        | Example                                    |
| -------------------------- | -------------------------------------------------- | ------------------------------------------ |
| **Error Messages**         | Different wording for invalid username vs password | “Username not found” vs “Wrong password”   |
| **HTTP Status Codes**      | Different response codes                           | 404 vs 200                                 |
| **Response Times**         | Longer time when user exists due to password check | 500ms vs 200ms                             |
| **Behavioral Differences** | Redirects, 2FA prompts, or UI changes              | Redirecting to “/2fa” after valid username |
| **Content Length**         | Slightly different HTML responses                  | 5,124 bytes vs 5,010 bytes                 |

Attackers automate this with tools like **Burp Suite Intruder**, **ffuf**, or **Hydra** to quickly test hundreds of usernames.

---

## **5. Testing Methodology (Based on WSTG)**

### **Test Objectives**

* Identify if the system reveals whether a username exists.
* Determine all possible locations where such leaks occur (login, registration, reset).

### **Steps to Test**

#### **Step 1: Identify Authentication Entry Points**

Locate all functionalities that accept a username or email:

* `/login`
* `/register`
* `/forgot-password`
* `/api/v1/authenticate`
* Mobile or API endpoints (`/auth/token`)

#### **Step 2: Observe Server Responses**

Try both **valid** and **invalid** usernames (or random ones) and compare responses:

* Messages
* HTTP codes
* Content length
* Response times

#### **Step 3: Automate the Comparison**

Use **Burp Suite Intruder**:

* Set payload positions on the username field.
* Load a wordlist (e.g. common usernames).
* Observe response differences (e.g. length, status, or time).

#### **Step 4: Verify Across Other Channels**

Check other parts of the system like:

* Password reset
* Registration (does it say “Username already exists”?)
* API endpoints (do they return “user not found” in JSON?)

---

## **6. Example Test Walkthrough**

**Scenario:**
Target login endpoint → `https://example.com/login`

**Test Input 1:**
`username=admin&password=wrongpass`
**Response:** “Invalid password.”

**Test Input 2:**
`username=nonexistent&password=wrongpass`
**Response:** “Username does not exist.”

**Observation:**
Different messages → username enumeration possible.

**Risk:**
Attacker can discover all valid usernames (`admin`, `user1`, `staff@company.com`) and then perform targeted brute force attacks.

---

## **7. Why It’s Dangerous**

Once an attacker collects valid usernames:

* **Brute-force efficiency increases** (because attacker only targets real accounts).
* **Credential stuffing becomes feasible.**
* **Phishing attacks** can be personalized using real names/emails.
* **Account takeover** chances rise if users reuse passwords.

This breaks one of the **core principles of authentication confidentiality** — revealing account existence.

---

## **8. How to Prevent Username Enumeration**

| Risk Area                  | Mitigation                                                             |
| -------------------------- | ---------------------------------------------------------------------- |
| **Error Messages**         | Always use **generic** error messages like “Invalid credentials”       |
| **Password Reset**         | Always say “If the account exists, a reset link has been sent”         |
| **Response Time**          | Implement **uniform response delays** for both valid/invalid usernames |
| **HTTP Codes**             | Use consistent status codes (e.g., always return 200)                  |
| **Content**                | Ensure identical HTML structure for all responses                      |
| **CAPTCHA**                | Add CAPTCHA to slow automated enumeration attacks                      |
| **Rate Limiting**          | Lock out or delay repeated failed login attempts                       |
| **Logging and Monitoring** | Detect large numbers of failed username attempts                       |

---

## **9. Example of Secure Implementation**

Here’s how a **secure login process** should respond:

### Request:

```
POST /login
username=anything@example.com&password=randompass
```

### Response (always):

```
HTTP/1.1 200 OK
{"message": "Invalid username or password."}
```

Even if the username doesn’t exist, the response, timing, and status are identical.

---

## **10. Note**

**Username Enumeration** may seem minor, but it’s the **foundation** for many large-scale attacks.
It helps attackers build valid user lists — making **brute force, credential stuffing, and social engineering** far more effective.

A secure system must:

* Hide all account existence indicators
* Standardize responses
* Apply rate limiting and CAPTCHAs
* Monitor failed login behavior

---
