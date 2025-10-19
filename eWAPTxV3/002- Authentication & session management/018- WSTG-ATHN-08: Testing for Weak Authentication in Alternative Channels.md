

## **Introduction**

Even if the **primary authentication mechanism** of a web application (for example, the main website’s login) is implemented securely, there may exist **alternative legitimate authentication channels** that share the same user accounts but use **weaker or inconsistent security controls**.

These alternative channels may be web-based (with different hostnames or paths), or entirely separate systems like **mobile apps**, **APIs**, or **call-center interfaces**.

An attacker could use such a weaker channel to:

* **Bypass strong authentication** protections enforced in the main web interface.
* **Enumerate users** or **obtain sensitive data** that can later be used to compromise the primary system.
* **Authenticate or reset passwords** using weaker or outdated mechanisms.

Therefore, testing for authentication weaknesses in **alternative channels** is a critical part of a comprehensive application security assessment.

---

## **Test Objectives**

1. Identify **all possible authentication channels** that share user accounts with the target system.
2. Determine whether **any alternative channel** uses **less secure authentication controls**.
3. Verify whether these alternative channels can **bypass** security mechanisms of the primary authentication process.
4. Assess if **information disclosure** through any alternative channel can **assist attacks** on the main one.
5. Evaluate whether **session management**, **MFA**, and **rate-limiting protections** are applied consistently across all channels.

---

## **Understanding Alternative Channels**

### **Typical Alternative Channels**

| Type                                   | Description                         | Example Weakness                            |
| -------------------------------------- | ----------------------------------- | ------------------------------------------- |
| **Standard Website**                   | The main production site            | Strong HTTPS + MFA                          |
| **Mobile or Device-Optimized Website** | Simplified site for phones          | Often lacks TLS or MFA                      |
| **Accessibility Website**              | Screen-reader optimized version     | May skip CAPTCHA or strong session controls |
| **Alternative Country/Lang Websites**  | Localized mirrors                   | May run older codebase                      |
| **Partner or Sister Websites**         | Shared accounts with partners       | May have weaker password reset              |
| **Development / UAT / Staging**        | Non-production copies               | Usually have real data but no controls      |
| **Mobile App**                         | Android/iOS app using API endpoints | May send credentials over HTTP              |
| **Desktop App**                        | Local client using stored tokens    | May save tokens in plain text               |
| **Call Center or IVR Systems**         | Authenticate via phone or operator  | Weak identity verification questions        |

---

## **Why This Matters**

Security is only as strong as its weakest channel.
If the main site enforces strong HTTPS + MFA but the mobile API allows password login without MFA or TLS, attackers will simply **shift their attacks to that weaker channel**.

Thus, identifying all **points of authentication** and verifying **uniform strength** is crucial.

---

## **Example Scenario**

The main site uses HTTPS and MFA:

```
https://www.example.com/login
```

But the mobile site uses:

```
http://m.example.com/login
```

It transmits credentials **without encryption** and allows password resets without verifying ownership via email or MFA.

An attacker can capture plaintext credentials using a simple network sniffer or a rogue Wi-Fi hotspot, then reuse them to log in to the main site.

---

## **Testing Methodology**

### **1. Understand the Primary Mechanism**

Before exploring alternatives, you must fully understand the main authentication logic:

* How accounts are created and managed
* How login, logout, password reset, and MFA function
* How session tokens are issued and validated
* What anti-brute-force protections are used

This knowledge allows comparison later against other channels.

---

### **2. Identify Other Channels**

Use a combination of **manual research** and **technical reconnaissance**:

**Manual Enumeration:**

* Read the site’s *Home*, *Help*, *Contact*, *FAQ*, and *Privacy* pages for mentions of mobile apps or alternative portals.
* Check the **robots.txt** and **sitemap.xml** files for unlisted paths or subdomains.
* Look for links such as:

  ```
  https://m.example.com/
  https://mobile.example.com/
  https://partner.example.com/
  https://uat.example.com/
  ```

**Automated Discovery:**

* Analyze proxy logs captured during prior testing for URLs containing:

  ```
  mobile, android, iphone, ipad, app, auth, sso, login, api
  ```
* Use search engines to find related domains of the same organization.
  Example:

  ```
  site:example.com login OR myaccount
  ```
* Decompile mobile apps or inspect their traffic to identify authentication endpoints.
* Check for staging environments like:

  ```
  dev.example.com, test.example.com, uat.example.com
  ```

Document every potential channel and verify if **user accounts are shared** between them.

---

### **3. Enumerate Authentication Functionality**

For each discovered channel, list the available authentication functions.
For instance:

| Function        | Primary | Mobile | Call Center | Partner Site |
| --------------- | ------- | ------ | ----------- | ------------ |
| Register        | Yes     | -      | -           | -            |
| Log in          | Yes     | Yes    | Yes (SSO)   | Yes          |
| Log out         | Yes     | -      | -           | -            |
| Reset Password  | Yes     | Yes    | -           | -            |
| Change Password | -       | Yes    | -           | -            |

This helps you quickly spot **differences or missing controls**.
Example: The mobile site allows password change but has no logout feature — a session management weakness.

---

### **4. Compare Authentication Controls**

For each channel, assess the following controls and note discrepancies:

| Control               | What to Check              | Example of Weakness                   |
| --------------------- | -------------------------- | ------------------------------------- |
| **Transport Layer**   | HTTPS/TLS enforced         | Mobile login uses HTTP                |
| **Password Policy**   | Minimum length, complexity | Mobile allows 4-digit passwords       |
| **MFA Enforcement**   | Consistent requirement     | API login skips MFA                   |
| **Lockout Mechanism** | Same failure limit?        | API allows unlimited attempts         |
| **CAPTCHA**           | Used on all forms          | CAPTCHA only on web login             |
| **Token Management**  | Token structure, expiry    | Static or permanent API tokens        |
| **Session Scope**     | Shared cookies/tokens      | Same session usable across subdomains |

---

### **5. Test for Bypasses**

Once differences are found, attempt to **use weaker channels** to access accounts.

**Example 1:**

* The web login requires password + OTP.
* The mobile API allows password only.

Send the following request (intercepted via Burp Suite):

```http
POST /api/v1/login
Content-Type: application/json

{"username": "victim@example.com", "password": "Password123"}
```

If the response contains a valid token, the attacker has bypassed MFA.

**Example 2:**

* Web app limits login attempts to 5.
* API endpoint `/api/login` has no rate limit.
* Use `ffuf`, `hydra`, or `burp intruder` to brute force credentials.

---

### **6. Session Management Considerations**

When accounts can be accessed through multiple channels:

* Check if sessions are **shared** (same cookie domain).
* Verify if concurrent sessions are allowed between web and mobile.
* Check for **logout synchronization** — does logging out in one channel terminate the others?

---

### **7. Testing Token-Based and API Authentication**

Many mobile and desktop apps authenticate using **API keys**, **JWTs**, or **OAuth tokens**.

Check for:

* Weak JWT signatures (e.g., “alg”: “none”).
* Hardcoded API keys within app code.
* Tokens with no expiry date.
* Tokens reused across different users.
* Tokens not tied to specific scopes (over-privileged).

**Example:**
Extracted from a decompiled Android app:

```
X-API-Key: 7a8f9e2cbd12
```

If this static key grants full access to the API, anyone with it can authenticate.

---

### **8. Assess Identity Verification in Non-Web Channels**

Call centers and IVR systems often use simple **security questions** like:

* “What is your date of birth?”
* “What is your pet’s name?”

These can be guessed or found via social media, allowing an attacker to impersonate a user and request account changes.

---

### **9. Review and Report**

* Document every discovered channel, even if out of scope.
* Indicate whether they use **shared authentication** or **shared session management**.
* Compare all protection levels and highlight inconsistencies.
* Recommend harmonization of security controls.

---

## **Example**

**Primary Channel:**
`https://www.example.com/myaccount/` — uses HTTPS and strong password policy.

**Alternative Channel:**
`https://m.example.com/myaccount/` — mobile version, no TLS and weak password reset.

**Impact:**
An attacker sniffing mobile traffic can capture credentials, which can then be reused on the secure main site.

---

## **Remediation**

1. **Apply a Unified Authentication Policy**

   * Enforce the same password complexity, MFA, and lockout thresholds on all channels.

2. **Centralize Authentication**

   * Use a single authentication service or identity provider (e.g., OAuth2, OpenID Connect).

3. **Enforce TLS Everywhere**

   * Every channel must use strong HTTPS/TLS (TLS 1.2+).

4. **Secure Alternative Interfaces**

   * APIs, mobile, and partner systems must implement equal protection.

5. **Review Account Recovery**

   * Consistent token lifetime and verification for password reset flows.

6. **Implement Central Logging & Monitoring**

   * Correlate login events across web, API, and mobile to detect anomalies.

7. **Penetration Testing Across All Channels**

   * Include staging, mobile, and API interfaces in every pentest cycle.

---

## **Related Test Cases**

All other authentication test cases from WSTG (ATHN-01 to ATHN-09) should be executed on each identified channel — including:

* Default credentials testing
* Lockout mechanism testing
* Authentication bypass testing
* Password reset testing
* Session management consistency

---

## **Notes**

* **Do not assume security uniformity.** Each channel must be tested.
* **Alternative interfaces can bypass strong primary controls.**
* **Comprehensive discovery** is vital — including mobile, API, partner, and support portals.
* **Consistent policies** across all authentication endpoints prevent lateral bypass.
* **Even if untested**, the mere **existence** of alternative channels must be documented — as they may reduce confidence in the overall security posture.

---
