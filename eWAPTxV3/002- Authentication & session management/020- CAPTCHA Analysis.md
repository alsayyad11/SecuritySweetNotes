

## 1. Introduction

This test focuses on evaluating whether a web application’s **lockout mechanisms**, such as **account lockout policies** and **CAPTCHA integrations**, effectively prevent **automated brute-force or credential-stuffing attacks** after multiple failed login attempts.

A secure authentication system must include rate-limiting or lockout controls to slow down or block repeated failed login attempts.
However, if these mechanisms (especially CAPTCHAs) are **weak**, **poorly configured**, or **implemented only on the client side**, attackers can easily bypass them — allowing mass-scale login attacks and possible **account takeovers**.

---

## 2. Testing Objective

> **Goal:** Evaluate whether CAPTCHA or other lockout mechanisms can be bypassed to continue automated login attempts (brute-force or dictionary attacks).

The tester should determine if:

* The system introduces CAPTCHA or other friction after a certain number of failed logins.
* The CAPTCHA can be **automatically solved**, **reused**, or **skipped**.
* Lockout thresholds are **too lenient** (e.g., only after 20 failed logins).
* Account lockout messages **reveal information** that aids username enumeration.
* Lockout resets **too quickly** (temporary lockout with predictable duration).

---

## 3. Background — Why Weak Lockout Is Dangerous

When CAPTCHA or lockout mechanisms are improperly implemented:

* Attackers can attempt **thousands of password guesses per minute**.
* Attackers can **verify valid usernames** based on response timing or error messages.
* Once a CAPTCHA token is **reused** or **globally shared**, the protection is lost.
* Weak lockouts that reset quickly allow distributed attacks (different IPs, same username).

Example:

```text
Attacker tries 5 invalid passwords → CAPTCHA appears.
Attacker reuses the same CAPTCHA token or bypasses validation.
System accepts the next 1000 attempts → brute-force succeeds.
```

Result → Account compromise.

---

## 4. Common Weak Lockout Mechanisms

### 4.1 No Lockout or Unlimited Attempts

* The system never locks or slows requests after repeated failures.
* Common in legacy or misconfigured APIs.

### 4.2 Weak or Predictable Lockout Threshold

* Account locked only after a high number (e.g., 10+) of failures.
* Lockout duration short (e.g., 30 seconds), allowing continuous guessing.

### 4.3 CAPTCHA After Threshold — But Weak Implementation

* CAPTCHA appears, but can be bypassed by automation, replay, or omission.
* Some systems only show CAPTCHA **on UI layer**, not on API endpoints.

### 4.4 Lockout on Username Only

* Attackers can cause **denial of service** by locking legitimate users out deliberately.

### 4.5 No Global Rate Limiting

* Multiple IPs can attack the same account (distributed brute-force).

---

## 5. CAPTCHA and Lockout — How They Interact

CAPTCHAs are often used as part of lockout or rate-limiting logic:

* After **N failed logins**, the application displays a CAPTCHA.
* Only after solving the CAPTCHA can the user retry login.

This mechanism slows down bots, but **its security depends on CAPTCHA strength**.

If CAPTCHA is weak or can be bypassed (token reuse, client-side-only validation, weak image type, etc.), attackers can **continue automated login attempts unhindered**.

---

## 6. Types of CAPTCHAs (Ranked from Weakest to Strongest)

### 1. Arithmetic-based CAPTCHA (Weak)

**Example:**

> “What is 3 + 7?”

**Characteristics:**

* Simple math or logic question.
* Easy for bots to parse and solve programmatically.

**Weaknesses:**

* Trivial to bypass with regex or script.
* CAPTCHA-solving services (e.g., *2Captcha*, *Anti-Captcha*) can instantly solve it.
* Minimal deterrence.

**Mitigation:**

* Avoid numeric puzzles; use modern CAPTCHA frameworks with server verification.

---

### 2. Text-based CAPTCHA (Basic)

**Example:**
A distorted image with text:

> “Enter the characters you see: 7hGkP”

**Characteristics:**

* Displays obfuscated or noisy letters and numbers.

**Strength:**

* Moderate barrier to unsophisticated bots.

**Vulnerabilities:**

* Bots using OCR or deep learning models can solve them easily.
* Minor distortion (tilt or background noise) no longer effective.
* Reuse of static CAPTCHA sets leads to predictability.

**Mitigation:**

* Generate new random CAPTCHA per session.
* Validate server-side.
* Combine with IP throttling.

---

### 3. Image-based CAPTCHA (Moderate)

**Example:**

> “Select all images containing traffic lights.”

**Characteristics:**

* Tests object recognition and contextual understanding.

**Strength:**

* Harder for traditional OCR; requires ML or human solvers.

**Vulnerabilities:**

* Machine learning models trained on open datasets can solve them.
* Human-solving services still defeat them at scale.

**Mitigation:**

* Use dynamic image sets with server-side validation.
* Limit token lifespan.

---

### 4. reCAPTCHA v2 (Moderate–Strong)

**Description:**

* Google’s “I’m not a robot” checkbox; triggers behavioral and image challenges if suspicious.

**Strength:**

* Analyzes mouse movement, cookies, and browsing behavior.
* Significantly slows bots.

**Vulnerabilities:**

* Token replay if reused.
* Third-party privacy implications.
* Possible to bypass via headless browsers simulating real behavior.

**Mitigation:**

* Verify token server-side using Google API.
* Bind token to user session and IP.

---

### 5. reCAPTCHA v3 (Very Strong)

**Description:**

* Works invisibly; assigns a risk score (0–1) based on user behavior.

**Strength:**

* Seamless UX, continuous risk analysis.

**Vulnerabilities:**

* Relies on behavioral fingerprint; can produce false positives/negatives.
* Not a hard block — needs custom logic to enforce thresholds.

**Mitigation:**

* Combine with rate-limiting and risk-based policies.

---

## 7. How Weak CAPTCHA Leads to Lockout Failure

When CAPTCHA is **misconfigured** or **insecure**, automated attacks resume easily:

| Weakness                                    | Impact                                                       |
| ------------------------------------------- | ------------------------------------------------------------ |
| CAPTCHA validated only client-side          | Bot can skip verification entirely                           |
| Token reusable across sessions              | Attackers reuse solved CAPTCHA for multiple attempts         |
| CAPTCHA appears only on login form, not API | Bots use API endpoint directly                               |
| Static CAPTCHA images                       | Precomputed answer database                                  |
| Weak math/logic CAPTCHA                     | Scriptable bypass                                            |
| CAPTCHA after too many failures             | Attackers distribute attempts across IPs to never trigger it |

---

## 8. Testing Methodology

### Step 1 — Identify Lockout Mechanism

* Perform multiple failed logins.
* Observe behavior (CAPTCHA trigger? lockout message?).

### Step 2 — Observe Server Response

* Compare responses before and after threshold.
* Analyze differences (status code, response time, error message).

### Step 3 — Inspect CAPTCHA Validation

* Check if CAPTCHA validation occurs server-side or client-side only.
* Modify request (e.g., remove CAPTCHA field) and replay.
* Try reusing the same CAPTCHA token on multiple requests.

### Step 4 — Test for API Bypass

* Determine if mobile API or AJAX endpoint skips CAPTCHA.
* Attempt login directly to those endpoints.

### Step 5 — Evaluate Rate Limiting

* Test whether multiple IPs can attack same username without triggering lockout.
* Observe if account lockout time is sufficient.

### Step 6 — Evaluate CAPTCHA Strength

* Assess challenge type (arithmetic, text, image, reCAPTCHA).
* Determine if easily solvable by automation or human-farm services.

### Step 7 — Verify Reset Behavior

* Check how long account remains locked.
* See if system resets after a few minutes, allowing continued attacks.

---

## 9. Example: Testing Weak CAPTCHA in Login Flow

```http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=john&password=wrongpass
```

After 3 failures → CAPTCHA appears:

```html
<img src="/captcha?sid=12345" />
<input name="captcha" value=""/>
```

Tester removes `captcha` field and resends the request.
If the application still processes login → **CAPTCHA not enforced server-side**.

Result: CAPTCHA can be bypassed → **Weak Lockout Mechanism**.

---

## 10. Real-World Attack Scenarios

### Scenario 1 — Credential Stuffing with Bypassed CAPTCHA

* CAPTCHA required after 3 failed logins.
* Attacker automates token reuse or API endpoint that skips CAPTCHA.
* Thousands of login attempts proceed → account takeover.

### Scenario 2 — Distributed Brute Force

* CAPTCHA triggers per IP, not per user.
* Attacker uses 1000 proxies → never triggers CAPTCHA threshold.

### Scenario 3 — Short Lockout Window

* Lockout lasts 60 seconds.
* Attacker retries after 1 minute → effectively no protection.

---

## 11. Secure Implementation Guidelines

| Control                               | Description                                                               |
| ------------------------------------- | ------------------------------------------------------------------------- |
| **Rate Limiting**                     | Enforce per-account and per-IP request limits.                            |
| **Progressive Delay**                 | Add incremental delay after each failed login attempt.                    |
| **CAPTCHA Server Validation**         | Always verify CAPTCHA server-side.                                        |
| **Token Binding**                     | Bind CAPTCHA token to specific IP/session/action.                         |
| **Single-use Token**                  | Expire tokens after one submission.                                       |
| **Account Lockout Policy**            | Lock account after N failures (e.g., 5), require cooldown or admin reset. |
| **IP Reputation Check**               | Block known bot/proxy IPs.                                                |
| **MFA (Multi-Factor Authentication)** | Adds an extra layer even if password brute-forced.                        |
| **Behavioral Analysis**               | Track request velocity, geolocation, and anomalies.                       |

---

## 12. Example: Secure CAPTCHA Verification Flow (reCAPTCHA v2)

```python
import requests

def verify_captcha(token, remoteip):
    payload = {
        'secret': 'YOUR_SECRET_KEY',
        'response': token,
        'remoteip': remoteip
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    return r.json().get('success', False)

# In login logic:
if not verify_captcha(user_input_token, client_ip):
    return "CAPTCHA verification failed"
```

---

## 13. Recommended Defense-in-Depth Strategy

* Use **adaptive lockout**: after 3 failed logins → show CAPTCHA; after 5 → delay; after 10 → lockout.
* Combine **CAPTCHA** + **rate limiting** + **progressive delays**.
* Log all failed login attempts; alert on anomalies.
* Use **reCAPTCHA v3** or **Cloudflare Turnstile** for invisible risk-based scoring.
* Rotate CAPTCHA provider secrets periodically.

---

## 14. Summary

| Issue                            | Impact                 | Mitigation                                |
| -------------------------------- | ---------------------- | ----------------------------------------- |
| CAPTCHA weak or client-side only | Bypass possible        | Server-side validation                    |
| Lockout after too many failures  | Large attack window    | Reduce threshold (e.g., 5)                |
| Short lockout time               | Persistent brute force | Increase cooldown or require admin unlock |
| CAPTCHA missing on APIs          | Easy bypass            | Apply CAPTCHA on all login vectors        |
| Token reuse                      | Mass bypass            | One-time use token                        |

---

## 15. Conclusion

**Testing for Weak Lockout Mechanisms (WSTG-ATHN-03)** is critical for assessing real authentication resilience.
CAPTCHA should never be treated as the only protection layer — it must be part of a **multi-layered defense** including:

* Rate limiting
* Behavioral detection
* Account lockout policies
* MFA enforcement

Strong, server-validated CAPTCHA combined with intelligent lockout logic significantly reduces the success rate of brute-force and credential-stuffing attacks.
