
## Introduction

For any application that requires the user to authenticate with a password, there must be a mechanism for users to regain access to their account if they forget their password.
This mechanism is commonly known as **“Password Reset”** or **“Forgot Password”** functionality.

Although this can sometimes involve contacting the website’s support team, most modern applications allow **self-service password reset** — users can reset their passwords by proving their identity through other evidence (email, SMS, security questions, etc.).

Because this functionality provides a **direct route to account compromise**, it must be implemented with **strong security controls**.

---

## Test Objectives

* Determine whether the password change or reset functionality can be abused to compromise user accounts.
* Verify that password reset mechanisms are at least as strong as the primary authentication process.
* Ensure the application prevents brute-force, enumeration, or token manipulation attacks.
* Confirm that users are properly re-authenticated before critical identity changes.

---

## How to Test

### 1. Information Gathering

1. Identify all interfaces that allow password resets:

   * Web application interface (`/forgot-password`, `/reset-password`)
   * Mobile application
   * Public API endpoints

2. Determine what identifiers are accepted for initiating the reset process:

   * Email address
   * Username
   * Phone number
   * Internal user ID (sometimes guessable)

3. Check if all platforms follow the same logic — sometimes APIs or mobile apps implement weaker or different password reset flows.

---

## 2. General Concerns

| Question                                               | Security Concern                                                                                                                                  |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Is the password reset weaker than authentication?**  | The reset mechanism must be at least as secure as login. Reset should not bypass MFA or use weak verification methods (e.g., security questions). |
| **Is rate limiting implemented?**                      | Prevents brute-force or automated token guessing. Use CAPTCHA or account lockout mechanisms.                                                      |
| **Is the reset process vulnerable to common attacks?** | Check for SQLi, XSS, CSRF, Host Header Injection, or other OWASP Top 10 vulnerabilities.                                                          |
| **Does the process allow user enumeration?**           | Error messages should be generic (e.g., “If an account exists, you will receive an email”).                                                       |

---

## 3. Email-Based Reset Mechanisms

### A. **New Password Sent via Email**

Some systems email a *new password* directly to the user.

**Security Risks:**

* Password is transmitted in **plaintext** over email.
* Account is **locked** until the email is received.
* Attacker can **spam the reset** and lock out legitimate users.

**What to Check:**

* Is the user forced to change the password at next login?
* Is the new password securely generated using a **CSPRNG**?
* Does the system ever send the *existing* password?
  → If yes, passwords are stored in plaintext (critical vulnerability).
* Are SPF, DKIM, and DMARC implemented to prevent email spoofing?

**Recommendation:**
Avoid this method — it’s **inherently insecure**.

---

### B. **Email Containing Reset Link (Token-Based Reset)**

The most common reset flow:

1. User requests password reset.
2. System emails a link like:

   ```
   https://example.com/reset?userid=123&token=abcdef
   ```
3. User clicks the link and sets a new password.

**Key Tests:**

| Check                                  | Description                                                                                |
| -------------------------------------- | ------------------------------------------------------------------------------------------ |
| **HTTPS used?**                        | The reset link must only be sent and accessed over HTTPS.                                  |
| **One-time usage?**                    | Tokens must expire immediately after being used.                                           |
| **Token expiration time?**             | Should be short (≤1 hour).                                                                 |
| **Token entropy?**                     | At least 128 bits of randomness (32 hex characters).                                       |
| **Predictable token generation?**      | Avoid MD5(email) or predictable UUIDs.                                                     |
| **Token format**                       | JWTs are fine if signed securely (verify algorithm, signature, key strength).              |
| **User ID parameter manipulation?**    | Attempt to modify `userid` to reset another account.                                       |
| **Host header injection?**             | Check if the reset link uses user-supplied Host headers.                                   |
| **Token exposure via Referer header?** | If the reset page loads third-party resources, tokens could leak. Check `Referrer-Policy`. |
| **Email domain protection**            | Verify SPF, DKIM, and DMARC are configured.                                                |
| **Email account security**             | Remember that email accounts might not use MFA or may be shared (corporate environments).  |

---

## 4. Tokens Sent via SMS or Phone Call

Some systems send reset codes through SMS or automated voice calls.

**Common Risks:**

* Short numeric tokens (e.g., 6 digits) have only ~20 bits of entropy.
* Easier brute-force if not rate-limited.
* SMS delivery can be abused for DoS or financial exploitation.
* SMS and phone channels are **not secure** against hijacking (SIM swap, SS7 attacks).

**What to Test:**

* Token randomness and expiration.
* One-time use enforcement.
* Rate limiting and protection against automated requests.
* Verify if international or premium rate numbers can be abused.
* Assess whether SMS/voice reset is appropriate for the application’s context.

---

## 5. Security Questions

Some legacy systems use “security questions” (e.g., “What is your mother’s maiden name?”) to verify identity.

**Risks:**

* Answers are often guessable or discoverable from public info/social media.
* Static and reused across multiple systems.

**Testing Tip:**
Attempt to enumerate or brute-force answers if allowed, and verify if the application uses them as the only factor for identity recovery.

**Recommendation:**
Avoid security questions. Use secure email or MFA-based verification instead.

---

## 6. Authenticated Identity & Configuration Changes

When a logged-in user changes sensitive identifiers like **email** or **phone number**, the app must require **re-authentication**.

Otherwise, an attacker with temporary access (stolen session/cookie) can:

1. Change the account email to their own.
2. Use the password reset flow to fully take over the account.

**Test:**

* Try changing email/phone without re-entering the current password or MFA.
* If allowed, this bypasses the authentication requirement of the password change process.

---

## 7. Authenticated Password Changes

When the user is logged in and wants to **change** (not reset) their password:

**Test Areas:**

* **Re-authentication:** Ensure the user must provide the old password or MFA.
* **CSRF protection:** Verify the change request requires a valid CSRF token.
* **User ID tampering:** Check if user ID is part of the request body and can be altered.
* **Password policy enforcement:** Confirm strong rules (length, complexity, reuse prevention) consistent across registration and reset forms.

---

## 8. Common Attack Scenarios

| Attack                    | Description                                                      |
| ------------------------- | ---------------------------------------------------------------- |
| **Token Brute-Force**     | Guessing weak tokens due to poor randomness or no rate limiting. |
| **User Enumeration**      | Distinct responses for valid/invalid users in reset form.        |
| **Email Link Hijacking**  | Intercepting or leaking reset links via Referer headers or MITM. |
| **Session Fixation**      | Failure to invalidate existing sessions after password change.   |
| **CSRF Exploitation**     | Changing passwords of logged-in users via forged requests.       |
| **Host Header Poisoning** | Manipulating generated reset links.                              |

---

## 9. Recommended Mitigations

* Always use **HTTPS** for all password reset endpoints.
* Generate tokens using **CSPRNG** with high entropy (≥128 bits).
* Tokens must be **single-use** and **expire quickly**.
* Implement **rate limiting** and **CAPTCHA** protection.
* Prevent **user enumeration** through consistent error messages.
* Require **re-authentication** for sensitive changes.
* Enforce **strong password policies** and disallow reuse of previous passwords.
* Use **SPF, DKIM, DMARC** for email integrity.
* **Invalidate all active sessions** after password change/reset.
* Log all reset requests and notify users of any changes.

---

## References

* [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
* [OWASP Authentication Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README.html)
* [OWASP Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/01-Testing_for_Account_Enumeration_and_Guessable_User_Account)
* [OWASP Testing for Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/04-Testing_for_Host_Header_Injection)
* [Testing JSON Web Tokens (JWT)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/07-Testing_JSON_Web_Tokens)
