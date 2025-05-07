##  1. What Is “Forgot Password”?

![image](https://github.com/user-attachments/assets/af9acf88-4947-460e-8174-a0d23f95fd73)

In any **user management system**, the **Forgot Password** functionality is essential. It allows users who forgot their password to reset it securely and regain access to their account.

Although it seems simple, it's often implemented insecurely, which leads to vulnerabilities such as:

* **User Enumeration**: When the system reveals whether an email/username exists based on the message.
* **Brute-force Token Attacks**: When tokens are short or predictable.
* **Token Leakage via Referer Header**: When password reset links expose sensitive tokens via HTTP headers.

---

##  2. Step-by-Step Secure Implementation

### 🔹 Step 1: Password Reset Request

**Goal**: User submits email/username to request a password reset.

**Key Requirements**:

#### 1. Return a Generic Message

* Don’t reveal whether the account exists.
* Example:

  > “If an account exists for the provided email, a password reset link has been sent.”

  That Prevents **User Enumeration Attacks**.

#### 2. Equal Response Time

* Use same processing time whether the user exists or not.
* Avoids timing attacks using tools like Burp Suite.

#### 3. Rate Limiting and CAPTCHA

* Prevent abuse through spam or brute-force:

  * Add per-account rate limits.
  * Use progressive delays or CAPTCHA.

#### 4. Input Validation

* Validate email format and sanitize inputs to avoid injection:

  ```python
  import re
  def is_valid_email(email):
      return re.match(r"[^@]+@[^@]+\.[^@]+", email)
  ```

---

### 🔹 Step 2: Token Generation and Delivery

#### 1. Generate a Secure Token

* Use cryptographically strong methods:

  ```python
  import secrets
  token = secrets.token_urlsafe(32)
  ```
* Token must be:

  * **Long** (at least 32 bytes)
  * **Random**
  * **Unique**
  * **Stored securely** (e.g., hashed)

#### 2. Token Expiration

* Set an expiration time (e.g., 15 minutes, 1 hour).

#### 3. Single-Use Only

* Invalidate token immediately after it’s used.

#### 4. Send via Side Channel (Email or SMS)

* Always use a secure channel.
* Email must be:

  * Sent over TLS (SMTP with STARTTLS)
  * Free from sensitive data leaks

---

### 🔹 Step 3: Password Reset Page

#### 1. Accept and Validate Token

* Extract token from the URL:

  ```
  https://example.com/reset-password?token=abc123
  ```
* Server must:

  * Check token validity and expiry
  * Check it hasn’t been used already

#### 2. Referrer Policy

* Prevent token leakage via HTTP headers:

  ```html
  <meta name="referrer" content="no-referrer" />
  ```

#### 3. Rate Limit the Page

* Prevent brute-force attempts on tokens.

#### 4. Ask User to Enter New Password Twice

* To avoid typing mistakes.

#### 5. Enforce Strong Password Policy

* Example policy:

  * Minimum 12 characters
  * At least one uppercase, one lowercase, one number, one special character

#### 6. Store Password Securely

* Hash it using secure algorithms like `bcrypt` or `argon2`:

  ```python
  from passlib.hash import bcrypt
  hashed = bcrypt.hash(new_password)
  ```

#### 7. Do **Not** Auto-Login After Reset

* Let the user manually login again.
* Reduces complexity and attack surface.

#### 8. Send Notification Email

* Example:

  > "Your password has been changed. If this wasn't you, please contact support."

⚠️ **Do NOT include the new password in the email.**

#### 9. Invalidate Existing Sessions 

* Either automatically or ask the user if they want to log out all other devices.

---

## ❌ Common Mistakes and Fixes

| Mistake                         | Risk              | Fix                                       |
| ------------------------------- | ----------------- | ----------------------------------------- |
| Revealing if the account exists | User enumeration  | Use a generic message                     |
| Short or predictable token      | Token brute-force | Use `secrets.token_urlsafe(32)`           |
| Reusable or non-expiring token  | Token hijacking   | Make tokens single-use and time-limited   |
| Auto-login after reset          | Session hijacking | Require manual login                      |
| Sending password by email       | Data leak         | Only send notifications, not the password |

---

## Alternative Methods

### PINs (SMS or Email Codes)

* Generate a numeric PIN (e.g., 6–12 digits)
* Send via SMS/email (use spacing for readability: `123 456`)
* PIN must:

  * Be tied to a specific user
  * Be one-time and expire quickly
* Don't allow PINs without identifying the user (to prevent PIN brute-force)

### Security Questions

* Avoid using them as the **only** recovery method.
* If used, make sure:

  * Answers are not guessable
  * Use as an extra layer only

---

## 💡  Implementation Tips

### Example: Generating a Token (Python)

```python
import secrets
import datetime

def generate_token(user_id):
    token = secrets.token_urlsafe(32)
    expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    save_to_db(user_id, token, expires)
    return token
```

### Example: Reset Link Email Template

```
Subject: Reset your password

Hi [Username],

We received a request to reset your password. Click the link below to set a new one:

https://example.com/reset-password?token=...

If you didn't request this, you can ignore this email.

Best,
Support Team
```

---

