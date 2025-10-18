
## **Introduction**

A **password policy** defines the rules that users must follow when creating or updating their passwords.
Weak password policies allow users to set simple or predictable passwords — like `123456`, `password`, `admin123`, etc.
Such weak passwords make it **easy for attackers** to perform **brute force** or **dictionary attacks**, gaining unauthorized access.

This test focuses on evaluating **how strong or weak** the application’s password policy is and **whether it enforces security best practices** such as minimum length, complexity, history, and expiration.

---

## **Test Objectives**

1. Assess whether the password policy is enforced both **client-side** and **server-side**.
2. Evaluate if the policy prevents users from using weak or commonly used passwords.
3. Identify missing password controls like:

   * Minimum length
   * Character diversity (uppercase, lowercase, numbers, symbols)
   * Password history and reuse prevention
   * Password expiration (if applicable)
   * Restrictions on username similarity
   * Dictionary/common password checks

---

## **Why This Matters**

Weak password policies expose applications to **credential stuffing** and **brute force** attacks.
If an attacker can easily guess passwords (like `admin123` or `P@ssw0rd!`), they can gain unauthorized access to sensitive data or administrative functions.

For example:

* A **banking web app** allows passwords like `123456` or `test123`.
  → Attackers can run automated tools like **Hydra**, **Burp Intruder**, or **OWASP ZAP** to brute-force accounts quickly.

---

## **How to Test**

The test involves **observing**, **creating**, and **analyzing** the password creation and reset processes.

---

### **1. Check Password Creation and Update Forms**

Try to register a new user or change a password.

Test multiple scenarios:

| **Test Case**                         | **Example Input**                  | **Expected Behavior**                                |
| ------------------------------------- | ---------------------------------- | ---------------------------------------------------- |
| Password shorter than required length | `abc`                              | Should reject with error: “Password too short.”      |
| All lowercase letters                 | `password`                         | Should reject due to lack of complexity.             |
| All uppercase letters                 | `PASSWORD`                         | Should reject.                                       |
| No special characters                 | `Pass1234`                         | Should reject if policy requires special characters. |
| Password equal to username            | Username: `john`, Password: `john` | Should reject.                                       |
| Common password                       | `123456` / `qwerty` / `letmein`    | Should reject.                                       |

If the system **accepts** any of these, it indicates a **weak password policy**.

---

### **2. Check for Password Complexity Enforcement**

A strong policy should require:

* **Minimum length**: at least **8–12 characters**
* **Character types**:

  * Uppercase (`A–Z`)
  * Lowercase (`a–z`)
  * Numbers (`0–9`)
  * Special characters (`!@#$%^&*` etc.)

Try combinations like:

* `Pass123` → too short
* `password` → lacks numbers/specials
* `Password1` → may be acceptable
* `P@ssword123!` → strong

Also check if validation happens **only client-side** (via JavaScript).
By intercepting requests with **Burp Suite**, modify the password field to a weak value and resend it — if the backend accepts it, the validation is **not enforced server-side**, which is a **vulnerability**.

---

### **3. Check for Password Reuse**

Attempt to:

* Change your password to the **same as the current one**.
* Change to a **recently used password**.

If accepted, the policy **does not prevent reuse**, allowing attackers to predict or reuse stolen passwords.

---

### **4. Check for Password Expiration Policy**

Some applications (especially enterprise systems) require users to change their passwords periodically.
Check if:

* The application enforces expiration (e.g., every 90 days).
* It **notifies** users to change expired passwords.
* It allows password change before expiration.

If passwords **never expire** and no security measures (like MFA) exist, risk increases.

---

### **5. Check for Dictionary Passwords**

Try using known common passwords like:

* `Password1`
* `Welcome123`
* `P@ssword`
* `qwerty123`

Applications should block such passwords using a **dictionary blacklist**.

You can use lists like:

* **rockyou.txt**
* **SecLists/common-passwords.txt**

If any common password is accepted — it’s a **weak password policy**.

---

### **6. Check for Username-Based Passwords**

If users can set their password similar to their username (e.g., `john` → password: `john123`), it’s a weakness.
Test by setting:

* Username: `ahmed`
* Password: `ahmed123`
  → If accepted, note it as insecure.

---

### **7. Check Password Storage Indicators**

While this overlaps with other tests, observe how the password is transmitted and stored:

* Ensure **passwords are sent over HTTPS** only.
* Ensure **no password hints** are displayed in error messages or source code.

---

## **Example Testing Scenario**

Let’s take a **realistic example**:

**Scenario:**
A shopping site `shopsecure.com` allows user registration.

1. You register with:

   * Username: `testuser`
   * Password: `12345`

   → The system accepts it.
   ✅ Weak: It doesn’t enforce a minimum length or complexity.

2. You change your password to `testuser123`.
   → The system accepts it even though it’s based on the username.
   ✅ Weak: Username similarity not enforced.

3. You try reusing `12345` as the new password.
   → System accepts it again.
   ✅ Weak: No password history check.

4. You check the network requests.
   → Passwords are sent via **HTTP** instead of **HTTPS**.
   ❌ Critical: Insecure transmission.

These combined weaknesses show that the password policy is **weak and poorly enforced**.

---

## **Tools Useful for Testing**

* **Burp Suite** or **OWASP ZAP** – Intercept and modify password submissions.
* **Hydra**, **Medusa**, or **Burp Intruder** – To check brute force feasibility.
* **SecLists** – For common passwords dictionary testing.
* **rockyou.txt** – Real-world password dataset.
* **OWASP Password Policy Cheat Sheet** – For reference best practices.

---

## **Remediation**

To strengthen password policy:

1. **Minimum Requirements**

   * At least 8–12 characters.
   * Mix of uppercase, lowercase, numbers, and special characters.
   * Disallow dictionary/common passwords.
   * Prevent passwords matching or containing username or email.

2. **Enforcement**

   * Validate both **client-side** and **server-side**.
   * Implement **rate limiting** or **lockout** after multiple failed attempts.
   * Apply **password history checks** (e.g., last 5 passwords).
   * Require password changes after X months (for enterprise use cases).

3. **Secure Storage**

   * Hash passwords using **bcrypt**, **Argon2**, or **PBKDF2**.
   * Never store plaintext or reversible passwords.

4. **User Guidance**

   * Display password strength meters.
   * Educate users about strong password creation.

5. **Alternative Measures**

   * Encourage or enforce **Multi-Factor Authentication (MFA)**.

---

## **References**

* [OWASP WSTG-ATHN-07](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/07-Testing_for_Weak_Password_Policy)
* [OWASP Password Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Policy_Cheat_Sheet.html)
* [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## **Summary**

| **Aspect**          | **Good Practice**           | **Weakness if Missing**       |
| ------------------- | --------------------------- | ----------------------------- |
| Minimum Length      | ≥ 8 characters              | Easy brute force              |
| Complexity          | Mixed character sets        | Easy dictionary attack        |
| Blacklist           | Common passwords blocked    | Predictable passwords         |
| Reuse Prevention    | Last N passwords forbidden  | Reuse of old/stolen passwords |
| Username Similarity | Disallowed                  | Guessable passwords           |
| Expiration          | Periodic change (if needed) | Long-term exposure            |
| HTTPS Transmission  | Mandatory                   | Password sniffing risk        |

---
