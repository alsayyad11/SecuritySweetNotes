
## **1. Introduction**

Account lockout mechanisms are a **defensive control** used to protect authentication systems against **brute-force** and **credential-guessing** attacks.
The concept is simple: after a certain number of **failed login attempts**, the system will **temporarily or permanently disable** further login attempts for that account.

This prevents attackers from trying unlimited password combinations and helps ensure that unauthorized users cannot guess valid credentials easily.

However, poorly implemented lockout mechanisms can lead to:

* Denial of Service (DoS) against legitimate users.
* Insecure unlock mechanisms.
* Weak thresholds that make brute-forcing still possible.

Therefore, **testing for weak lockout mechanisms** is a critical part of authentication testing.

---

## **2. Why Lockout Mechanisms Are Important**

Without a proper lockout mechanism, attackers can perform **automated password-guessing attacks** using tools like:

* **Hydra**
* **Burp Intruder**
* **ffuf**
* **wfuzz**

These tools can send thousands of login attempts per minute.

**Example Scenario:**

An attacker targets a webmail service and tries 100,000 passwords against user `jane@example.com`.
If the system does not block or delay attempts, the attacker could guess her password in a few minutes.

A correct lockout system would detect repeated failed attempts and **temporarily lock Jane’s account** after, for example, 5 failed tries, making such brute-force attacks impractical.

---

## **3. Test Objectives**

1. **Evaluate the lockout mechanism’s effectiveness** in mitigating brute-force password guessing attacks.

   * How many failed attempts trigger a lockout?
   * How long is the lockout period?
   * Is it user-based, IP-based, or global?

2. **Evaluate the unlock mechanism’s security** and resistance to abuse.

   * Can attackers unlock accounts without authorization?
   * Are unlock tokens predictable, reusable, or permanent?

---

## **4. Attack Scenarios That Lockout Mechanisms Can Mitigate**

* **Password guessing attacks**
* **Username guessing (via response difference)**
* **2FA or OTP brute-forcing**
* **Security question guessing**

---

## **5. How to Test**

Testing involves two major phases:

1. **Lockout Mechanism Testing**
2. **Unlock Mechanism Testing**

---

### **5.1. Lockout Mechanism Testing**

#### **Step 1: Prepare a Test Account**

Use a dedicated account (for example, `testuser@example.com`).
Make sure you’re allowed to lock it — otherwise, test this part last.

---

#### **Step 2: Perform Incremental Failed Logins**

Try to log in multiple times with an incorrect password and observe system behavior.

**Example Procedure:**

| Attempt | Action           | Expected Result                                 |
| ------- | ---------------- | ----------------------------------------------- |
| 1       | Wrong password   | Login failed                                    |
| 2       | Wrong password   | Login failed                                    |
| 3       | Wrong password   | Login failed                                    |
| 4       | Wrong password   | Login failed                                    |
| 5       | Wrong password   | Login failed                                    |
| 6       | Correct password | Should return “Account locked” if threshold = 5 |

If you can log in after multiple wrong attempts → Lockout mechanism may be **missing or misconfigured**.

---

#### **Step 3: Verify Lockout Duration**

Attempt to log in with the correct password at different intervals to determine how long the lockout lasts.

| Time after lockout | Expected Behavior      |
| ------------------ | ---------------------- |
| 5 minutes          | Still locked           |
| 10 minutes         | Still locked           |
| 15 minutes         | Unlocked automatically |

If the lockout never expires, it might require manual unlock by admin.
If it expires too quickly (1–2 minutes), it’s weak and ineffective.

---

#### **Step 4: Test for User Enumeration via Error Messages**

If error messages differ, attackers can identify valid usernames.

**Example:**

* Invalid user: “Invalid username or password.”
* Locked user: “Your account has been locked.”

This difference leaks information.
Best practice: always show **generic** error messages:

> “Login failed. Please try again later.”

---

### **5.2. Testing CAPTCHA Integration**

Some applications use **CAPTCHA** to slow down brute-force attacks.
However, CAPTCHA should **complement**, not replace, a lockout mechanism.

#### **Types of CAPTCHA and How They Work**

| Type                          | Description                                                       | Example Weaknesses                                                         |
| ----------------------------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------- |
| **Text CAPTCHA**              | User must type distorted letters/numbers from an image.           | Easy to solve using OCR tools.                                             |
| **Image Recognition CAPTCHA** | User selects specific images (e.g., “Select all traffic lights”). | Automated using computer vision or pre-solved datasets.                    |
| **Audio CAPTCHA**             | Plays numbers/words for visually impaired users.                  | Can be solved using speech-to-text software.                               |
| **Math CAPTCHA**              | Simple arithmetic (e.g., “3 + 5 = ?”).                            | Predictable, easy to automate.                                             |
| **reCAPTCHA v2**              | “I’m not a robot” checkbox or image puzzle.                       | Can be bypassed via token reuse or proxying to CAPTCHA-solving APIs.       |
| **reCAPTCHA v3**              | Invisible, assigns a score based on user behavior.                | Not binary (pass/fail), can be bypassed by simulating legitimate behavior. |
| **hCAPTCHA**                  | Similar to reCAPTCHA but uses image labeling.                     | Same class of weaknesses as reCAPTCHA.                                     |
| **Invisible CAPTCHA**         | Triggered when bots skip JS or behave too fast.                   | Can be bypassed with headless browsers that mimic human behavior.          |

---

#### **Testing CAPTCHA Effectiveness**

Perform the following checks:

1. **Submit login without solving CAPTCHA.**

   * If request still goes through → CAPTCHA not enforced server-side.

2. **Reuse old CAPTCHA tokens.**

   * If previous challenges are accepted → CAPTCHA not one-time use.

3. **Replay solved CAPTCHA requests.**

   * If still valid → weak validation.

4. **Check hidden fields or HTML source.**

   * Some CAPTCHAs leak answers in hidden inputs or image filenames.

5. **Try automation.**

   * Use tools like Selenium or headless Chrome to simulate user behavior.

6. **Bypass using alternative endpoints.**

   * Mobile APIs or JSON login endpoints sometimes skip CAPTCHA validation.

7. **Cookie and session manipulation.**

   * Clearing cookies might reset CAPTCHA counters, making it bypassable.

**Example Test Using Burp Suite:**

* Capture login request with CAPTCHA token.
* Replay request without solving CAPTCHA or modify parameter like `captcha=1234`.
* If the server accepts → CAPTCHA validation is missing or weak.

---

### **5.3. Unlock Mechanism Testing**

After an account is locked, you must analyze how the system unlocks it.

#### **Common Unlock Methods**

| Unlock Type             | Description                                  | Risks                                                     |
| ----------------------- | -------------------------------------------- | --------------------------------------------------------- |
| **Time-based unlock**   | Unlocks automatically after X minutes/hours. | May be too short. Attackers can wait out lockout periods. |
| **Self-service unlock** | User gets an email or SMS with unlock link.  | Weak tokens or reusable links can be abused.              |
| **Admin unlock**        | Admin manually resets lockout.               | Most secure but time-consuming.                           |

---

#### **Step 1: Inspect Email/SMS Unlock Link**

Check:

* Is the unlock token unique per session?
* Does it expire after one use?
* Is it long and random enough (128-bit at least)?
* Is the token tied to the specific user?

**Example Weak Unlock URL:**

```
https://example.com/unlock?user=test&code=1234
```

→ Predictable and brute-forcible.

**Example Secure Unlock URL:**

```
https://example.com/unlock?token=47f1a89d73b2d49f5e9ab27d6...
```

---

#### **Step 2: Inspect Self-Service Questions**

Some apps use “secret questions” for unlocking.

Test for:

* Guessable answers (“What is your favorite color?” → “Blue”).
* Case-insensitive comparison.
* SQL injection or code injection vulnerabilities in the question fields.

---

## **6. Common CAPTCHA Weaknesses (Expanded)**

| Weakness                        | Description                                                         | Example                                         |
| ------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------- |
| **Static challenges**           | Same CAPTCHA reused across sessions.                                | CAPTCHA always asks “2 + 3 = ?”.                |
| **Client-side only validation** | CAPTCHA checked by JavaScript, not server.                          | Removing JS bypasses it.                        |
| **Hidden solution leakage**     | CAPTCHA answer stored in hidden HTML field.                         | View source → find solution.                    |
| **Predictable tokens**          | CAPTCHA IDs or values increment sequentially.                       | `/captcha?id=101`, `/captcha?id=102`.           |
| **CAPTCHA service downtime**    | If external CAPTCHA service fails open, requests bypass validation. | reCAPTCHA API returns error → app allows login. |
| **Bypass via API endpoint**     | Mobile API skips CAPTCHA requirement.                               | `/api/login` doesn’t require solving.           |
| **Weak image sets**             | Limited images repeated often.                                      | Bot memorizes responses.                        |
| **Audio CAPTCHA reuse**         | Audio challenge doesn’t change for same session.                    | One solved audio reused many times.             |

---

## **7. Additional Considerations**

A lockout mechanism must balance **security vs usability**.

| Risk                      | Consequence                                   |
| ------------------------- | --------------------------------------------- |
| Too strict (3 attempts)   | Attackers can easily lock all accounts (DoS). |
| Too lenient (20 attempts) | Brute-force attacks succeed.                  |

**Recommended configuration:**

* 5–10 failed attempts before lockout.
* Lockout duration: 10–30 minutes.
* Secure unlock method (time-based or verified email).
* Optional CAPTCHA after 3 failed attempts (secondary layer).

---

## **8. Example of a Secure Lockout Mechanism**

### **Behavior**

1. Account locks after 5 consecutive failed login attempts.
2. Lock lasts for 15 minutes.
3. CAPTCHA required after 3 failed attempts.
4. Unlock email link expires after 10 minutes.
5. Error messages remain generic.

### **Pseudocode Example**

```python
if user.locked_until > now:
    return "Login failed. Please try again later."

if not password_is_correct(user, password):
    user.failed_attempts += 1
    if user.failed_attempts >= 5:
        user.locked_until = now + timedelta(minutes=15)
    elif user.failed_attempts >= 3:
        require_captcha = True
    save(user)
    return "Login failed. Please try again later."

user.failed_attempts = 0
save(user)
return "Login successful."
```

---

## **9. Example Attack and Defense**

### **Attack Without Lockout**

Attacker runs:

```bash
for pass in $(cat passwords.txt); do
  curl -X POST -d "user=john@example.com&pass=$pass" https://target.com/login
done
```

10,000 attempts/minute → Password guessed in seconds.

### **Attack With Lockout**

* Account locked after 5 wrong tries.
* Must wait 15 minutes.
* 4 attempts/hour = impractical.

---

## **10. Remediation Recommendations**

| Problem                   | Recommendation                                       |
| ------------------------- | ---------------------------------------------------- |
| No lockout                | Implement after 5–10 failures                        |
| CAPTCHA replaces lockout  | Use CAPTCHA only as a supplement                     |
| Reusable unlock links     | Use unique, single-use tokens                        |
| Error message differences | Use generic responses                                |
| DoS via lockouts          | Consider IP-based rate limiting or exponential delay |

---

## **11. Summary**

Testing for weak lockout mechanisms ensures an application resists brute-force and guessing attacks effectively.

**Notes:**

* Lockout mechanisms are vital to limit guessing attacks.
* CAPTCHA should be secondary, not primary protection.
* Unlock processes must be secure and unpredictable.
* Implement balanced thresholds to prevent DoS.
* Always validate CAPTCHA and unlock logic server-side.
