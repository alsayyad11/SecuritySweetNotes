

## 1 — Purpose / Scope

Test whether **security questions** (knowledge-based authentication — KBA) used in account recovery, unlock, or secondary authentication flows are weak, predictable, or implemented insecurely. The goal is to determine if an attacker can bypass account recovery or reset workflows by guessing, brute-forcing, or discovering answers via OSINT and other channels.

This includes:

* Password reset flows using security questions.
* Account unlock / verification using KBA.
* Any secondary authentication step relying on personal questions.
* Storage and validation of question answers (client/server).

---

## 2 — Why it matters

Security questions are often based on publicly known or guessable facts (mother’s maiden name, birth city, pet’s name). Attackers can:

* Use **OSINT** (social media, public records) to find answers.
* **Brute-force** answers if there is no rate limiting.
* **Enumerate** valid users via differing error messages.
* **Exploit weak server-side validation** (accepting variations, case insensitive, no normalization).
* **Compromise accounts** via weak KBA even if passwords are strong.

NIST and many security standards no longer recommend KBA as a standalone recovery mechanism because of these weaknesses — prefer robust alternatives (email/SMS OTP, hardware MFA, push authentication).

---

## 3 — Typical flows to test

* “Forgot password?” → answer security questions → set new password.
* Account unlock via answering security questions.
* Secondary auth (2nd factor) using security question.
* “Remember this device” or “sensitive transaction” confirmation via KBA.

---

## 4 — Common weaknesses you will look for

* Questions with **low entropy** (few possible answers).
* Answers based on **publicly available info** (social media).
* **No rate limiting** on attempts.
* **Predictable** question lists (always same questions).
* **Poor answer validation** (accepts partial matches, case differences, ignores punctuation).
* **Client-side validation** only (can be bypassed).
* **Answers stored in plaintext** or using reversible encryption.
* **No logging/alerting** on repeated failed KBA attempts.
* **Enumeration** via error messages (different messages for wrong vs unknown user).
* **Reusing** KBA answers across services.

---

## 5 — Attack techniques / testing methodology

Below are precise tests and attack methods (manual and automated) with examples.

### 5.1 Reconnaissance / OSINT (Information Gathering)

Objective: find likely answers from public sources.

Sources:

* Facebook, Instagram, Twitter, LinkedIn
* Genealogy sites, public records
* Company bios, interviews, blog posts
* Leaked password / data dumps (have legal authorization)
* WHOIS records
* Forum signatures or comments

Example: If question = “Mother’s maiden name”, search:

```
site:facebook.com "mother" "Smith" "lastname"
```

or check family photos, obituaries, genealogy databases.

Tools:

* Google dorks
* Maltego, Recon-ng
* Custom Google/Bing queries
* LinkedIn and company pages

---

### 5.2 Enumeration

Objective: detect whether the KBA flow leaks information (valid username, which questions are set, allowed attempts).

Tests:

* Submit non-existent username on “forgot password” and observe messages.

  * If system replies “User not found” vs a generic “If that account exists, we have sent an email”, it leaks user existence.
* Request KBA for many usernames and observe which return different question sets.

Evidence:

* Request/response captures showing differing messages.
* List of users for which questions are returned.

---

### 5.3 Brute force / Guessing attacks

Objective: test if answers can be guessed via lists or brute force.

Approach:

* For low-entropy answers (e.g., “What is your favorite color?”), prepare a small wordlist (`colors.txt`) and iterate.

* Use Burp Intruder or custom script to submit sequences:

  ```
  POST /reset-answer HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=alice&question=pet_name&answer=^PAYLOAD^
  ```

* Observe whether there is rate limiting, lockout, or account disablement.

If no rate limiting, attacker can try hundreds/thousands of common answers quickly.

---

### 5.4 Test validation logic and normalization

Objective: determine if server accepts variations that reduce entropy.

Checks:

* Case sensitivity: `Fido` vs `fido`
* Punctuation: `St. Louis` vs `St Louis` vs `Saint Louis`
* Unicode normalization: accented characters vs non-accented
* Partial answers: does server accept substrings?

Test examples:

* Submit `fido`, `FIDO`, `FiDo` and watch acceptance.
* Submit `O'Neill` vs `Oneill`.

If server accepts multiple forms, attacker has more chances.

---

### 5.5 Test for client-side only validation

Objective: ensure answers are validated server-side.

Method:

* Use Burp to intercept the reset submission and send manipulated values ignoring client checks.
* If server accepts manipulated answers, validation is only client-side.

---

### 5.6 Test for token reuse, predictable tokens, replay

Some flows return a token or link after correct KBA. Test:

* Is token predictable or sequential?
* Can token be reused to reset multiple accounts?
* Does token expire and is it single-use?

Example:

* Capture `reset_token=abc123`. Try reusing it. If still valid after first use or long expiry — risk.

---

### 5.7 Social engineering & phone/SMS paths

If unlock flows involve human helpdesk or SMS:

* Test helpdesk procedures (with authorization) to check whether operators verify identity well or accept weak answers.
* For SMS/voice-based KBA (e.g., “what is your mother’s maiden name”), evaluate robustness.

Note: Social engineering tests require explicit authorization and careful scope agreement.

---

### 5.8 Check storage and transport of answers

* Intercept network traffic to confirm answers are sent over HTTPS (must be).
* Inspect cookie/response storage – answers or tokens must not be stored in clear in cookies or local storage.
* Where possible, audit server behavior (if authorized): ensure answers are hashed & salted, not plaintext.

---

## 6 — Examples & exact test payloads

### Example HTTP flow (vulnerable)

```http
POST /forgot-password HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=alice
```

Response:

```http
200 OK
Content-Type: application/json

{ "question": "What is your pet's name?" }
```

Attacker sees question. Then:

```http
POST /answer-question HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=alice&answer=fido
```

If reply = `{"result":"correct","token":"reset-abc123"}` attacker has reset token.

### Brute force via Burp Intruder

* Position payload on `answer` value and use small wordlist: `['fido','spot','max','bella','luna']`.
* Set throttle / rate limits as allowed.
* Observe responses where `result=correct`.

### SQLi or injection angle

If answers are compared unsafely, try special characters `' OR '1'='1` to see if validation is bypassable (rare but possible).

---

## 7 — Evidence to collect

* Request/response captures showing:

  * How questions are revealed.
  * Responses on correct/incorrect answers.
  * Rate limits or lack thereof.
  * Token issuance after successful KBA.
* Screenshots of differing error messages (user enumeration).
* Logs or output showing brute force success (with consent).
* Notes on OSINT findings linking public data to specific question answers.

---

## 8 — Severity Assessment

Severity depends on:

* The privilege of affected account (admin vs normal user).
* Whether KBA leads to full password reset or just unlock.
* Ease of guessing (publicly known vs unique).
* Presence/absence of rate limiting and monitoring.

Typical ratings:

* **Critical/High**: KBA allows password reset/unlock without rate limiting and answers derivable from OSINT.
* **Medium**: KBA protects low-sensitivity actions but is weak.
* **Low**: KBA used as minor extra info and not controlling sensitive operations.

---

## 9 — Remediation & secure design recommendations

**Short term / quick fixes**

* Add **rate limiting** and **progressive delays** on KBA attempts.
* Use **generic messages** (avoid “question X is set” or “user not found”) — prevent enumeration.
* Limit attempts then require stronger flow (email OTP, admin review).
* Log and alert on repeated failed KBA attempts.

**Secure storage & validation**

* Treat answers like passwords:

  * Hash with salt using a slow hashing algorithm (bcrypt/Argon2).
  * Do not store plaintext or reversible encryption.
* Normalize inputs server-side (case normalization, punctuation) and store normalized hash.
* When validating, normalize user input and compare hashed values.

**Replace KBA with stronger alternatives**

* Prefer **email-based verification links** or **OTP via SMS** (with caveats), or better **MFA** (TOTP, FIDO2/WebAuthn, push).
* If KBA must be used, increase entropy:

  * Allow users to define custom questions (not from small fixed lists).
  * Enforce minimum answer length and complexity.
  * Allow users to treat the answer like a password (obscured input, no autocomplete).

**Token security**

* Make reset tokens one-time use and short expiry (minutes).
* Bind token to the specific user and device/IP where reasonable.
* Invalidate tokens after password change.

**Operational**

* Train helpdesk: require multi-factor verification for unlocks.
* Provide user notifications (email/SMS) when KBA-based changes occur.
* Allow users to disable KBA-based recovery.

---

## 10 — Sample secure implementation snippets

### Hashing answers (pseudo-code)

```python
from argon2 import PasswordHasher

ph = PasswordHasher()

# when saving answer
normalized = normalize(answer)   # e.g., lower(), remove punctuation
hash = ph.hash(normalized)
store_in_db(user_id, question_id, hash)

# when validating
try:
    ph.verify(stored_hash, normalize(submitted_answer))
    # success
except VerifyMismatchError:
    # failure
```

### Rate limiting example (pseudo)

```python
if kba_attempts(user_id) > 5:
    lock_kba(user_id)  # require email OTP or admin unlock
else:
    verify_answer()
```

---

## 11 — Detection and monitoring

* Monitor for unusual KBA attempt frequency per IP and user.
* Alert on multiple different-user KBA attempts from same IP (possible enumerator).
* Keep audit trails of successful KBA resets; send email/SMS notifications to account owner.

---

## 12 — Reporting template (concise)

**Title:** Weak security question answers allow account recovery via guessing/OSINT
**WSTG:** WSTG-ATHN-08
**Severity:** High (if leads to password reset)
**Description:** The account recovery flow returns the security question and accepts freely guessed answers without sufficient rate limiting. Answers for `alice@example.com` can be derived via public sources.
**Proof:** (attach Burp captures)

* `POST /forgot-password` returns question.
* `POST /answer-question` with `answer=fido` returned success and `reset_token`.
  **Impact:** Attacker can reset passwords and take over accounts.
  **Recommendation:** Disable KBA for password reset or harden it: store hashed answers, add rate limiting, require email/OTP, use MFA, log and notify users, and avoid static low-entropy questions.

---

## 13 — Tools & resources

* Burp Suite / OWASP ZAP (intercept & automate)
* Intruder / Repeater for brute forcing
* Maltego / Recon-ng / Google Dorking for OSINT
* Hydra / custom scripts (with authorization and caution)
* Password hashing libs (Argon2, bcrypt) for remediation
* Logging and SIEM (Elasticsearch, Splunk) for monitoring

---

## 14 — Checklist

* [ ] Does the forgot/unlock flow reveal security questions prior to verifying user existence? (avoid user enumeration)
* [ ] Are security questions based on publicly available facts? (low entropy)
* [ ] Are answers rate limited / subject to progressive delays or lockout?
* [ ] Are answer submissions validated server-side and normalized?
* [ ] Are reset tokens single-use and short-lived?
* [ ] Are answers stored hashed with a strong hash function and salt?
* [ ] Are alerts/notifications sent when KBA is used to change account state?
* [ ] Is KBA optional and/or disabled for privileged accounts?
* [ ] Are helpdesk unlock procedures robust (multi-factor verification)?
* [ ] Are users allowed to create custom questions and treated like passwords?
* [ ] Is KBA replaced or supplemented with stronger methods (MFA/WebAuthn)?

---

## 15 — Notes 

* Security questions were historically convenient but are largely **insufficient** on their own today. Treat KBA as **last resort**, and only after strengthening with rate limits, hashing, normalization, and notifications.
* Prefer stronger, modern recovery mechanisms: **email verification links**, **time-limited OTP**, **authenticator apps**, **FIDO2/WebAuthn**, or **out-of-band approval**.
* Always assume an attacker can perform OSINT and craft defenses accordingly.

---
