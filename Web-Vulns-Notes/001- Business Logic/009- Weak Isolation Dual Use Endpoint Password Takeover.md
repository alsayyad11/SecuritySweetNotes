
# **1. The Core Issue**

The root of the vulnerability is a **fundamental failure in how the application determines user identity and authorizes high‑privilege operations**.

In a properly engineered system:

* The **server** decides who the user is — based strictly on the **session**.
* The client has **zero authority** to declare who they are.
* Any data from the client (form fields, JSON, query params, cookies except session tokens) must be treated as **untrusted**, because attackers can alter it.

But in this lab, the developer made a catastrophic design choice:

### **The application relies on a client‑supplied parameter (`username=`) to decide whose password should be changed.**

This means the flow looks like:

```
User sends request → Server reads "username" from body → Server updates that user’s password
```

Instead of:

```
User’s session identifies them → Server updates the authenticated user's password only
```

By delegating identity trust to the attacker-controlled request, the system becomes wide open for privilege abuse.

This is the classic backbone of many **Business Logic Flaws**: the system works logically, but the logic itself is fundamentally broken.

---

# **2. What Actually Happens During a Password Change (Expanded Breakdown)**

A secure password‑change feature should enforce multiple layers of validation to avoid unauthorized takeover.

### **A properly designed password‑change flow MUST include:**

### **1. Authentication Validation**

The server ensures the requester is logged in using the **session cookie**.
If there’s no valid session → no password change.

### **2. Verification of the Old Password**

The server must verify that the submitted **current password** is correct.
This prevents:

* CSRF-style unauthorized changes
* Hacked users silently losing access
* Attackers brute‑forcing password resets from inside a stolen session

### **3. Binding the Action to the Session User Only**

The new password must always be applied to the **account linked to the session**, not to a client‑supplied value.

Under no circumstances should the request body be allowed to decide:

* Which user the action applies to
* Whether the requester has the privilege for that change

But in the lab, the server essentially ignores all proper security design.

### **The vulnerable flow looks like this:**

```
POST /my-account/change-password
current-password=oldPass
new-password=newPass123
username=wiener
```

And the server logic effectively does something like:

* “Is there a parameter named `current-password`?”
* “Cool, looks valid.”
* “Which user should we update? Let me read the `username` field from the client…”
* “Done.”

This completely bypasses proper authentication and authorization rules.

---

# **3. The Server Only Checks for the Presence of the Parameter — Not Its Validity**

This is a next‑level bad logic flaw.

The server **does not verify** whether the submitted old password is correct.
It only checks:

### **Does the field `current-password` exist in the request?**

So instead of:

```
if (currentPassword == storedPassword) { allow change }
else { reject }
```

The logic behaves like:

```
if ("current-password" parameter exists) { allow change }
else { reject }
```

### **This means:**

If you **delete** the entire line:

```
current-password=peter
```

The server still considers the request valid, because the logic doesn’t validate the actual value — it just checks for the key’s existence.

This creates a direct bypass of the only security barrier keeping attackers from resetting someone else’s password.

---

# **4. The Fatal Design Flaw: User Identity Comes From a Client Parameter**

This vulnerability is even worse than the password‑check bypass.

The application reads:

```
username=wiener
```

And **assumes** the client is telling the truth about who they are.

This is a complete violation of secure authentication principles.

### **Why this is catastrophic:**

* Attackers can modify the username value at will.
* The server never links the action to the session user.
* The server *blindly trusts* the supplied username.
* This allows direct privilege escalation.

### **Real‑world meaning:**

If the attacker changes:

```
username=wiener
```

to:

```
username=administrator
```

The server treats the attacker like they are the administrator initiating a legitimate password change.

The system literally hands attackers the keys to any account.

This is full-blown **Authentication Bypass via Business Logic**.

---

# **5. How Both Flaws Combine Into a Critical Vulnerability**

Each flaw alone would be bad.
Together, they create a complete privilege escalation chain.

### **Flaw 1: No old password needed**

You don’t need to know any victim’s current password.

### **Flaw 2: You choose the user**

Changing the `username` parameter lets you target any account.

### **Combined effect:**

An attacker can:

* Pick any account — including `administrator`
* Change its password without knowing the old one
* Log in as that account
* Perform any action as that user

This is a masterclass of how **multiple weak assumptions** can align into a catastrophic exploit.

---

# **6. Full Practical Exploitation Walkthrough (Enhanced, Detailed)**

Below is the complete exploitation chain with deeper clarity on each step.

---

## **Step 1 — Log in as a normal user**

You need a valid session cookie.

Credentials provided by the lab:

```
wiener : peter
```

Once logged in, you gain access to the password-change function.

---

## **Step 2 — Visit the Change Password page**

The form typically contains fields like:

* current-password
* new-password
* confirm-password
* username (hidden or displayed)

The browser will submit all fields to the server.

---

## **Step 3 — Intercept the request with Burp Suite**

Use Burp’s **Proxy → HTTP history → Send to Repeater**.

This gives you full control over every parameter before sending the request to the server.

---

## **Step 4 — Remove the entire current-password parameter**

Delete the entire line:

```
current-password=peter
```

Do NOT set it to blank.
Do NOT replace the value.

### Why?

Because the server logic:

* Does NOT validate the password
* Only checks whether the parameter *exists*

Removing the parameter completely bypasses even that minimal check.

---

## **Step 5 — Replace the username parameter**

Modify:

```
username=wiener
```

to:

```
username=administrator
```

This hijacks the identity verification logic (since the server trusts this field).

---

## **Step 6 — Set a new password for the administrator**

Example:

```
new-password=AdminHacked123
```

This becomes the administrator’s new password.

---

## **Step 7 — Send the modified request**

Because of the flawed logic:

* No validation happens
* No linking to session user
* No old password check
* No privilege filtering

The server updates the **administrator's** password as requested.

---

## **Step 8 — Log out**

To clear the session of the `wiener` user.

---

## **Step 9 — Log in as the administrator**

Use the newly forced password:

```
administrator : AdminHacked123
```

Boom — full admin access.

---

## **Step 10 — Access the admin panel and delete user Carlos**

This completes the lab requirement.

---

# **7. Example Requests (Before vs After Attack)**

### **Original Legitimate Request**

```
POST /my-account/change-password
current-password=peter
new-password=NewPass123
username=wiener
```

### **Malicious Modified Request**

```
POST /my-account/change-password
new-password=AdminHacked123
username=administrator
```

### **Resulting Credentials**

```
administrator : AdminHacked123
```

With these, the attacker gains full administrative control.

---
---
---

# **How to Prevent This Vulnerability**

This type of issue isn’t fixed by “one patch”.
It’s fixed by **rebuilding the logic the right way**.

Below are the prevention controls grouped by category so you can directly see what solves what.

---

# **1. Never Trust Client‑Supplied User Identity**

### **Root Cause This Fixes:**

The app used `username=` from the request body to decide *which account* to modify.

### **Fix:**

The server must ALWAYS determine the user from the **session**, NOT from request parameters.

### **Correct approach:**

**Server-side:**

```python
# BAD ❌
username = request.form['username']  

# GOOD ✔️
username = session['user_id']
```

**What this prevents:**
Attackers can’t impersonate other users by just changing `username=administrator`.

This single fix kills the entire account takeover chain.

---

# **2. Enforce Mandatory Old-Password Verification**

### **Root Cause This Fixes:**

The server didn’t verify whether `current-password` was correct. It only checked for its presence.

### **Fix:**

A password‑change request MUST include:

* The user’s actual current password
* A server‑side verification step that matches it against the stored hash

### **Correct logic flow:**

```python
if hash(submitted_current_password) != stored_password_hash:
    reject("Incorrect current password")
```

### **Impact:**

Prevents attackers from resetting passwords without knowing the old one.

Even if an attacker had a valid session, they still couldn’t take over another user’s account.

---

# **3. Bind All Sensitive Actions to the Authenticated Session**

### **Fix:**

Any high‑risk action — password change, email change, delete account, manage users — must be tied to:

1. The session user
2. A server-side authorization check

### **Proper model:**

```
session user identity → authorization check → perform action on session user only
```

### **Never ever:**

Use form fields to pick the target user for sensitive actions.

---

# **4. Remove Hidden or Editable Username Fields from Sensitive Forms**

Many flawed systems include fields like:

```
<input type="hidden" name="username" value="wiener">
```

This is **not secure** — hidden != protected.

### **Fix:**

Sensitive endpoints should not accept user identifiers from the client.
Only the backend decides the identity.

---

# **5. Use Server‑Side Authorization Checks**

Even after identifying the session user, the system must check:

* Does this user have the right to change this password?
* Does this user belong to this account?
* Is this action allowed for this role?

### **Correct example:**

```python
if session['user_id'] != target_user_id:
    reject("Not authorized")
```

### **This prevents:**

Privilege escalation
Horizontal account takeover
Vertical account takeover (regular user → admin)

---

# **6. Validate Request Structure Properly**

Don’t just check if a parameter “exists”.

### **Fix:**

Implement **strict backend validation**:

* Required fields must be present.
* Required fields must be non-empty.
* Required fields must be correct.

### **Example of proper validation:**

```
If current-password is missing → reject.
If current-password is empty → reject.
If current-password is incorrect → reject.
```

The vulnerable lab only checked the first one.

---

# **7. Remove Business Logic from the Client Side**

Clients should **never** control business logic decisions such as:

* Which user to modify
* Whether validation happens
* Whether a flow is allowed

### **Fix: All business logic must reside on the server.**

---

# **8. Implement Defense-in-Depth Security Controls**

Even if one control fails, others should block the attack.

Recommended safeguards:

### **1. Session-bound anti-CSRF tokens**

Prevent forged requests modifying critical data.

### **2. Rate limiting**

Stops brute-force attempts.

### **3. Logging + Alerting**

Flag suspicious actions:

* Multiple password changes
* Password change for privileged accounts
* Requests missing core fields

### **4. Role Separation**

Admin functions should be completely isolated and require extra validation.

---

# **9. Follow Secure Coding Standards (OWASP ASVS)**

Specifically:

### **OWASP ASVS Controls to Apply**

| Area             | ASVS Requirement                      |
| ---------------- | ------------------------------------- |
| Authentication   | V2.1 – Session binding                |
| Password Change  | V2.6 – Old password verification      |
| Authorization    | V4.1 – User-to-user access protection |
| Business Logic   | V7.1 – Server-side enforcement        |
| Input Validation | V5.1 – Mandatory validation           |

Following ASVS ensures these bugs never happen in the first place.

---

# **10. Summary — The "Perfect" Prevention Model**

### **The server must:**

* Identify the user ONLY from the session
* Never trust client-supplied usernames
* Validate the current password
* Apply changes only to the authenticated account
* Enforce authorization checks
* Use strict backend validation rules
* Avoid client-side logic for sensitive flows
* Log and monitor all privileged ops


