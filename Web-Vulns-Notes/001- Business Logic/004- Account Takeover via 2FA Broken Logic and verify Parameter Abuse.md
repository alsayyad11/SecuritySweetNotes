
Business logic vulnerabilities around authentication often happen when developers make dangerous assumptions about user behavior. One of the most common and severe examples is when a system relies on **client-controlled parameters** to decide which account is undergoing 2FA verification. When this happens, an attacker can take full control of the entire verification flow simply by modifying a single request. To understand why this is so dangerous, we first need to break down how a proper 2FA flow should work, and then compare it to what was actually implemented in this vulnerable application.

---

# **1. How 2FA Is Supposed to Work**

In a secure system, the 2FA process should look like this:

1. **User submits username + password**
   The server checks if the credentials are correct.

2. **Server stores the identity of the user in the session**
   For example:

   ```
   session.user = "wiener"
   ```

3. **Server generates a temporary 2FA token for the same user**
   This 2FA code is tied internally to the session user and cannot be changed by the client.

4. **User submits the 2FA code**

   * The server checks the code *against the code generated for the session user*.
   * No client parameter is ever allowed to choose which user is being verified.

5. **If verified, the session becomes fully authenticated**

This design ensures that even if an attacker tries to manipulate requests, they can never switch accounts during 2FA and they can never force the server to generate codes for someone else.

---

# **2. What Went Wrong in the Vulnerable Application (Flawed Logic)**

The vulnerable application does *not* follow the secure workflow.
Instead:

* The application uses a parameter called **`verify`** inside the 2FA request.
* This parameter is **controlled entirely by the user**.
* The backend uses this parameter to decide **which user’s 2FA flow should run**.

So instead of the session determining the user being verified, the application believes whatever value is placed inside:

```
verify=<username>
```

This is a catastrophic design flaw because:

* Anyone can change this value.
* Anyone can trigger 2FA generation for another user.
* Anyone can brute-force another user’s 2FA code.
* The system has no mechanism to detect cross-account abuse.

This is exactly the kind of blind trust in user-supplied data that leads to business logic vulnerabilities—specifically, authentication bypass and account takeover.

---

# **3. Full Attack Flow**

Below is the **fully expanded version**, integrating the exact steps you performed.

---

## **Step 1 — Investigating the 2FA Flow**

You started by logging in with your own credentials to observe how the 2FA sequence works.

After entering your username and password, the application redirected you to a 2FA page. You intercepted this request in Burp Suite and saw something unexpected and dangerous:

```
POST /login2
verify=wiener
mfa-code=1234
```

Here, `verify=wiener` clearly tells the server which account is being verified.

This is already a major red flag:
**The server is depending on a client parameter to determine which user's 2FA code should be checked.**

Instead of using the session, the server trusts this parameter.

This discovery is the core of the whole exploit.

---

## **Step 2 — Logging Out**

To avoid session conflicts and ensure that you can cleanly manipulate the process, you logged out. This resets the flow and prepares a clean state for crafting malicious requests.

---

## **Step 3 — Triggering 2FA Generation for Another User (Carlos)**

This is where the real attack begins.

You intercepted the request responsible for loading the 2FA process:

```
GET /login2?verify=wiener
```

Then you sent it to **Burp Repeater**.

Inside Repeater, you modified it:

```
verify=carlos
```

So the request became:

```
GET /login2?verify=carlos
```

You sent the request.

### **What happens internally at this moment:**

* The application receives a 2FA initialization request.
* It trusts the `verify` parameter blindly.
* It therefore believes that **Carlos** is performing a login.
* It generates a fresh 2FA code for **Carlos**.
* It stores this 2FA code server-side, ready to be verified.

This step alone proves the vulnerability.

You have:

* Triggered 2FA generation for a user you are not logged in as.
* Caused the server to allocate a temporary code for Carlos.
* Prepared the environment for brute-forcing Carlos’s 2FA.

Everything is happening because of one simple mistake:
**The application trusted the verify parameter.**

---

## **Step 4 — Triggering a Real 2FA Request to Capture the Request Format**

You then logged back into your own account using your real username and password.

At the 2FA screen, you intentionally entered an invalid code so that Burp could capture the exact structure of the request:

```
POST /login2
verify=wiener
mfa-code=0000
```

This gives you the final form you need to manipulate in Intruder.

---

## **Step 5 — Preparing the Brute-Force Attack**

You sent the above POST request to **Burp Intruder**.

Inside Intruder:

### **1. You changed verify to carlos**

Making the modified request:

```
verify=carlos
mfa-code=0000
```

This forces every brute-force attempt to apply to Carlos’s temporary 2FA challenge.

### **2. You placed a payload marker around the mfa-code**

Example:

```
mfa-code=§0000§
```

This tells Burp Intruder that the digits inside this field should be iterated through.

You then selected a payload list—usually a simple 0000 → 9999 range—to brute-force the entire 4-digit code space.

---

## **Step 6 — Executing the Attack**

You started the attack.

* Each request sent tries a new 2FA code.
* Each request manipulates the verify parameter to target Carlos.
* The backend is tricked into thinking Carlos is performing 2FA.
* Because the code is short (4 digits), brute-forcing is trivial.

Eventually, one of the responses returned:

```
HTTP/1.1 302 Found
Location: /my-account
```

A 302 redirect is a clear sign the verification succeeded.

This means:

* You discovered the correct 2FA code for Carlos.
* You fully authenticated as Carlos.
* The system now treats you as Carlos.

---

## **Step 7 — Finalizing the Attack**

You loaded the successful request in your browser (from Burp).

The session became authenticated as Carlos.

By clicking **"My account"**, the application displayed Carlos’s account dashboard.

You successfully completed a full account takeover.

---

# **4. Why This Vulnerability Exists (Root Logic Failure)**

The fundamental design mistake is this:

**The application ties the 2FA verification to a user-controlled parameter instead of the authenticated session.**

This leads to:

* Cross-user 2FA generation
* Cross-user 2FA verification
* Brute-force feasibility
* Account takeover
* Total bypass of authentication boundaries

This is a severe business logic flaw with authentication impact.

---

# **5. Proper Fix**

To prevent this:

1. **Remove the verify parameter entirely**
   The backend should determine the user from the session, not the request.

2. **Enforce strict session binding**

   ```
   session.user = "wiener"
   ```

3. **Rate-limit MFA attempts**

4. **Use longer MFA codes**

5. **Invalidate codes after several failed attempts**
