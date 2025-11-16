## **What input validation is supposed to do**

Input validation is the process of making sure that whatever a user enters into a system is:

* Correctly formatted
* Safe to store
* Safe to process
* Acceptable according to the business rules

For example:

* If the system expects an email → it must look like an email.
* If the system expects a number → it must be a number.
* If the system expects a company email → it must belong to that company’s domain.

**Business logic validation** = Rules that enforce *“who is allowed to do what”*.

Example:
Only users with *@dontwannacry.com* emails can access the admin panel.

---

### **How business logic vulnerabilities arise**

A business logic vulnerability happens when:

* The application has a business rule
* But the developer implemented that rule incorrectly
* Or trusted something the user controls
* Or forgot to validate something important

So the attacker uses normal features in an unexpected way to bypass the rule.

Not hacking the system — *hacking the logic of the system*.

---

### **Why email-based authorization is risky**

Some systems check the *domain* of the email address to decide permissions.

Example:

```
If email ends with "@dontwannacry.com" → grant admin access
Else → deny
```

This is risky because:

* The attacker *controls their entire email address*
* The server might store it differently than it was sent
* Email length limits might cause weird behavior
* Email validation might be weak

If the app “trusts whatever email string is stored in the database”, that’s a problem.

---

### **What “trusting the domain part of an email” means**

The domain part is everything after the **@**.

Example:

```
attacker@evil.com
```

Domain = *evil.com*

Some apps assume:
“If the stored domain looks like a trusted domain, then the user is legit.”

But if the attacker finds a way to manipulate the stored email — such as using **truncation** — the server may *think* the email is trusted when it isn’t.

---

# **2. The Specific Vulnerability: Email Truncation**

### **How email length limits work (255 chars)**

Most systems store email addresses in a database column like:

```
VARCHAR(255)
```

This means:

* The maximum length allowed is **255 characters**
* Anything longer gets **cut off** (truncated)

So if you send:

```
300-character-long-email@domain.com
```

The stored version becomes:

**only the first 255 characters**.

---

### **Why truncation happens on the server**

The server receives the user’s email → saves it into a database field.

If the field max length = 255:

* The database removes everything past character 255 automatically.
* The application layer does NOT necessarily check for this.

This is where the flaw starts.

---

### **How an attacker manipulates truncation**

If the app cares about **how the email looks AFTER it is stored**,
but the attacker controls the email BEFORE it is stored,
then the attacker can:

1. Craft an email slightly *longer* than 255 characters
2. Carefully position a trusted domain (like `dontwannacry.com`)
3. Force the server to *cut off the remaining part* of the email
4. Making the stored version end with “@dontwannacry.com”

The trick =
**Positioning the “m” of dontwannacry.com at index 255**.

Meaning:

Stored email ends like:

```
...@dontwannacry.com
```

Even though the original email was something completely different.

---

### **Why placing "dontwannacry.com" at character 245–255 works**

Because:

* Characters 1–244 = attacker-controlled filler (aaaaa...)
* Characters 245–255 = “dontwannacry.com”
* Everything after the 255th character is cut away

Example before truncation:

```
aaaa....aaaa@dontwannacry.com.attacker-id.web-security-academy.net
```

After truncation:

```
aaaa....aaaa@dontwannacry.com
```

Boom.
The server thinks the user is actually a *DontWannaCry employee*.

---

### **Real-world implications**

Attackers can:

* Impersonate internal users
* Force account upgrades
* Get admin functionality
* Trigger internal-only workflows
* Bypass domain-based access control

This is a *business logic flaw*, not a bug in cryptography or servers.

---

# **3. Full Walkthrough Using the Lab**

Let’s walk through the exact PortSwigger lab step-by-step.

---

## **Step 1 — Discovering /admin**

Using Burp Suite → Content Discovery →
You find:

```
/admin
```

Trying to access it shows a message:

```
Only DontWannaCry employees may access this.
```

So the application uses:

**Email domain = authorization method**

---

## **Step 2 — Understanding the Registration Page**

The registration page literally says:

> “DontWannaCry employees should use their company email address.”

So:

* If your email = *@dontwannacry.com* → you get admin access
* If not → you’re a normal user

This is the core logic you’re about to break.

---

## **Step 3 — Use the email client**

You open the mailbox for:

```
@YOUR-EMAIL-ID.web-security-academy.net
```

This means ANY email that ends with:

```
.<YOUR-ID>.web-security-academy.net
```

will arrive in YOUR inbox.

---

## **Step 4 — Create the first long email to study truncation**

Register using something like:

```
aaaaaaaaaaaaaaaa...aaa@YOUR-ID.web-security-academy.net
```

At least **200+ characters**.

After confirming the email,
you check the "My account" page.

You notice:

**Your email got truncated to exactly 255 characters.**

This confirms:

* The server stores the email in a 255-char field.
* There is no validation after truncation.

Bingo.

---

## **Step 5 — Exploit: Create the second carefully crafted email**

Now craft an email like:

```
VERY-LONG-STRING@dontwannacry.com.<YOUR-ID>.web-security-academy.net
```

Goal:

* Make the “m” in “dontwannacry.com” be character **255**
* Everything after the “m” gets cut off

Final stored email becomes:

```
<attackers-random-string>@dontwannacry.com
```

Which the app treats as a **real employee email**.

---

### **How to calculate the exact length**

Structure:

```
[very long filler] + @dontwannacry.com + .YOUR-ID.web-security-academy.net
```

Let:

* filler = "a" repeated many times

We tune the number of "a"s so that:

Index 255 = the “m” in “.com”

Simplified:

```
length(filler + "@dontwannacry.com") == 255
```

Everything afterwards is ignored by the database.

---

## **Step 6 — Confirm the email**

The confirmation link still arrives in your inbox because:

**The real email (before truncation) still contains your actual domain.**

Even though the stored email does not.

So:

* Delivery works
* Stored version becomes privileged
* You get the best of both worlds

---

## **Step 7 — Log in**

Now the server considers your new account:

```
@dontwannacry.com
```

→ You automatically get access to:

```
/admin
```

---

## **Step 8 — Delete user carlos**

You visit the admin panel and delete Carlos, solving the lab.

---

# **4. ASCII Diagrams**

### **Flow 1: Registration → Truncation → Stored Email**

```
User Input Email
       |
       v
[ Application Server ]
       |
       v
[ DATABASE FIELD (VARCHAR 255) ]
       |
 Truncation happens
       |
       v
Stored Email (first 255 chars only)
```

---

### **Flow 2: Before vs After Truncation**

**Before:**

```
aaaaaaaaaaa...aaaa@dontwannacry.com.<YOUR-ID>.web-security-academy.net
123456.........245 246 ------------------- AFTER 255 -> CUT
```

**After:**

```
aaaaaaaaaaa...aaaa@dontwannacry.com
```

App sees: valid employee.

---

# **5. Summary**

### **Why truncation-based spoofing works**

* The app trusts the *stored email*
* The attacker controls the *original email*
* The database silently truncates long input
* Placing a trusted domain at the 255 boundary rewrites what the server believes

This is the perfect example of a **business logic flaw**, not a technical exploit.

---

# **How to Prevent Email‑Truncation Logic Flaws**

To fix this vulnerability completely, developers must address **four layers**:

1. Input size validation
2. Email parsing + canonicalization
3. Domain verification
4. Business‑logic hardening

We will go layer by layer.

---

# **1. Enforce Correct Email Length BEFORE Saving Anything**

### **Why this matters**

The entire vulnerability exists because:

* The attacker submits a long email (300+ chars)
* The database truncates it to 255 chars
* The application *does not check again after truncation*

This means the email the **user submitted**
≠
the email the **server stored**

Which breaks the business rules.

### **How to fix it**

The application should:

✔ Check email length BEFORE saving
✔ Reject anything above the standard allowed size
✔ Ensure the email used for authentication is exactly what the user submitted

### **Industry standard**

RFC5321 + RFC5322 define:

* Max email length = **254 characters**
* Max local-part = **64 characters**
* Max domain = **255 characters**, BUT email itself must not exceed 254

### **Secure rule**

```
If email.length > 254 → reject
If local-part.length > 64 → reject
If domain.length > 255 → reject
```

### **Effect**

If your app rejects long emails → truncation cannot happen → the vulnerability disappears.

---

# **2. Canonicalize the Email BEFORE Checking the Domain**

### **Why this matters**

The app must confirm that the domain is trustworthy **AFTER any transformations**, including:

* Unicode normalization
* Lowercasing
* Truncation
* Trailing dot removal
* Whitespace stripping

Because the attacker may use tricks like:

```
employee@dontwannacry.com.evil.com
employee@dontwannacry.com................evil.com
employee@dontwannacry.com\0.evil.com      (null-byte trick)
employee@dontwannacry.com%00evil.com
```

### **Canonicalization process**

When the app receives the email:

1. Trim spaces
2. Lowercase the entire domain
3. Normalize Unicode (NFC form)
4. Remove trailing periods
5. Reject any email with control characters
6. Recalculate the final, canonical domain

### **Why this prevents attack**

Once the email is canonicalized *before* storage, the attacker cannot inject hidden characters or domain tricks that magically alter the stored version.

---

# **3. NEVER Decide Authorization Based on String Matching**

### **This is the biggest problem in the lab.**

The application uses this logic:

```
If email endsWith("@dontwannacry.com") → admin
```

This is dangerous because:

* Users control their entire email
* “endsWith” is weak
* “contains” is weak
* “substring after truncation” is weak
* Subdomain tricks break it

### **Correct way**

Use **domain ownership verification**, not string comparison.

A secure system determines if the domain is trusted by verifying that the user truly owns an inbox inside the company email system.

### **Safe methods**

1. Send a verification code to an internal-only email server
2. Require OAuth / SSO for employees
3. Validate MX records belong to the company
4. Validate DNS zone is owned by the company

Example safe flow:

```
User registers → Email = user@dontwannacry.com
System sends a code to that email
User must retrieve the code
BUT: The company email server is not accessible to attackers
```

So attackers can’t fake being employees by spoofing the domain.

---

# **4. Validate After Truncation Too (Post-Storage Validation)**

### **Why this matters**

Even if you fix input size checks, you must add another layer:

**Check what gets saved is valid.**

Because:

* Database columns may still silently truncate input
* Frameworks may re-encode strings
* Unicode conversion may rewrite characters
* Mailers may rewrite addresses

### **Correct approach**

After storing the email:

1. Read the stored version
2. Re-validate the domain
3. If storedEmail != submittedEmail → reject registration
4. If domain != allowed domain → reject registration

### **Why this defeats attacks like this lab**

Even if an attacker tries:

```
aaaaaa@dontwannacry.com.evil.com.......(long filler)
```

The system sees:

* submittedEmail = attacker-controlled
* storedEmail = truncated version
* They are NOT equal → registration fails

---

# **5. Enforce Strict Allowed-Domain Rules With FQDN Checks**

If your platform has “company-only” emails:

DO NOT CHECK domain using:

* endsWith()
* contains()
* substring()
* regex like `/@dontwannacry.com/`

Instead, do:

### **Correct strict rule**

```
extractDomain(email) == "dontwannacry.com"
```

Not:

```
endsWith("dontwannacry.com")
```

Because:

```
attacker@dontwannacry.com.evil.com
```

is NOT the same domain.

### **How to extract domain safely**

1. Split at the final "@"
2. Enforce exactly one "@"
3. Validate the domain against trusted list
4. Ensure no trailing characters or subdomains

---

# **6. Validate MX Records for Trusted Domains**

### **Why?**

If your system is supposed to trust only corporate emails, then validate:

* Does the domain’s MX record belong to the company?
* Does the MX server require corporate authentication?
* Is it a domain the attacker cannot control?

### **This kills the lab exploit**

The attacker used:

```
dontwannacry.com.<their-server>.web-security-academy.net
```

If you enforce:

```
Valid MX = must resolve to real company mail servers
```

Then:

```
dontwannacry.com.<attacker-domain>
```

will fail MX validation → no registration possible.

---

# **7. Reject Emails With Too Many Subdomains**

### **Why?**

Attackers rely on subdomain chaining:

```
dontwannacry.com.attacker.com
```

To trick naive “endsWith” checks.

### **Mitigation**

Reject email domains like:

* more than 3 dots
* more than 63 characters per label
* punycode edge cases
* malformed TLDs

---

# **8. Do NOT authorize admin access at registration time**

### **The fundamental logic flaw**

The app promotes users to “admin” based on their email domain *during registration*.

Attackers can get in because registration is exposed.

### **Correct design**

Admin privileges should NEVER be based on user-supplied registration input.

Instead:

* Use an internal admin creation tool
* Use company SSO / LDAP
* Use invitation-based admin onboarding
* Or require internal VPN

If you don't rely on email domain → truncation exploit becomes irrelevant.

---

# **9. Logging + Alerts**

Systems should alert when:

* Someone registers with an unusually long email
* Email fails canonical validation
* Stored email ≠ submitted email
* High number of registration attempts
* Mixed-domain emails appear

This won’t fix the issue, but it makes attack detection easier.

---

# **10. Summary**

### **To permanently prevent email truncation logic flaws:**

✔ Reject overly long emails
✔ Canonicalize before validation
✔ Validate domain using strict equality, not substring matching
✔ Validate MX records
✔ Verify domain ownership
✔ Validate after truncation/storage
✔ Avoid domain-based authorization altogether
✔ Use SSO or controlled admin provisioning
✔ Reject malformed or multi-subdomain emails
✔ Log suspicious registration input


