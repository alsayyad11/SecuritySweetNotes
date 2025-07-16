<img width="795" height="397" alt="image" src="https://github.com/user-attachments/assets/7a494078-fd86-43c7-96bc-f5e15fa7a648" />


## What is XSS?

**Cross-Site Scripting (XSS)** is a web vulnerability that allows an attacker to inject malicious scripts (usually JavaScript) into a website. These scripts are then executed in the browser of another user.

* It is a **client-side vulnerability**.
* The injected script runs in the context of the vulnerable web page.
* Any user who visits the affected page may be impacted.

---

## How XSS Works

1. **Injection**
   The attacker submits input that contains malicious JavaScript code.

2. **Delivery**
   The server processes the input and includes it in the response sent to the user’s browser.

3. **Execution**
   When the victim visits the page, their browser automatically executes the injected script.

4. **Result**
   The attacker’s code runs with the same privileges as the trusted website. This gives access to cookies, session tokens, page content, and more.

---

## Goal of XSS Attacks

The main goal of XSS attacks is to **exploit the browser to steal information or manipulate user behavior**. Common goals include:

| Goal                      | Description                                               |
| ------------------------- | --------------------------------------------------------- |
| Session Hijacking         | Stealing cookies to impersonate the user                  |
| Account Takeover          | Gaining full control over user accounts                   |
| Credential Theft          | Displaying fake login forms to capture credentials        |
| Defacement                | Modifying how the website appears                         |
| Keylogging                | Logging user keystrokes to steal data                     |
| Phishing                  | Redirecting users to fake websites                        |
| Bypassing Access Controls | Performing unauthorized actions as the user               |
| Worm-like Spread          | Injecting scripts that spread automatically between users |

---

## Summary

| Concept   | Description                                              |
| --------- | -------------------------------------------------------- |
| XSS       | Executes malicious JavaScript in the victim’s browser    |
| Type      | Client-side vulnerability                                |
| Steps     | Inject → Deliver → Execute                               |
| Main Goal | Hijack sessions, steal data, perform actions as the user |

---
