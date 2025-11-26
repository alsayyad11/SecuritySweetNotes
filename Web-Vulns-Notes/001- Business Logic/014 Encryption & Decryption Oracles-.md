

## 1. **What’s an Encryption Oracle? Why Is It Dangerous?**

An **encryption oracle** is an application feature that lets users submit arbitrary plaintext and receive the ciphertext produced using the app’s internal key and encryption algorithm.  
**Dangerous scenarios happen** when user-controlled input is encrypted and the resulting ciphertext is, in any way, made available to the user. Attackers thus have a mechanism to encrypt data with the correct algorithm and (often) the correct key.

This becomes critical when:
- Other places in the application accept encrypted input from the user that expects ciphertext generated with **that same algorithm and key**.
- The attacker can use the encryption oracle to create valid, attacker-controlled encrypted values (tokens, cookies, API params) and pass them into other sensitive functions.

The risk is even **more severe** if there’s another user-controllable input on the site that offers the *reverse* function—a **decryption oracle** that lets the user submit ciphertext and get plaintext out (or see it reflected in an error message, etc).  
This lets the attacker:
- Decrypt legitimate tokens (like cookies or session IDs)
- Discover the expected internal structure and formatting of tokens/cookies  
- Mass-produce perfectly-forged malicious data with less trial and error, but even without decryption, a well-crafted exploit can succeed.

**Severity** depends on which application functions share the algorithm and key—if it controls authentication, roles, or sensitive data/functions, it’s typically **critical**.

***

## 2. **Core Definitions & Attack Primitives**

- **Encryption oracle:** Endpoint or feature that returns ciphertext for attacker-supplied plaintext using the application’s internal key(s).
- **Decryption oracle:** Endpoint/feature that accepts ciphertext and returns (or reflects) plaintext.
- **Target tokens:** Anything encrypted by the app and trusted (session cookies, authorization tokens, password reset links, etc.).
- **Block-based cipher:** Ciphers like AES, operate in 16-byte blocks. Block boundaries, padding, and IV matter for manipulation.
- **Transformations for exploitation:**
   - URL decode / encode
   - Base64 decode / encode
   - Hex/binary view/edit
   - Remove/Add whole blocks of ciphertext
   - Re-encode for use as cookies/headers

***

## 3. **Why Encryption Oracles Are Dangerous? Practical Scenarios**

1. **Token Forgery (Authentication/Authorization Escalation)**
   - If the server uses encrypted tokens for auth or role assignment, the oracle lets attackers create a ciphertext that decrypts to `role=admin` or `user=administrator`.
   - Attacker injects the forged ciphertext into a cookie/header/request and gains privileges.

2. **Chaining Oracles Across Inputs**
   - If the application allows client-supplied encrypted values in different places (cookie, parameter, header), the attacker can use the oracle to produce valid values for any context.

3. **Format Disclosure via Reflection**
   - If errors or pages reflect decrypted cookies’ contents, attackers learn the *structure* (e.g., `user:timestamp`).
   - They then know how to structure arbitrary, valid plaintexts for encryption.

4. **Automation & Scalability**
   - After learning the structure, attackers can easily and automatically mass-produce tokens for unauthorized actions.

5. **Decryption Oracle Amplification**
   - If there’s a decryption oracle, attackers decrypt legitimate data, learn every detail: fields, separators, encoding, padding.
   - “Reverse engineering” token formats becomes trivial.

**Severity rises with sensitivity of functions using the same key/algorithm as the oracle. If it’s used for login tokens, payment, admin: critical. If only for notifications, less so.**

***

## 4. **How Decryption Oracle Amplifies Attacks**

- Decryption oracle reveals plaintext for any supplied ciphertext.
- Practical outcome: submit legitimate tokens, see full details; attacker learns token structures with full accuracy.
- With this, exploit cycles are rapid, forgeries perfect (regardless of random IV usage in encryption).

***

## 5. **Cryptographic Details (Blocks, Prefixes, Padding, Example)**

- **Block size (AES):** 16 bytes. Changes need to align with blocks, or decryption will fail.
- **Prefix handling:** If a fixed prefix is prepended to plaintext before encryption (e.g., `"Invalid email address: "`), attackers need to pad their input, ensure the prefix fits into full blocks, and delete the corresponding ciphertext blocks.
- **Removing blocks:** To remove a 23-byte prefix, pad to a 32-byte block (add 9 arbitrary chars), then after encryption, delete first 32 bytes of ciphertext (two blocks).

*Example:*
- You want token `administrator:timestamp`
1. Pad input: `xxxxxxxxxadministrator:timestamp`
2. Oracle encrypts, returns ciphertext.
3. Base64/hex decode; delete the first 32 bytes; re-encode.
4. Use forged ciphertext as login cookie.

***

## 6. **Lab Walkthrough: All Steps & Explanations**

### Prerequisites
- Burp Suite (Proxy, Repeater)
- Browser proxied through Burp
- Credentials: `wiener:peter`
- Lab access

### Steps

#### Step 1 — Obtain Cookie Format
- Login with user, enable "Stay logged in".
- Get original `stay-logged-in` cookie.

#### Step 2 — Find Encryption Oracle
- Submit comment with custom (malicious) input.
- Server sets notification cookie (encrypted).

#### Step 3 — Find Decryption Oracle
- Use endpoint that reflects decrypted cookie/input in page or error message.

#### Step 4 — Reveal Format
- Paste original `stay-logged-in` value into notification cookie, send through decryption endpoint.
- See output: `wiener:timestamp`.

#### Step 5 — Direct Admin Token Attempt
- Encrypt `administrator:timestamp`, try as cookie—fails as decrypted output contains unwanted prefix.

#### Step 6 — Adjust Blocks
- Pad input with 9 extra bytes so prefix is a multiple of sixteen (two blocks).
- Encrypt, then delete first two blocks from ciphertext.

#### Step 7 — Forge Admin Token
- Paste edited ciphertext as `stay-logged-in` cookie; request homepage to confirm admin.

#### Step 8 — Confirm Privilege Escalation
- Visit `/` (see admin status).
- `/admin` (admin UI visible).
- `/admin/delete?username=carlos` (user deleted).

*Every step reflects how the real application can be abused by combining oracles and adjusting block-aligned exploits.*

***

## 7. **Manipulation Techniques Cheat Sheet**

- **URL decoding:** Reverse percent encoding.
- **Base64 decoding:** Get raw bytes for editing.
- **Hex editing:** Remove/add blocks at exact offsets.
- **Re-encoding:** Back to Base64, then URL; paste as cookie value.

***

## 8. **Example: Decoding and Interpreting Cookies**

Given:
```
awaUOmbpP0ynecCTTgwW7ABGq4%2bcuN657n7woHQ1awU%3d
```
- URL decode: awaUOmbpP0ynecCTTgwW7ABGq4+cuN657n7woHQ1awU=
- Base64 decode: hex bytes...
- Paste into decryption oracle endpoint to see plaintext.

***

## 9. **Post-exploit Verification**

- Visit `/`, confirm `administrator` displayed.
- `/admin` accessible? UI shows admin privileges.
- `/admin/delete?username=carlos`: user deleted and lab solved.

***

### 1. **Never expose encryption endpoints for arbitrary user input**
- **Do not provide endpoints** or features that allow clients to encrypt chosen plaintexts using internal application secrets (session keys, master keys).
- **If encryption is necessary**, always use user-specific or ephemeral keys not shared with sensitive functions.

***

### 2. **Eliminate decryption oracles**
- **Don’t allow user-supplied ciphertext** to be decrypted and reflected back to the client, either in UI, error messages, or API responses.

***

### 3. **Don’t reuse encryption keys for multiple purposes**
- Use **different cryptographic keys** for different domains (e.g., session tokens, notifications, password resets).
- **Key separation** limits the damage of any single oracle exposure.

***

### 4. **Always use authenticated encryption (AEAD modes)**
- Implement strong encryption algorithms that provide both confidentiality and integrity:
    - **AES-GCM**
    - **ChaCha20-Poly1305**
- **Authenticated encryption** ensures that tampered ciphertexts are detected and rejected.

***

### 5. **Prefer signing over encrypting for tokens**
- Use **secure signatures** (e.g., HMAC, JWT with RS256/ES256) rather than opaque encrypted tokens.
- Signing allows the server to validate token authenticity without decrypting user data.

***

### 6. **Validate all decrypted inputs server-side**
- After decryption, **strictly validate** fields, formats, allowable values, timestamps, and revocation status.
- **Never trust decrypted content blindly**—cross-check with business rules.

***

### 7. **Sanitize error messages**
- **Never echo decrypted information** (even partial data) in errors, logs, or UI; keep these details safely on the server side.

***

### 8. **Implement strict cookie configurations**
- Use `HttpOnly`, `Secure`, and `SameSite` flags for all cookies.
- Set **cookie scope** tightly (path/domain).

***

### 9. **Monitor, rate-limit, and log crypto operations**
- **Log all cryptographic endpoint calls**, flag abnormal/frequent use.
- Apply **rate limiting** to block mass token generation or brute force attempts.

***

### 10. **Engage experts for cryptographic design & code review**
- Include experienced **security architects** and **cryptographers** in app design.
- Perform **threat modeling** on all flows involving encryption and authentication.

***

## 10. **Mitigations & Secure Design Recommendations**

1. Never expose cryptography endpoints for user data using application secrets—**don’t let users encrypt their own tokens!**
2. Avoid exposing decryption endpoints or reflecting decrypted data to the client.
3. Use *authenticated encryption* modes (AEAD—AES-GCM, ChaCha20-Poly1305) for data integrity/confidentiality.
4. Use separate keys for different purposes (tokens, notifications, etc).
5. Use signed tokens or robust token frameworks (e.g., JWT) rather than opaque encryption.
6. Always validate decrypted data server-side.
7. Never echo internal decrypted info in error messages.
8. Strict cookie flags—HttpOnly, Secure, SameSite.
9. Log and rate-limit cryptographic operations; alert on abnormal usage.
10. Have code, design and logic reviewed by a cryptography expert.

***

## 11. **Testing Checklist**

- Spot endpoints/encrypted cookies set after receiving user input.
- Look for reflected decrypted content in responses (errors, pages).
- Try arbitrary plaintext → encrypted cookies via oracles.
- Use Burp Repeater to inject/modify ciphertexts and observe how the app decodes and uses them.
- Measure constant prefixes in reflected messages.
- Test block-wise deletion/addition in ciphertext, observe outcomes.
- Ensure logs are robust and alert on repeated cryptography actions.

***

## 12. **Summary**

- Encryption oracles are a major vulnerability, especially for sensitive app functions.
- Decryption oracles amplify attack potential by revealing internal formats.
- Exploitation involves oracle endpoints, plaintext/ciphertext manipulation, block-aligned edits, and token injection.
- Real defense means removing public cryptography features, using robust encryption/signing, separating keys, and validating everything server-side.

***

