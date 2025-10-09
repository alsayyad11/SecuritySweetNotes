
## 1. Password-based authentication

### What it is

A user proves identity by presenting a secret string (password) associated with an account (username or email). Server verifies the secret and issues a session (cookie or token).

### How it’s normally implemented (high level)

1. Client posts credentials to `/login` (HTTPS).
2. Server looks up account, verifies password (compare hashed + salted stored value).
3. On success, server issues a session (cookie with a session id) or issues tokens (JWT / access token).

### Common attacks against password auth

* **Weak passwords / credential reuse**

  * Users choose simple or common passwords; attackers try common lists (rockyou, etc.).
  * When users reuse passwords across sites, a breach on site A exposes credentials usable on site B (credential stuffing).

* **Brute-force and credential-stuffing**

  * Brute-force: try all combinations (rare at scale; rate-limiting mitigations exist).
  * Credential stuffing: try known username/password pairs from leaks against other sites; succeeds if users reused credentials.

* **Phishing**

  * Attacker tricks user into entering credentials into a malicious page that forwards them to attacker.
  * Phishing is effective vs passwords and can bypass password-based 2FA (if real-time relay).

* **Password spraying**

  * Attack uses a small set of common passwords against many accounts to avoid lockouts.

* **Server-side compromise or weak hashing**

  * If server stores passwords with weak hashes (MD5 / unsalted SHA1), attackers can crack them offline. Use strong salted hashes (bcrypt, Argon2).

### Defenses and best practices

* **Enforce strong password policies**: length over complexity, passphrases. Prefer minimum 12–16 characters.
* **Blocklist known-bad passwords** (HaveIBeenPwned/passwords API) to prevent commonly leaked choices.
* **Rate-limit login attempts** and implement progressive backoff, temporary lockout on repeated failures (but avoid account enumeration and DoS vectors).
* **Multifactor Authentication** (see section 2) — require MFA for high-risk operations.
* **Password storage**: always store salted hashes using Argon2id (or bcrypt/scrypt with appropriate cost parameters). Never store plaintext.
* **Credential stuffing protection**: monitor for leaked credentials, test for reused passwords, apply login protection services (e.g., bot mitigation, CAPTCHA, device fingerprinting).
* **Phishing-resistant approaches**: prefer phishing-resistant MFA (hardware tokens, WebAuthn/FIDO2) and phishing-resistant SSO solutions.

---

## 2. Multi-Factor Authentication (MFA)

### Overview

MFA requires two or more independent factors from these categories:

* **Something you know** (knowledge): password, PIN, answers to secret questions (avoid using as 2nd factor)
* **Something you have** (possession): smartphone app, hardware token, SMS, security key
* **Something you are** (inherence): fingerprint, face recognition, biometric trait

MFA reduces risk because attacker must obtain multiple factor types.

### Common MFA methods

#### 2.1 Authenticator apps (TOTP)

* Apps like Google Authenticator, Authy, Microsoft Authenticator implement **TOTP** (Time-Based One-Time Password).
* Server and app share a secret; app generates codes (6 digits) that change every 30 seconds.
* Pros: offline, resistant to passive interception.
* Cons: can be phished with real-time relay; backup/transfer issues if user loses device.

#### 2.2 HOTP (counter-based OTP)

* One-Time Passwords based on a counter (HMAC). Less common for interactive login; used in some hardware tokens.

#### 2.3 SMS / Email OTP

* Server sends a one-time code to user’s phone number (SMS) or email.
* Pros: convenient and ubiquitous.
* Cons: insecure: SMS can be intercepted, SIM-swap attacks can reassign phone number, SMS messages may be accessible to adversaries; email may be compromised.

#### 2.4 Push notifications / Out-of-band (OOB) push

* Server sends a push to trusted app (e.g., Duo, Microsoft Authenticator) asking user to approve sign-in. Often shows context (device, IP).
* Pros: user friendly, phishing-resistant to an extent; can include transaction details.
* Cons: susceptible to approval fatigue/social engineering ("Approve that sign-in").

#### 2.5 Hardware security keys (FIDO2 / U2F / WebAuthn)

* Physical device (YubiKey, Titan Key) that performs cryptographic challenge signing. Built on public-key cryptography and is **phishing-resistant** because the key signs only for the legitimate origin (origin binding).
* Pros: strong, phishing-resistant, no shared secrets, supports FIDO2/WebAuthn flows.
* Cons: user must carry key; onboarding flow required.

#### 2.6 Biometrics (fingerprint, face)

* Local biometric check unlocks a private key on device (e.g., platform authenticator).
* Pros: convenient; combined with hardware tokens for strong resistance.
* Cons: biometric data, once compromised, cannot be changed; must be implemented with safe local storage (TPM, Secure Enclave). Also has false positives/negatives.

### Attacks against MFA

* **SIM swap** — attacker convinces mobile carrier to transfer victim’s number; attacker receives SMS OTPs and phone-based auth.

  * Mitigation: reject SMS for high-value auth when possible; use hardware keys or app-based TOTP; require PIN/port-out protection with carriers.

* **Phishing with real-time relay** — attacker captures credentials and OTP in real time and forwards to legitimate site; works for password+TOTP and push if user approves.

  * Mitigation: use phishing-resistant MFA (WebAuthn hardware keys), educate users, detect anomalous login contexts (new device, geo), block impossible travel.

* **Social engineering (push fatigue, bribery, helpdesk bypass)** — attacker convinces user or operator to approve.

  * Mitigation: show contextual info in push requests; rate-limit approvals; implement approvals with transaction data.

### Best practices for MFA

* Prefer **phishing-resistant** second factors (hardware keys / WebAuthn).
* Keep recovery processes secure — poorly designed account recovery is a major bypass (alternate email, SMS recovery). Use multiple recovery channels with strong identity proof.
* Provide backup codes that are single-use and require secure storage.
* For push/TOTP, tie sessions to device fingerprint and present risk-based challenges for suspicious activity.

---

## 3. Token-based authentication (JWT, opaque tokens, refresh tokens)

### Overview

Modern web/mobile apps often use tokens (instead of server sessions) to represent authenticated identity. Two broad types:

* **Opaque tokens**: random identifiers stored server-side (session store, DB). Server validates token by looking it up.
* **JWT (JSON Web Token)**: self-contained tokens with claims, signed (and optionally encrypted). Server validates signature and trust chain.

### JWT — what it is

* A JWT has three dot-separated parts: `header.payload.signature`.
* Payload contains claims: `sub`, `iss`, `aud`, `exp`, `iat`, etc.
* Signed with HMAC (shared secret) or RS256 (RSA public/private). Verification done by signature check.

### Common JWT pitfalls

* **No server revocation**: Because JWTs are self-contained, you cannot easily revoke them until they expire unless you maintain a revocation list.

  * Mitigation: set short `exp` times, use refresh tokens for long sessions, maintain a revocation store if necessary.

* **Long-lived access tokens**: If `exp` is long, token theft leads to long window of misuse. Use short-lived access tokens (minutes–hours) + refresh tokens.

* **Improper signature verification**: Accepting unsigned tokens or incorrect key validation (alg: none vulnerability historically). Always validate `alg` and signature and verify `aud`, `iss`, `exp` claims.

* **Storing tokens insecurely on client**: Storing tokens in localStorage can expose to XSS; cookies mitigate XSS but can be vulnerable to CSRF unless properly configured.

### Access + Refresh token pattern (recommended)

* Issue **short-lived access token** (JWT) used to access APIs (e.g., 5–15 minutes).
* Issue **refresh token** (longer-lived, stored securely) to obtain new access tokens.
* Refresh tokens are usually opaque and must be revocable server-side.
* Use refresh rotation: each refresh replaces the refresh token and invalidates the previous one (prevents replay).

### Storage options & their tradeoffs

* **HttpOnly Secure cookies** (same-site settings):

  * Pros: not accessible to JavaScript (resists XSS), browser attaches cookie automatically.
  * Cons: susceptible to CSRF unless SameSite or CSRF token used. For APIs use `SameSite=Strict` or `Lax`, or prefer token in Authorization header with CSRF mitigations.

* **localStorage/sessionStorage**:

  * Pros: simple, used by SPAs.
  * Cons: vulnerable to XSS (attacker JS can read tokens).

* **Browser memory (in-memory)**:

  * Pros: safest from persistent XSS; cleared on reload.
  * Cons: complex for page reloads; requires refresh or silent auth.

* **Native secure storage (mobile)**: Keychain (iOS), Keystore (Android) for apps.

### CSRF & tokens

* If using cookies for auth, defend against CSRF with SameSite cookies and/or CSRF tokens per form/unsafe method.
* If using Authorization header tokens, CSRF is not a problem but XSS becomes primary concern.

### Practical JWT HTTP example

Login flow (server issues JWT in response):

```
POST /auth/login
Content-Type: application/json

{ "username": "alice", "password": "s3cret" }

200 OK
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9....",
  "expires_in": 900,
  "refresh_token": "opaque-refresh-token"
}
```

API call with Bearer token:

```
GET /api/profile
Authorization: Bearer eyJhbGciOi...
```

Refresh flow:

```
POST /auth/refresh
Authorization: Bearer <refresh_token>
```

---

## 4. OAuth and OpenID Connect (OIDC)

### OAuth 2.0 — purpose

OAuth is an **authorization** framework that allows a user to grant a client limited access to their resources on a resource server without sharing credentials. Frequently used to allow third-party apps to access APIs on behalf of users.

### OAuth roles

* **Resource Owner**: the user
* **Client**: the application requesting access
* **Authorization Server**: issues tokens (OAuth server)
* **Resource Server**: exposes protected resources (API)

### Common OAuth flows

* **Authorization Code Grant** (server-side apps): secure, uses code exchanged for tokens. With **PKCE** for public clients (mobile/SPA). Recommended for most apps.
* **Implicit Grant** (deprecated): returned tokens directly in redirect URI (not recommended).
* **Client Credentials**: machine-to-machine (no user).
* **Resource Owner Password Credentials** (deprecated): app collects username/password — avoid.
* **Device Code**: for devices with limited input.

### PKCE (Proof Key for Code Exchange)

* PKCE prevents interception of authorization codes in public clients (SPAs/mobile). Client creates a random `code_verifier`, sends its hashed `code_challenge` at auth request, then uses `code_verifier` when exchanging code. Authorization server verifies match.

### OpenID Connect (OIDC)

* Layer on top of OAuth for authentication. Returns an **id_token** (JWT) that asserts user identity. Use OIDC for SSO and authentication.

### Threats & mitigation

* **Authorization code interception** — mitigated by PKCE and TLS.
* **Improper redirect URI validation** — always validate redirect URIs exactly (no wildcards).
* **Token leakage via referrer** — use `referrer-policy` and avoid placing tokens in query strings.
* **Scope over-granting** — request only necessary scopes; use least privilege.

---

## 5. Single Sign-On (SSO) and Federation (SAML / OIDC)

### What SSO is

SSO allows users to authenticate once with an identity provider (IdP) and then access multiple applications (service providers) without signing in again.

### Common protocols

* **SAML**: XML-based, widely used in enterprise SSO (SSO between corporate IdP and apps).
* **OpenID Connect**: modern JSON/JWT-based authentication built on OAuth2. Used for web and mobile.
* **Kerberos/NTLM**: internal SSO in Windows domains.

### Benefits

* Convenience for users, centralized identity management, easier enforcement of corporate policies (MFA, password policies), logs.

### Risks

* **Single point of compromise**: if IdP is breached or account compromised, attacker gains access across many apps.
* **SSO misconfiguration**: weak trust, incorrect claim mapping, or poor logout flows can cause issues.

### Best practices

* Enforce strong MFA at IdP.
* Validate assertions and audience (`aud`) claims.
* Implement SP-initiated and IdP-initiated flows carefully.
* Implement SAML/OIDC logout or session revocation when necessary.

---

## 6. One-Time Passwords (OTP): HOTP, TOTP, SMS/Email OTP

### HOTP (HMAC-based OTP)

* Based on a counter, synchronized between server and token. Produces one-time codes that change on use.
* Less commonly used in web MFA.

### TOTP (Time-based OTP)

* Codes generated from a shared secret and current time (RFC 6238). Commonly used by Google Authenticator style apps.
* Provides 30-second window and is widely supported.

### SMS/Email OTP

* Server sends a one-time code over SMS or email.
* Widely used but considered weaker due to interception and SIM swap threats.

### Security considerations

* **TOTP** is stronger than SMS, but still vulnerable to real-time phishing relay if the attacker mediates the session.
* **HOTP** needs robust counter handling.
* **SMS** is vulnerable to SIM swap and interception — do not rely on SMS for high-security contexts if stronger alternatives available.
* Use rate limiting for OTP submit attempts and expiry windows.

---

## 7. Additional concepts and defenses

### Device binding and risk-based authentication

* Tie tokens or sessions to device fingerprints, IP ranges, user agent. Use risk scoring to prompt additional verification when anomalies occur (new device, unusual geo, rapid requests).

### Account recovery

* Account recovery often becomes the weakest link — design recovery to be as secure as login. Avoid replacing robust MFA with weak email-only recovery without verification. Consider account recovery codes, multi-channel verification, or human-in-the-loop identity proofing for high-value accounts.

### Session management & logout

* Implement secure session invalidation on logout and password change. Use server-side session stores or short-lived tokens + refresh rotation. On logout, revoke refresh tokens and invalidate access via revocation lists if needed.

### Logging and monitoring

* Log failed logins, MFA failures, suspicious IPs, device changes. Alert on abnormal patterns: many login failures, logins from new countries, or unusual refresh token use.

### Protecting against XSS & token theft

* Sanitize input and use Content Security Policy (CSP) to reduce XSS risk. For tokens, prefer HttpOnly, Secure cookies, SameSite configuration; for SPA consider silent refresh and in-memory storage.

### Secure passwordless approaches

* **WebAuthn/FIDO2**: Public key credentials where server stores public key, client holds private key; auth is phishing-resistant. Use for high security and passwordless login flows.

---

## 8. Practical implementation checklists

### When implementing password auth

* Use Argon2id for hashing (tunable cost).
* Enforce password strength and blocklist.
* Implement account lockouts with exponential backoff (avoid account enumeration leaks).
* Require MFA for high-risk operations and administrative accounts.

### When implementing token auth (JWT)

* Use short `exp` on access tokens.
* Use refresh token rotation and server-side revocation tracking.
* Protect refresh endpoints (require client authentication, rotate tokens).
* Validate signature, `iss`, `aud`, and `exp`.
* Avoid putting sensitive data in JWT payload unless encrypted.

### When implementing OAuth/OIDC

* Use Authorization Code Flow with PKCE for SPAs and mobile apps.
* Use state parameter to prevent CSRF in auth redirects.
* Validate redirect URIs strictly.
* Keep scopes minimal.

### When deploying MFA

* Offer hardware keys (WebAuthn) as highest assurance.
* Offer TOTP apps as default second factor.
* Use SMS only as fallback and with carrier protections.
* Design secure recovery — avoid broad bypass via single channel.

---

## 9. Example flows (concise practical snippets)

### TOTP verification (high level)

1. Server and client share base32 secret at enrollment: `otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example`.
2. Client's authenticator generates TOTP code every 30s from secret.
3. On login, server validates submitted code against expected TOTP.

### OAuth 2.0 Authorization Code (with PKCE) flow (simplified)

1. Client creates random `code_verifier` and hashed `code_challenge = base64url(SHA256(code_verifier))`.
2. Client redirects user to authorization server: `/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256`.
3. User authenticates at auth server and consents; server redirects back with `code`.
4. Client sends `POST /token` with `code`, `code_verifier`; server verifies and issues `access_token` (and `refresh_token`).

### JWT validation example (server)

* On each request:

  * Extract `Authorization: Bearer <token>`.
  * Verify signature with public key / secret.
  * Verify claims:

    * `exp` > now (not expired)
    * `nbf` <= now (not before)
    * `iss` matches issuer
    * `aud` includes your audience
  * Optionally, check token in revocation list if implemented.

---

## 10. Summary — prioritized recommendations

1. **Use MFA for all privileged accounts and at least offer it for all users. Prefer phishing-resistant factors (FIDO2/hardware keys).**
2. **Use short-lived access tokens + refresh token rotation** for token-based systems.
3. **Avoid SMS as primary second factor** for high-value accounts; use it only as fallback.
4. **Store passwords safely** with Argon2id and blocklist known weak passwords.
5. **Implement PKCE and Authorization Code grant** for SPAs and mobile apps using OAuth/OIDC.
6. **Use secure cookie flags and CSRF protections** when authenticating via cookies.
7. **Design secure recovery flows**; account recovery is often the weakest link.
8. **Log and monitor** suspicious auth activity; respond to anomalies promptly.
