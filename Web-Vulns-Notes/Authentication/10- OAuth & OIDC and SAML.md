##  Why We Even Need OAuth?

![image](https://github.com/user-attachments/assets/e41b3672-33dc-4c52-9606-225b44ad3863)

Imagine downloading a new app and it says:

> "Give me your Gmail password so I can access your emails."

You'd panic, right?

That app could:

* Log in as you.
* Steal your data.
* Keep your password even after you stop using it.

**This is exactly why OAuth exists.**

---

##  What Is OAuth?

**OAuth** is a system that allows third-party applications (like Facebook, GitHub, or any website) to:

* **Get your permission** to access a part of your data
* **Without ever seeing your password**

### How?

Instead of the app asking for your password:

* It redirects you to Google or Facebook.
* You log in there.
* Google or Facebook sends back an "Access Ticket" called an **Access Token**.

---

## The Main Players in OAuth (Roles)

| Role                    | Description                                               |
| ----------------------- | --------------------------------------------------------- |
|  Resource Owner    | You – the person who owns the data                        |
|  Client               | The app that wants access to your data                    |
|  Authorization Server | The server that authenticates you (e.g., Google Auth)     |
|  Resource Server     | The server where your data is hosted (e.g., Google Drive) |

---

##  OAuth 2.0 – Authorization Code Flow 

Scenario: You're on a website called `MyApp` and see:

> "Login with Google"

### Here's what happens behind the scenes:

1. **Redirect:**

   * `MyApp` sends you to Google's Auth Server with:

     * `client_id`
     * `redirect_uri`
     * `scope` (what data the app wants)
     * `state` (random string to prevent CSRF)

2. **Login:**

   * You log in using your Google credentials.

3. **Consent:**

   * Google asks:

     > "Do you allow `MyApp` to access your profile and email?"

4. **Authorization Code:**

   * If you approve, Google sends you back to `MyApp` with an **Authorization Code**.

5. **Token Exchange:**

   * `MyApp` sends this code to Google's Token Endpoint to receive:

     * **Access Token**
     * (optional) **Refresh Token**

6. **API Access:**

   * `MyApp` uses the Access Token to call Google's API on your behalf.

---

##  Token Types

###  Access Token

* Like a temporary entry ticket.
* Grants access to user data for a limited time.
* Usually a JWT or Bearer Token.
* Expiry: e.g., 1 hour.

###  Refresh Token

* Used to get a new Access Token when the old one expires.
* Allows long-term sessions without re-login.
* **Very sensitive!** Must be securely stored.

---

## Where Does OIDC Come In?

OAuth only provides **Authorization**, not **Authentication**:

*  Doesn’t tell the app *who you are*
*  Doesn’t confirm your identity

That’s where **OIDC (OpenID Connect)** comes in.

---

## What Is OIDC?

**OIDC** is a layer on top of OAuth that says:

> "Also tell me who the user is."

It allows the app to know:

* Your name
* Email
* Profile picture
* User ID

This is done via a new token called **ID Token**.

---

##  What Is an ID Token?

A signed token (usually a JWT) containing:

| Claim   | Description                                   |
| ------- | --------------------------------------------- |
| `sub`   | Unique user ID                                |
| `email` | Your email                                    |
| `iss`   | Who issued the token (Google, Facebook, etc.) |
| `aud`   | The client app allowed to use this token      |
| `exp`   | Token expiry                                  |

---

##  OAuth vs OIDC

| Feature               | OAuth | OIDC |
| --------------------- | ----- | ---- |
| Grants access to data | ✅     | ✅    |
| Identifies the user   | ❌     | ✅    |
| Uses Access Token     | ✅     | ✅    |
| Provides ID Token     | ❌     | ✅    |

---

##  Real-World Examples

### Example 1 – Login with Google

* User logs in to a website using Google.
* The app uses **OIDC**.
* It receives an **ID Token** to identify the user.

### Example 2 – Access Google Calendar

* A third-party app wants to read your Google Calendar.
* It uses **OAuth**.
* It gets an **Access Token** to access the API.

---

##  How to Secure OAuth/OIDC Implementations

Best practices:

1.  Always use HTTPS
2.  Use `state` to protect against CSRF
3.  Use `PKCE` in mobile or SPA apps
4.  Limit `scope` to only what's necessary
5.  Validate ID Token (signature, `iss`, `aud`, `exp`)
6.  Don’t store tokens in `localStorage` in web apps

---

## What Is PKCE?

**PKCE = Proof Key for Code Exchange**

A security layer to prevent token interception.

Used with:

* Mobile apps
* Single Page Applications (SPAs)

---

##  Summary

| Use Case                   | Use This     |
| -------------------------- | ------------ |
| Just logging in            | OIDC         |
| Accessing user's data      | OAuth        |
| Login + access in one flow | OIDC + OAuth |

---

##  What Is SAML?

**SAML** is a protocol from the early 2000s designed for:

> **Single Sign-On (SSO)**

Example: Log in once at your company’s identity system → access all internal apps.

---

## How Does It Work?

1. You try to access an internal app (e.g., HR portal).
2. The app (called **Service Provider**) redirects you to the **Identity Provider (IdP)** (e.g., Okta, ADFS).
3. You log in at the IdP.
4. IdP sends a **SAML Assertion** (a signed XML document with your identity).
5. The app verifies the assertion and grants access.

---

##  SAML Components

| Component                  | Description                                        |
| -------------------------- | -------------------------------------------------- |
| 👤 User                    | The person trying to log in                        |
| 🏢 Identity Provider (IdP) | Authenticates the user (e.g., Okta, Azure AD)      |
| 🧾 Service Provider (SP)   | The target app (e.g., Salesforce, Zendesk)         |
| 📄 SAML Assertion          | A signed XML containing user identity & attributes |

---

##  SAML Flow 

1. User visits a Service Provider (SP).
2. SP redirects to the IdP.
3. User authenticates at IdP.
4. IdP returns a signed **SAML Response** (XML).
5. SP verifies it → logs user in.

---

##  Sample SAML Assertion

```xml
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>user@company.com</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="Role">Admin</saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

---

## SSO via SAML

Key benefit:

> **Login once → access many apps**

E.g., login to Azure AD → use Salesforce, Jira, Confluence without re-authenticating.

---

##  SAML vs OAuth vs OIDC

| Feature               | SAML                       | OAuth 2.0                 | OIDC                         |
| --------------------- | -------------------------- | ------------------------- | ---------------------------- |
| Token Format          | XML                        | Access Token (JWT/Bearer) | Access + ID Token (JWT)      |
| Purpose               | Single Sign-On             | Delegated API Access      | Auth + Identity Verification |
| Identifies the User?  | ✅                          | ❌                         | ✅                            |
| Data Access?          | ❌ (or limited)             | ✅                         | ✅                            |
| Typical Use           | Enterprises / Internal SSO | Public APIs / Mobile / 3P | Modern Login with Identity   |
| Mobile/SPAs Friendly? | ❌ (poor)                   | ✅                         | ✅                            |
| MFA Support           | ✅                          | ✅                         | ✅                            |

---

##  Which One Came First?

| Protocol | Year Released |
| -------- | ------------- |
| SAML     | 2002          |
| OAuth    | 2010          |
| OIDC     | 2014          |

---

##  When to Use Which?

| Situation                                 | Use            |
| ----------------------------------------- | -------------- |
| Corporate with Active Directory + SSO     |  SAML         |
| Mobile app needing Google Drive access    |  OAuth        |
| Web app with "Sign in with Google"        |  OIDC         |
| B2B SaaS app offering enterprise login    |  SAML or OIDC |
| Need both login & data access in one step |  OIDC + OAuth |

---

##  SAML Security Considerations

* Assertions must be **digitally signed**
* Validate:

  * `Issuer`
  * `Audience`
  * `Expiration`
  * Replay attacks (via `InResponseTo`)

---

##  Final Summary

| Your Goal                        | Use       |
| -------------------------------- | --------- |
| Single Sign-On in enterprise     | **SAML**  |
| Grant app access to user data    | **OAuth** |
| Login with identity verification | **OIDC**  |

---
