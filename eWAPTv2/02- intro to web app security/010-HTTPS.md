<div align="center">
  <img src="https://github.com/user-attachments/assets/a1d4f373-ecb6-466d-a3a1-13434d042441" alt="image">
</div>

## What Is HTTPS?

**HTTPS (Hypertext Transfer Protocol Secure)** is the secure version of HTTP. It is used to securely transmit data between a client (usually a browser) and a web server.

By default, HTTP sends data in **clear-text**, meaning it is unencrypted and can easily be intercepted, viewed, or altered by attackers on the network. This poses serious security risks, especially when transmitting sensitive information like passwords, personal data, or credit card numbers.

HTTPS solves this issue by encrypting the communication between the client and the server using cryptographic protocols such as **SSL (Secure Sockets Layer)** and **TLS (Transport Layer Security)**.

---

## Why HTTP Is Insecure

Here are the key limitations of HTTP:

* **Lack of encryption**: Anyone with access to the network can read the traffic.
* **No authentication**: The browser cannot verify that it is communicating with the legitimate server.
* **No protection from tampering**: The content can be modified in transit by attackers.

---

## How HTTPS Works

HTTPS operates by layering HTTP over **SSL/TLS**, which provides:

1. **Confidentiality**: Ensures the data is encrypted and unreadable to third parties.
2. **Integrity**: Detects any tampering with the data.
3. **Authentication**: Verifies the identity of the server to prevent impersonation.

### Step-by-Step Process

1. The client (browser) initiates a secure connection with the server.
2. The server responds with a **digital certificate** (TLS certificate), which includes:

   * Domain name
   * Public key
   * Certificate Authority (CA) signature
   * Expiration date
3. The browser validates the certificate by checking:

   * If it is issued by a trusted CA
   * If the domain name matches
   * If it is still valid
4. If validation passes, the client and server perform a **TLS Handshake**, during which:

   * They negotiate encryption algorithms
   * They generate a shared symmetric key (session key)
   * Future communication is encrypted using this key

From this point onward, all HTTP requests and responses are encrypted.

---

## Protocol Stack Comparison

| Protocol Stack    | Without HTTPS | With HTTPS |
| ----------------- | ------------- | ---------- |
| Application Layer | HTTP          | HTTP       |
| Security Layer    | None          | TLS/SSL    |
| Transport Layer   | TCP           | TCP        |
| Network Layer     | IP            | IP         |

---

## Advantages of HTTPS

1. **Data Encryption**
   All data transmitted between the browser and the server is encrypted. Even if an attacker intercepts the traffic, they will not be able to read or modify it.

2. **Authentication**
   The TLS certificate assures the client that it is communicating with the legitimate website, not an imposter.

3. **Data Integrity**
   HTTPS prevents the modification of data during transmission.

4. **Protection from Eavesdropping**
   Attackers cannot passively listen to the traffic and extract sensitive data like credentials or cookies.

5. **User Trust and Browser Indicators**
   Modern browsers indicate secure connections with a padlock icon and often warn users about insecure (HTTP) connections.

6. **Improved SEO**
   Search engines, especially Google, give higher ranking to HTTPS websites.

---

## Important Note: HTTPS Does Not Prevent Web Vulnerabilities

While HTTPS secures the communication channel, it **does not protect the web application itself** from logic flaws or security vulnerabilities such as:

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Insecure Direct Object References (IDOR)

These vulnerabilities must be addressed through **secure coding practices**, **regular testing**, and **code reviews**.

---

## Types of TLS Certificates

| Type                         | Validation Level | Description                                                                      |
| ---------------------------- | ---------------- | -------------------------------------------------------------------------------- |
| DV (Domain Validation)       | Basic            | Verifies domain ownership only. Fast and cheap.                                  |
| OV (Organization Validation) | Intermediate     | Verifies the organization’s identity and domain ownership.                       |
| EV (Extended Validation)     | High             | Verifies extensive details. The organization name may appear in the address bar. |

---

## Summary 

| Feature                           | HTTP | HTTPS |
| --------------------------------- | ---- | ----- |
| Data is encrypted                 | No   | Yes   |
| Server identity is verified       | No   | Yes   |
| Protection from data modification | No   | Yes   |
| Prevents web application attacks  | No   | No    |

---
