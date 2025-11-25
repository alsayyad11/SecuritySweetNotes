

## **1. Core Concept**

Many web applications depend on a **specific sequence of events** (a workflow) for performing sensitive actions.
For example, purchasing an item, changing a password, transferring money, or completing a 2FA login all depend on the user completing **Step 1 → Step 2 → Step 3** in order.

Developers often assume that users will always follow the interface **as intended**.
But attackers don’t follow the UI.
Attackers can:

* Skip steps
* Repeat the same step multiple times
* Go back to an earlier step
* Jump directly to a “final result” step
* Replay any previously captured request at any time

This breaks the assumptions the backend makes about the user's state.

This is where the vulnerability appears.

---

## **2. Why This Happens**

Webapps often track user progress using:

* Session variables
* Hidden fields
* Cookies
* Values passed between steps
* Flags that mark a workflow state

If the backend doesn't **strictly enforce** the correct sequence, then:

The attacker can send **requests out of order** and the server will accept them anyway.

---

## **3. Tools That Make This Possible**

With tools like **Burp Proxy** and **Burp Repeater**, once an attacker sees a request:

* They can replay it whenever they want
* They can modify parameters
* They can access an endpoint directly using forced browsing

Forced browsing = accessing endpoints the UI does not currently show.

Example:
The UI only shows Step 1 → Step 2 → Step 3,
but the attacker already knows Step 3's endpoint (from proxy history),
so they just send Step 3 directly without doing Step 1 or Step 2.

---

## **4. What This Leads To**

If the application does **not** enforce state properly, the attacker may be able to:

* **Bypass payment steps**
* **Bypass confirmation screens**
* **Complete actions without meeting conditions**
* **Skip authentication checks**
* **Trigger final workflow actions without doing the required previous actions**

This is extremely common in:

* e-commerce checkout flows
* password recovery flows
* multi-step profile updates
* booking/reservation systems
* 2FA login workflows

---

## **5. How to Test for This Vulnerability**

You should intentionally break the workflow sequence.

### **What to attempt:**

1. **Skip steps**
   Send the request for Step 3 without doing Step 1 or 2.

2. **Repeat steps**
   Submit the same request more than once.

3. **Return to earlier steps**
   After finishing Step 3, send Step 1 again and see what happens.

4. **Force browse hidden steps**
   Directly access URLs like:
   `/checkout/confirm`
   `/finish-payment`
   `/complete-order`
   even if the UI does not show them.

5. **Replay previously captured requests**
   Take a request from proxy history and resend it when the app is in an unexpected state.

6. **Manipulate parameters**
   Sometimes multiple steps are handled by the **same endpoint** but with different parameters.

Example:
`POST /checkout`

* With param “step=1” → Validate cart
* With param “step=2” → Process payment
* With param “step=3” → Confirm order

If you skip “step=2” and directly send “step=3”,
you might place an order without paying.

---

## **6. Important Clues While Testing**

When you break the sequence, the app may:

* Throw exceptions
* Produce errors about missing variables
* Show debug messages
* Leak stack traces
* Reveal internal logic about state tracking
* Expose back-end assumptions

These errors help you understand how the workflow is structured internally.

---

# **7. SCENARIO (Lab Example)**

**Goal:** Exploit a flawed event sequence in the purchase workflow to buy an expensive item (“Lightweight l33t leather jacket”) without paying.

---

## **Step-by-Step Real Attack**

### **Step 1 — Log in normally**

Use the provided credentials:

```
wiener : peter
```

This gives you access to your account and your store credit.

---

### **Step 2 — Make a normal purchase**

Buy **any cheap item** that your store credit allows.

During this process, Burp Proxy will capture the checkout requests.

---

### **Step 3 — Study the checkout flow**

Look at the requests in your proxy history and identify:

* `POST /cart/checkout`
  This request processes the order.

After sending this, the app **redirects** you to:

* `/cart/order-confirmation?order-confirmed=true`

This is important because this “order-confirmation” endpoint **finalizes** the order.

This is the endpoint the UI expects you to reach **only after** paying.

But once you’ve seen the URL, you can access it **anytime**.

---

### **Step 4 — Send the order confirmation request manually**

Send this request to **Burp Repeater**:

```
GET /cart/order-confirmation?order-confirmed=true
```

This request **completes** the order.

The app incorrectly assumes:

“If someone visits the order-confirmation page, they must have paid.”

This is the flawed assumption.

---

### **Step 5 — Add the expensive jacket to your cart**

Add:
**“Lightweight l33t leather jacket”**

It is more expensive than your current store credit.

Under normal circumstances, you cannot buy it.

---

### **Step 6 — Replay the confirmation request**

In Burp Repeater, resend:

```
GET /cart/order-confirmation?order-confirmed=true
```

This forces the app to finalize the order **without validating payment**
because it incorrectly depends on the **sequence of events**.

The order is completed, and you keep your store credit.

The lab is now solved.

---

# **8. Why the Attack Works**

Because the app makes **an incorrect assumption**:

“Users always reach the confirmation page by following the checkout steps.”

Attackers don’t follow the UI.
They replay the final step directly.

The vulnerable assumptions were:

* The user must have paid before accessing `/order-confirmation`
* Users cannot reach confirmation page unless checkout is complete
* Workflow will always be followed in order
* The backend trusts the frontend to enforce sequence

All of these assumptions are FALSE.

---
---
---

# How to Prevent it

## 1 — Core principle

**The server is the authority for workflow state.**
Never trust the client/UI to enforce the sequence. Every step must be validated server-side before proceeding to the next. Treat workflow progression like a small state machine stored and validated on the server.

---

## 2 — Architectural controls

### 2.1 Maintain an authoritative server-side state machine

* Store per-workflow state in the database (or server session) with explicit states, e.g.:

  ```
  cart_created → checkout_initiated → payment_pending → payment_confirmed → order_finalized
  ```
* Each endpoint must check the current state and only accept transitions that are valid.
* Record timestamps and actor (user/session) for each transition.

**DB schema (example)**

```sql
orders (
  id UUID PRIMARY KEY,
  user_id UUID,
  state TEXT, -- e.g. "cart", "checkout_initiated", "payment_confirmed", "finalized"
  order_token VARCHAR,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  amount_cents INT,
  payment_processed BOOLEAN,
  balance_before INT,
  balance_after INT
)
```

### 2.2 Enforce single responsibility / isolate endpoints

* Design endpoints to have single, well-documented purposes.
* Avoid endpoints that behave differently depending on parameter combinations — split behavior into explicit endpoints for each step.
* Ensure each endpoint verifies preconditions (state, token, authorization).

---

## 3 — Tokens & anti-replay

### 3.1 Use single-use, server-issued tokens between steps

* When step N completes (e.g., `checkout`), generate a cryptographically strong `order_token` (single-use nonce) stored server-side and associated with the order state.
* Require that the confirmation endpoint present this token and mark it used on success.
* Reject attempts with absent, expired, or already-used tokens.

**Token generation (concept)**

* Token = HMAC(secret, order_id || timestamp || random_nonce) or use UUID stored server-side.
* Store `token_status = unused|used|expired` in DB.

### 3.2 Bind tokens to session/user/device

* Token must be tied to the session or user account to prevent token theft abuse.
* Optionally bind to client attributes (IP range, user-agent) for higher assurance — careful with legitimate changes.

---

## 4 — Atomicity & transactional integrity

### 4.1 Perform critical operations in a single DB transaction

* Deduct funds and create the finalized order in the same database transaction. If any sub-operation fails, rollback.
* Use DB transaction isolation levels appropriate to the workload (e.g., `SERIALIZABLE` or `REPEATABLE READ` where necessary) to avoid race conditions.

**Pseudo SQL transaction**

```sql
BEGIN;
SELECT balance FROM users WHERE id = :uid FOR UPDATE;
IF balance < order_amount THEN
  ROLLBACK; return error;
END IF;
UPDATE users SET balance = balance - order_amount WHERE id=:uid;
INSERT INTO orders (...) values (...);
UPDATE orders SET state='finalized' WHERE id=:orderid;
COMMIT;
```

### 4.2 Avoid splitting critical logic across chained requests

* Don’t implement "do A then later do B" where A and B must both succeed but are performed via separate unauthenticated or unaudited endpoints. If unavoidable, use strong coordination tokens and transactional compensations.

---

## 5 — HTTP/REST best practices

### 5.1 Use POST for state-changing actions

* Never finalize or change server state via GET. GET must be safe and idempotent.
* Use POST/PUT with body+CSRF tokens for actions that change state.

### 5.2 CSRF protection

* For browser-initiated flows, use CSRF tokens on state-changing endpoints.
* For APIs, use proper authentication (e.g., Bearer tokens) and CORS restrictions.

### 5.3 Idempotency keys for safe retries

* For operations that may be retried (e.g., network errors), accept a client-provided idempotency key that is checked server-side to prevent duplicate side effects. Still validate state preconditions.

---

## 6 — Validation & authorization checks

### 6.1 Validate preconditions server-side

Before executing a step, check:

* current state matches expected previous state
* token (if any) is present and valid
* user/session is authorized for this order
* resource hasn't changed (cart contents, price, availability)
* user balance/payment method is sufficient

Reject requests that fail any precondition with clear status codes (e.g., `400/403/409` depending on context).

### 6.2 Principle of least privilege

* Only privileged endpoints (admin) can bypass normal workflow; require stronger auth and separate code paths and logging.

---

## 7 — Hardening patterns & additional protections

### 7.1 One-time nonces + expiry

* All single-use tokens must have a short expiry window and be stored server-side as used after consumption.

### 7.2 HMAC / signed payloads for sensitive flows

* Sign payloads/tokens server-side (HMAC) so clients cannot fabricate valid requests. Example: sign order_id + timestamp.

### 7.3 Request fingerprinting (optional)

* Track session, idempotency key, and a fingerprint hash (user agent + partial IP) to make replay from different contexts harder.

### 7.4 Rate limiting + throttling

* Limit how frequently a confirmation endpoint can be invoked per session/order.
* Detect bursts/abnormal patterns.

### 7.5 Input validation & strict schemas

* Validate body schema strictly; reject unexpected parameter combinations that attempt to switch endpoint behavior.

---

## 8 — Logging, monitoring & alerts

### 8.1 Comprehensive logging

* Log all state transitions, token generations/usages, client IP, user id, timestamps, and request payload hashes.
* Log attempts to call confirmation/finalization endpoints that do not meet preconditions.

### 8.2 Alerting rules

* Alert on:

  * confirmation endpoint called with unused balance or without prior payment step
  * tokens used multiple times
  * many failed precondition checks for same user/order
  * unusual order patterns or large volume of free/zero-balance orders

### 8.3 Forensics-friendly logs

* Ensure logs are immutable (append-only), time-synced, and stored off the application server for post-incident analysis.

---

## 9 — Testing & QA

### 9.1 Unit & integration tests

* Unit test server-side state transitions: valid and invalid transitions.
* Integration tests must:

  * attempt step skipping and expect rejection
  * attempt replay of confirmation token and expect single-use failure
  * simulate concurrent order finalization attempts to verify DB locking and atomicity

### 9.2 Automated security tests

* Use tests to replay captured requests in different orders (scripted via test harness) to ensure preconditions are enforced.
* Include tests for token expiry, reused tokens, and missing tokens.

### 9.3 Pen-test & fuzzing

* Fuzz the workflow endpoints with missing params, empty values, repeated calls.
* Include forced browsing attempts and replay attacks in the security test plan.

---

## 10 — Example pseudocode

### 10.1 Server: checkout endpoint (creates order + token)

```python
def post_checkout(user_id, cart):
    # 1. create order draft
    order = create_order(user_id, cart, state='checkout_initiated')
    token = generate_secure_token()
    save_order_token(order.id, token, status='unused', expires_at=now + timedelta(minutes=10))
    return { 'order_id': order.id, 'confirm_token': token }
```

### 10.2 Server: confirmation endpoint (single-use token + atomic finalize)

```python
def post_confirm(order_id, token, user_id):
    order = db.get_order_for_update(order_id)  # SELECT FOR UPDATE
    if order.user_id != user_id:
        return error(403, 'Not authorized')

    token_record = db.get_order_token(order_id, token)
    if not token_record or token_record.status != 'unused' or token_record.expires_at < now:
        return error(400, 'Invalid or expired token')

    if order.state != 'checkout_initiated':
        return error(409, 'Invalid state')

    # atomic transaction: deduct balance and finalize order
    with db.transaction():
        user_balance = db.get_user_balance_for_update(user_id)
        if user_balance < order.amount_cents:
            return error(402, 'Insufficient funds')
        db.update_user_balance(user_id, user_balance - order.amount_cents)
        db.update_order_state(order_id, 'finalized')
        db.mark_token_used(order_id, token)
    return success('Order finalized')
```

Notes:

* `SELECT FOR UPDATE` locks rows to avoid race conditions.
* Token is marked used inside transaction to prevent reuse.

---

## 11 — Operational & deployment considerations

### 11.1 Backwards compatibility & migration

* When introducing state machine or tokenization, plan DB migration and fallbacks.
* Migrate behavior in phases: monitoring mode → strict mode.

### 11.2 Performance

* Token lookups and row locking add overhead — index tokens by order_id; use short token lifetimes.
* Use connection pooling and test under load.

### 11.3 Failure handling & compensation

* If external payment processors are used, implement idempotency and compensating actions if payment succeeds but finalization fails (or vice versa).

---

## 12 — Checklist

* [ ] Server maintains authoritative workflow state for each order/session.
* [ ] Each endpoint enforces precondition checks for expected state.
* [ ] Use single-use, server-stored tokens between critical steps.
* [ ] Finalize actions are POST only; never use GET to change state.
* [ ] Deduct funds and create final order inside a single atomic DB transaction.
* [ ] Implement idempotency keys for safe retries.
* [ ] Reject requests with invalid/missing/expired tokens.
* [ ] Log all state transitions and token usage.
* [ ] Add alerts for token reuse, failed preconditions, and abnormal patterns.
* [ ] Add unit/integration tests that attempt step skipping and replay attacks.
* [ ] Rate limit and fingerprint suspicious activity.
* [ ] Perform periodic pen tests focusing on forced browsing & replay.

