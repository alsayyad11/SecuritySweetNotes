
<img width="100%" height="450" alt="image" src="https://github.com/user-attachments/assets/ee7ef8c5-a8ad-4cdb-b105-c731c182b947" />


# Contents

1. Executive summary
2. Definition & core idea
3. Why BLVs matter — impact and mapping to CIA triad
4. Root causes — how BLVs appear
5. Common categories & detailed examples
6. How to find BLVs — methodology and techniques
7. Safe, non-destructive proof-of-concept (PoC) guidance
8. Detection & monitoring — what to log and alert on
9. Prevention & remediation — design and engineering controls
10. Testing checklist — copyable
11. Reporting template — PoC structure for triage
12. 11 practical lab ideas (safe, educational)
13. Learning path and next steps
14. Glossary & quick reference
15. Appendix — textual flowcharts & example pseudo-code

---

# Executive summary

Business-logic vulnerabilities are flaws in an application’s *intended behavior* — its workflows, rules and assumptions — that let an attacker cause the system to do something harmful while appearing to use normal functionality. They are typically **application-specific**, often invisible to automated scanners, and require **human reasoning** and manual testing. Impact ranges from minor integrity issues to full financial compromise or account takeover. The best defenses are **clear design documentation**, server-side enforcement of business rules, atomic operations for shared resources, and security-focused code reviews and testing.

---

# Definition & core idea

**Business-Logic Vulnerability (BLV)**:
A defect in the design or implementation of application workflows and business rules that permits an attacker to cause an application to behave in ways not intended by the designers — typically by abusing legitimate features rather than bypassing low-level technical controls.

Key properties:

* **Contextual**: Rooted in the application’s business processes.
* **Legitimate surface**: Attacks use normal UI/API features rather than exploits like SQLi/XSS.
* **Manual discovery**: Requires reasoning about workflows, state, and assumptions.
* **Server-side authority**: The server must enforce correctness — otherwise BLVs appear.

> Mental model: BLVs are *policy or process* bugs — think of them as the app doing what the frontend told it to because the backend accepted the frontend’s assumptions.

---

# Why BLVs matter — impact and mapping to CIA triad

Business logic flaws affect the business value protected by the application. Map the typical impacts:

* **Confidentiality (C)**: BLV may allow unauthorized viewing of data (e.g., reading another user’s orders or reports).
* **Integrity (I)**: BLV may let an attacker alter data or transactions (e.g., change account balances, issue refunds, change passwords).
* **Availability (A)**: BLV may disrupt services or legitimate processes (e.g., cancel critical jobs, exhaust quotas).

Concrete impact types:

* Financial loss (free goods, refunds, fraud)
* Account takeover or privilege escalation
* Data exposure or tampering
* Regulatory & reputational harm
* Business process disruption

Severity is contextual — the same flaw is critical in banking and minor in a low-value demo app.

---

# Root causes — how BLVs are introduced

Typical engineering issues that lead to BLVs:

1. **Client-side / parameter trust**
   Decision logic or authority inferred from client parameters (e.g., `isAdmin=true` or presence/absence of a field).

2. **Assumed request ordering (sequence assumptions)**
   Backend assumes UI enforces ordering; server does not validate the current object state.

3. **Incomplete validation of business parameters**
   Missing checks for sign, range, currency, or semantically invalid values (e.g., negative transfer amount).

4. **Non-atomic operations / race windows**
   Shared resources (inventory, balance) modified without transactional or concurrency control.

5. **Token misuse or missing binding**
   One-time tokens reused or not bound to user/context.

6. **Insufficient role/permission enforcement**
   Role checks done via mutable client data rather than server session or claims.

7. **Lack of design documentation & threat modeling**
   Assumptions not recorded; code reviewers miss edge logic because flows are poorly documented.

8. **Feature complexity / edge case explosion**
   More workflows and features make complete coverage harder; corner cases are missed.

---

# Common categories & examples

Below are canonical categories, with clear, conceptual examples and recommended defenses. These examples are **descriptive** and **non-destructive**.

---

## Category A — Authorization / role logic flaws

**Concept:** Backend decides privilege from request data (parameters or missing fields) instead of verifying session identity and server-side roles.

**Example (password change):**

* UI: regular users provide `existing_password`; admins use a form *without* `existing_password`.
* Vulnerable backend: if `existing_password` is empty → assume admin → proceed.
* Attack concept: an authenticated regular user submits a change with `existing_password` empty and supplies a `username` to change — server accepts and changes that user’s password.
* Impact: account takeover across users.
* Fix: derive actor role from server session (session token, JWT claims) and require per-role checks (admins permitted to change other users’ passwords; non-admins must prove ownership).

**Safe pseudo-fix:**

```python
if session.user.role == 'admin':
    change_password(target_user, new_pass)
elif session.user.username == target_user:
    if verify_password(session.user, existing_password):
        change_password(target_user, new_pass)
else:
    deny()
```

---

## Category B — Sequence / workflow bypass (step skipping)

**Concept:** Server assumes the client progress sequence enforced by the UI; attacker reorders or skips requests.

**Example (checkout bypass):**

* Normal flow: Add to cart → Finalize order → Payment → Delivery info.
* Vulnerability: server trusts that if the client submits delivery info, payment has been processed. It does not verify `order.status == PAID`.
* Attack concept: send delivery step request without performing payment step — order is accepted and fulfilled.
* Impact: direct revenue loss.
* Fix: validate preconditions at each step (e.g., `if order.status != 'PAID' -> reject fulfillment`).

**Textual FSM (valid):**

```
CART -> FINALIZED -> PAID -> FULFILLED
```

**Server must enforce transitions.**

---

## Category C — Business parameter manipulation (semantic validation)

**Concept:** Input values are validated syntactically but not semantically (e.g., negative numbers accepted where only positive values make sense).

**Example (negative transfer bypass):**

* Intended rule: transfers > $10,000 require manager approval.
* Vulnerable code: `if amount <= threshold: auto_approve()` (and nowhere checks for sign).
* Attack concept: submit `amount = -20000` to invert logic and bypass approval or manipulate balances.
* Impact: monetary manipulation, eventual fraud or integrity loss.
* Fix: canonicalize and validate domain semantics (e.g., `if amount <= 0 -> reject` and ensure `amount` represents debit from source).

---

## Category D — Promotion / discount manipulation (cart composition changes)

**Concept:** Promotion eligibility calculated at one point but not rechecked at payment; eligibility can be revoked by altering cart contents after discount application.

**Example (bulk discount removal):**

* Flow: add qualifying product → discount applied to whole cart → remove qualifying product → checkout at discount.
* Vulnerability: discount flag remains valid or stored in order even if qualifying item removed before payment.
* Attack concept: buy non-qualifying items at discounted price without buying the qualifying one.
* Fix: recompute eligibility and discount at **payment** time; bind discount to the qualifying items or to the final purchased basket.

---

## Category E — Race conditions (concurrency issues)

**Concept:** Concurrent requests manipulate a shared resource (inventory, balance) without atomicity, leading to inconsistent states.

**Example (last item sale):**

* Two clients simultaneously submit checkout for the last unit. Inventory check passes for both because decrement happens later or without locking. Both orders accepted.
* Impact: oversell, customer service issues, potential fraud.
* Fix: atomic update pattern (transactional decrement), optimistic concurrency with version checks, row locking, or queueing.

---

## Category F — Token / state reuse

**Concept:** Tokens intended for one-time use (reset tokens, promo tokens) are not marked consumed or not bound to specific context.

**Example (reset token reuse):**

* Reset token can be used multiple times or for multiple users because it's not bound to user / order id.
* Impact: repeated unauthorized actions or attackers reusing tokens for other targets.
* Fix: bind tokens to user/object, mark consumed atomically, set short expirations.

---

## Category G — Incomplete audit & admin protections

**Concept:** Admin APIs are reachable from client surface or sensitive parameters are modifiable by any user.

**Example:** admin actions accept `target_user_id` in the body and only check that the request is authenticated — not that the caller is admin.

* Impact: privilege escalation.
* Fix: server must verify caller role and require secure admin channels (MFA, IP allowlists) and robust audit logging.

---

# How to find BLVs — methodology and techniques

Finding BLVs is a human-driven process. Below is a repeatable methodology followed by specific techniques.

## Phases

1. **Recon & mapping (required)**

   * Map every user journey and business flow: signup, login, password reset, purchase, refund, transfer, subscription, admin tasks.
   * Identify assets: money, credits, items, roles, tokens, sensitive records.
   * Note trust boundaries: where client input crosses server logic or external services.

2. **Threat modeling & hypothesis generation**

   * For each flow, ask: what assumptions were made? (ordering, identity, ranges, uniqueness)
   * Create specific hypotheses to test (e.g., "If discount application is stored server-side but not rechecked, removing the trigger item will still grant discount").

3. **Manual testing & sequence fuzzing**

   * Reorder steps, skip steps, re-invoke steps, modify parameters.
   * Replay tokens, reuse or alter IDs.
   * Tamper with request headers and body (role IDs, flags).
   * Try negative/edge values and extreme values (0, -1, huge number).

4. **Concurrent testing (lab only)**

   * Simulate simultaneous requests to operations modifying shared state (inventory, balance). Use small scripts to send concurrent requests in an isolated environment.

5. **Code review (if available)**

   * Inspect logic for authorization, state machine enforcement, token lifecycle, and parameter handling. This is fastest path to BLVs.

6. **Confirm & craft safe PoC**

   * Demonstrate the issue non-destructively (see PoC guidance below).

## Tools & aids (do not rely solely on them)

* **Proxy:** Burp Suite, OWASP ZAP for intercepting and editing requests.
* **API clients:** Postman, HTTPie for controlled calls.
* **Scripting:** small scripts (Python/Go) for concurrency testing in labs.
* **Local vulnerable apps / labs:** Juice Shop, Web Security Academy labs, intentionally vulnerable microservices.
* **Static analysis:** for code availability.
* **Unit/integration test harnesses:** to encode invariants.

> **Important:** Automated scanners are largely ineffective at BLVs because these require contextual reasoning. BLV testing is manual work.

---

# POC

When you find a BLV, construct a PoC that proves the vulnerability without causing harm.

## Goals of a responsible PoC

* **Prove feasibility** without causing production damage or financial loss.
* **Record evidence** (requests/responses, screenshots) sufficient for triage.
* **Explain the exploit path and impact** clearly and quantitatively where possible.
* **Provide remediation suggestions** and suggested tests.

## PoC structure 

1. **Title** — short, descriptive.
2. **Overview** — one paragraph summary with impact.
3. **Preconditions** — accounts/roles/test data needed.
4. **Safe reproduction steps** — stop before any destructive final operation (e.g., show that an order reaches `FULFILLMENT_PENDING` without `PAID` instead of triggering fulfillment). Use test or staging accounts.
5. **Evidence** — full HTTP request & response pairs (redact PII), screenshots of state, server responses showing the missing checks.
6. **Impact assessment** — explain what an attacker *could* do if destructive testing were used, including business consequences.
7. **Root cause** — brief technical explanation.
8. **Remediation** — exact code/design changes and suggested tests.
9. **Mitigation / temporary controls** — rate limits, feature toggles, manual checks.
10. **Appendix** — logs, timestamps, and test account credentials (if allowed by program scope).

## Example (non-destructive) — checkout bypass PoC (high level)

* Preconditions: test user, cart with items; staging environment.
* Steps:

  1. `POST /orders/finalize` → record `order_id`.
  2. *Do not* perform payment.
  3. `POST /orders/{order_id}/delivery` (supply delivery data).
  4. Observe server response showing `order.status` moved to `FULFILLMENT` or `DELIVERY_SCHEDULED`.
* Evidence: show the `finalize` response and `delivery` response; show that `payment` status remained `UNPAID`.
* Avoid making actual shipments, refunds, or payments. Stop at observable server state change.

**Always follow the program’s rules and get explicit permission if testing production.**

---

# Detection & monitoring — what to log and alert on

Design detection around business events and invariants. These are the critical signals:

## Logging suggestions

* **State transitions**: log (actor id, request id, previous state, next state, timestamp).
* **Business parameters**: log important values (amounts, discounts applied, token IDs).
* **Token lifecycle**: creation, consumption, reuse attempts, expiry events.
* **Admin actions**: who performed action, target, reason, and time.
* **Concurrent access patterns**: multiple simultaneous requests touching same resource.

## Alerts & anomaly rules

* **Sequence anomalies**: operations occurring out of expected order (e.g., `FULFILLMENT` without `PAID`).
* **High frequency of value-sensitive events**: many refunds, coupon uses, or failed password resets from same IP.
* **Token reuse attempts**: same token used more than once.
* **Concurrent checkout attempts on same inventory item**: repeated successes for last item.
* **Negative or abnormal parameter submissions**: negative amounts where only positives expected.

## Monitoring approach

* Implement **business-metric monitoring** (numbers of refunds, discount redemptions) and alert on abnormal changes.
* Use **suspicious sequence detection**: maintain a finite sliding window of recent API calls per session to detect unusual flows.
* Keep **audit trails** with immutable logs for incident investigation.

---

# Prevention & remediation — design and engineering controls

Prevention requires both design discipline and engineering enforcement. The following is a prioritized list:

## 1. Server-side enforcement of business rules (mandatory)

* Recompute any critical value server-side (price, tax, discount total). Never trust client-computed totals.
* Validate state preconditions before accepting actions (e.g., `if order.status != 'PAID' -> reject FULFILLMENT`).
* Authorize every sensitive operation using server-controlled identity/roles.

## 2. Explicit workflow modeling

* **Design state machines (FSMs)** for major objects: orders, transfers, promotions. Define allowed transitions and enforce them in code.

## 3. Token & session best practices

* Bind tokens to user and context. Mark tokens consumed in an atomic operation.
* Use short expirations for sensitive tokens and log consumption.

## 4. Atomicity & concurrency control

* Use transactions/row locks or optimistic concurrency to prevent race conditions on shared resources.
* Employ version or sequence numbers for critical updates (`UPDATE ... WHERE version = X`).

## 5. Input canonicalization & semantic validation

* Normalize amounts (sign, scale), validate ranges, and reject semantically invalid values (e.g., negative transfer amounts).
* Verify currency and conversion correctness at server side.

## 6. Least privilege & admin controls

* Do not expose admin-level parameters to frontend payloads.
* Require additional authentication/authorization steps for high-impact admin operations (MFA, separate admin interfaces, approval processes).

## 7. Testing & CI integration

* Add unit and integration tests that assert business invariants and forbidden transitions.
* Include sequence fuzzing and negative tests in CI.
* Implement regression tests whenever a change touches business logic.

## 8. Documentation & code clarity

* Document design assumptions and expected flows.
* Require in-code comments for tricky assumptions and boundaries.
* Perform security-focused design reviews and threat modeling during feature design.

## 9. Operational controls (short-term mitigation)

* Rate limiting on sensitive operations, temporary feature toggles to disable risky flows, analytics alerts for suspected abuse patterns.

---

# Testing checklist — copyable

Use this checklist during manual assessments and code reviews:

* [ ] Enumerate all user flows and assets (orders, balances, tokens).
* [ ] For each flow, list expected state transitions & preconditions.
* [ ] Verify server recomputes client-visible critical values (price/tax/discount).
* [ ] Attempt to reorder/skip flow steps and observe server response.
* [ ] Test parameter tampering (quantities, price, discount IDs, sign).
* [ ] Test negative/edge values (0, -1, huge).
* [ ] Test token binding and single-use semantics.
* [ ] Test role enforcement using server identity (not client flags).
* [ ] Test concurrent requests on shared resources in a lab.
* [ ] Verify audit logging for sensitive transitions and admin actions.
* [ ] Check that admin APIs require appropriate privileges and are not reachable from normal clients.
* [ ] Ensure CI contains tests for business invariants and disallowed transitions.

---

# Reporting template — PoC structure for triage

Use this structure when filing a bug or bounty report:

```
Title: [Business-Logic] Short description (e.g., Order fulfilled without payment)

1. Overview
   - Short summary + business impact

2. Affected components
   - Endpoint(s), roles, environment versions

3. Preconditions
   - Accounts, test data, required state

4. Safe Steps to Reproduce (PoC)
   - Step 1: ...
   - Step 2: ...
   - *Stop before destructive final action*

5. Observed behavior
   - Request/Response pairs (redacted)
   - State change evidence

6. Expected behavior
   - What should have happened

7. Impact
   - CIA mapping, business consequence estimate

8. Root cause
   - Short technical explanation (e.g., server infers admin from missing param)

9. Fix recommendation
   - Exact code/design changes and tests

10. Mitigation / Workaround
    - Short term controls

11. Appendix
    - Logs, timestamps, screenshots, sample payloads
```
---

# Learning next step

1. **Read & practice**: Web Security Academy BLV module, Web Application Hacker’s Handbook (attacking application logic chapter).
2. **Build & break**: create simple apps that implement vulnerable flows, then fix them.
3. **Practice on labs**: use the 11 lab ideas above.
4. **Code & test**: add business invariant tests into CI for your projects.
5. **Review & document**: mandate design docs and threat models per feature.
6. **Peer review**: perform security-focused code reviews, not only static analysis.

---

# Glossary & quick reference

* **FSM (Finite State Machine)**: A model of allowed states and transitions for objects like orders.
* **Token binding**: Associating a token to a specific user/context/object.
* **Canonicalization**: Normalizing input values (e.g., sign, formatting) before validation.
* **Atomicity**: Operation completes fully or not at all; necessary for safe updates.
* **Business invariant**: A rule that must always hold true (e.g., `order.payment_amount == server_calculated_total`).

---

# Appendix — textual flowcharts & example pseudo-code

## Flowchart: Secure order lifecycle (text)

```
[ CART ] -> [ FINALIZED ] -> [ PAYMENT_PROCESSING ] -> [ PAID ] -> [ FULFILLMENT ] -> [ DELIVERED ]
                 ^                 |
                 |                 v
              (cannot skip)     (verify PAID)
```

## Vulnerable pseudo-code (password change — vulnerable)

```python
# VULNERABLE (do not use)
existing = request.params.get('existing_password')
if not existing:
    # assume admin — unsafe!
    change_password(request.params['username'], request.params['new_password'])
else:
    if verify_password(request.params['username'], existing):
        change_password(request.params['username'], request.params['new_password'])
```

## Secure pseudo-code (password change)

```python
# SECURE
actor = session.user
target = request.params['username']
if actor.role == 'admin':
    change_password(target, request.params['new_password'])
elif actor.username == target:
    if verify_password(actor, request.params['existing_password']):
        change_password(target, request.params['new_password'])
    else:
        deny()
else:
    deny()
```

## Atomic decrement pattern (inventory)

```sql
-- optimistic concurrency
UPDATE inventory
SET stock = stock - 1, version = version + 1
WHERE product_id = ? AND stock > 0 AND version = ?
```

If rows_affected == 0 -> retry or fail.

---

## To know more about Business Logic Vulnerabilities , Go to : 
[PortSwigger stduy guide for Business logic](https://portswigger.net/web-security/logic-flaws)
