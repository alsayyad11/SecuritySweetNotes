## **1.1 What Is a State Machine in Authentication Flows?**

A **state machine** is the internal logic that defines what sequence of steps a user must follow in order to complete a process — for example, login → role selection → homepage.

Each step represents a **state**, and the application expects users to move through these states in a fixed order.

Example intended flow:

```
POST /login  →  GET /role-selector  →  GET /home
```

The application assumes:

* You cannot access `/role-selector` before logging in.
* You cannot access `/home` before selecting a role.
* Your role is only known after completing the proper step.

**BUT if the application does not enforce these assumptions on the server side**, then the flow becomes vulnerable.

---

## **1.2 How the Vulnerability Happens**

A flawed state machine happens when:

1. The **server trusts the client** to follow the UI sequence.
2. The application **stores temporary state in session/cookies** without verifying it is set correctly.
3. The server **does not verify that required steps were actually completed** before allowing access to protected resources.

So if an attacker **skips a step**, the application may:

* Assign **default values**,
* Leave uninitialized variables,
* Or accidentally authorize the user with **more privileges**.

In this lab, if the attacker **skips the role-selection step**, the app sets a **default role = admin**.

This is a textbook example of:

* Missing precondition validation,
* Faulty workflow enforcement,
* And failure to validate critical authentication state.

---

## **1.3 Why This Is Dangerous**

Because attackers can:

* Skip authentication steps
* Replay login requests out of order
* Force application into an unexpected state
* Abuse uninitialized or default values
* Get elevated privileges accidentally (admin)

---

## **1.4 How Attackers Exploit It**

Attackers use tools like **Burp Proxy + Repeater** to:

1. Capture the entire login workflow.
2. Identify which requests are mandatory and which can be skipped.
3. Manipulate the sequence:

   * Drop certain requests,
   * Replay others,
   * Submit them in a new order,
   * Or access protected pages before the app expects them.

If the backend does not strictly verify each state transition, attackers can bypass authentication completely.

---

## **1.5 What Proper Prevention Should Look Like**

To prevent this vulnerability:

### **A. Enforce Server-Side State Validation**

Every request to a protected endpoint must check:

* Is the user logged in?
* Has the user completed previous steps?
* Is the workflow state valid?
* Is the role actually set by a legitimate step?

No step should rely only on front-end redirects.

---

### **B. Do Not Rely on Default Values**

* Never assign a **default role**, especially not admin.
* Always explicitly set authenticated state only after validating the correct process.

---

### **C. Use a Strict Authentication State Machine**

Each stage must specify allowed next states.

Example:

| Step           | Allowed Next Step  |
| -------------- | ------------------ |
| login_done     | role_selection     |
| role_selection | homepage           |
| homepage       | (normal operation) |

Blocked if user tries:

* login_done → homepage
* login_done → /admin
* role_selection → /admin
  without proper authorization.

---

### **D. Bind Privileges to Verified Server Events**

Role must be set **only** when:

* A server-validated form is submitted,
* With CSRF protection,
* And the user session is authenticated.

Never rely on:

* Query parameters
* Cookies created client-side
* Assumptions about UI flow

---

### **E. Use Defensive Logging**

Log:

* Unexpected state transitions
* Missing prerequisites
* Suspicious skipping behavior

---

### **F. Consistent Access Control**

Even if role is selected correctly:

* `/admin` should always check `role == admin`
* Never trust session defaults

---

# **2. Example — Lab Walkthrough **

Now here is the lab scenario fully explained as an application of the above concept.

---

## **2.1 What the Lab Is Doing Wrong**

The login process is:

```
1. User logs in
2. User selects a role
3. User reaches the homepage
```

BUT the server assumes:

* The user *will always* visit `/role-selector`
* The server does NOT verify that the role was manually chosen
* If a role is not selected, the server falls back to **default role = admin**

This is the exact definition of a flawed state machine.

---

## **2.2 Attack Plan**

We will:

1. Log in normally
2. Intercept the request that loads the role selector
3. DROP it
4. Visit the homepage manually
5. Observe that we are now **admin**
6. Access the admin panel
7. Delete carlos

---

## **2.3 Full Breakdown**

### **Step 1 — Log In Normally**

In Burp with intercept ON, submit:

```
POST /login
```

Forward this request.

This is correct and needed because:

* The server sets the authenticated session here.
* We need a valid session cookie.

---

### **Step 2 — The App Sends You to /role-selector**

Burp captures:

```
GET /role-selector
```

This is the critical request.

If we **complete** this, the server will wait for us to choose a role.

If we **skip** it, the server will NOT initialize the role properly.

Because the app has flawed logic, skipping it causes:

```
role = admin (default)
```

---

### **Step 3 — Drop GET /role-selector**

In Burp:

* When `GET /role-selector` appears
* DROP the request instead of forwarding it.

Now the server thinks:

* User is logged in,
* But no role was selected,
* So fallback role = admin.

---

### **Step 4 — Manually Browse to Home Page**

In your browser, visit:

```
/home
```

Observe:

* You are logged in
* Your role is "administrator"
* The admin panel link is visible

---

### **Step 5 — Access /admin**

Now `/admin` works because:

* The session’s role variable was never set properly
* The default admin value was applied

---

### **Step 6 — Delete carlos**

Using the admin interface, delete the user **carlos** and solve the lab.

---
# How to prevent authentication bypass caused by a flawed state machine 

**The server is the single source of truth for workflow state.**
Never accept “I did step X” as true because the client says so. Every endpoint must validate preconditions server-side before executing sensitive actions or granting privileges.

---

## prevention summary

1. **Keep an authoritative server-side state machine** for login/workflow state.
2. **Never assign insecure defaults** (e.g., `role = admin`) when state is missing.
3. **Bind session and role assignment to an explicit, server-validated event** (use single-use tokens, CSRF, and server session flags).
4. **Always enforce authorization checks** on privileged endpoints (`/admin`) regardless of prior steps.
5. **Log and alert** unexpected or out-of-sequence state transitions.

---

## Detailed controls and implementation patterns

### 1 — Authoritative server-side state machine

* Store per-session or per-workflow state server-side (DB or server session), not in hidden form fields or client cookies.
* Model explicit states. Example for login+role selection:

  ```
  states: UNAUTHENTICATED → AUTHENTICATED_NO_ROLE → ROLE_SELECTED → AUTHORIZED
  ```
* Only allow transitions defined by the state machine. Reject any request that attempts an invalid transition.

**Database example (orders/users state):**

```sql
users {
  id,
  username,
  auth_state,         -- e.g., 'none', 'logged_in_no_role', 'role_selected'
  selected_role,      -- null or 'user'|'admin'
  last_state_change TIMESTAMP
}
```

### 2 — No insecure defaults

* Never default to a privileged role. If a required state/field is missing, deny access and require explicit completion.
* Fallback policy: *deny until explicitly authorized*.

### 3 — Make role selection an explicit, server-validated action

* When user picks a role, perform a server POST that:

  * validates the CSRF token
  * verifies the session is authenticated
  * writes `selected_role` into server session/DB
  * issues a one-time audit entry (who changed role, when, from what IP)
* Only after this server action should `/home` or `/admin` honor the role.

### 4 — Enforce authorization on every privileged endpoint

* On `/admin` and other sensitive endpoints, always perform:

  * `is_authenticated()` check
  * `session.selected_role == 'admin'` verification (server side)
  * additional RBAC policy checks (permissions matrix)
* Do **not** assume that a prior redirect or page access implied authorization.

### 5 — Use single-use tokens / explicit confirmation for role elevation

* If role selection elevates privileges, require a server-issued, single-use token to be presented to finalize elevation.
* The token should be:

  * generated server side and stored with `status = unused`
  * tied to the session/user
  * marked used inside the same server transaction that sets the role

### 6 — CSRF, POST only, and idempotency

* Role selection and authentication steps that change server state must be **POST** requests protected by CSRF tokens (or strong API auth for non-browser clients).
* Avoid changing auth state on GETs.
* Use idempotency keys if retries are possible; still validate preconditions.

### 7 — Atomic operations and transactionality

* When changing sensitive state (e.g., assign role and record audit), do it in one transaction so partial state cannot be observed or exploited.
* Example: assign role + mark token used + write audit log in a single DB transaction.

### 8 — Validate session integrity and binding

* Ensure session cookie is the only authoritative identity; don’t accept identity data from request body.
* Bind role/session to server session id and optionally to other metadata (e.g., session creation timestamp) to detect replay.

### 9 — Defensive logging and alerting

* Log every unexpected state or missing precondition attempt (e.g., access to `/admin` while `auth_state != ROLE_SELECTED`).
* Alert on patterns:

  * repeated requests that attempt to skip role selection
  * role assignment without explicit confirmation
  * defaulting to a privileged value due to missing state

### 10 — Fail closed and fail safe

* On any ambiguity (missing state, expired token, inconsistent session), deny access and require re-authentication.

---

## Concrete code patterns

### Example: Express.js middleware (Node) — enforce role selection

```js
// middleware/ensureRoleSelected.js
module.exports = function ensureRoleSelected(requiredRole) {
  return function (req, res, next) {
    if (!req.session || !req.session.userId) {
      return res.status(401).send('Authentication required');
    }
    // server-side authoritative role
    const role = req.session.selectedRole;
    if (!role) {
      return res.status(403).send('Role not selected');
    }
    if (requiredRole && role !== requiredRole) {
      return res.status(403).send('Insufficient privileges');
    }
    return next();
  }
}
```

Use it on admin routes:

```js
app.use('/admin', ensureRoleSelected('admin'), adminRouter);
```

### Example: Role selection endpoint (Express pseudocode)

```js
app.post('/role/select', csrfProtection, async (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.status(401).end();
  const desiredRole = req.body.role;
  // validate allowed roles for this user
  if (!isRoleAllowedForUser(userId, desiredRole)) return res.status(403).end();

  // Use transaction to set role + audit
  await db.transaction(async (trx) => {
    await trx('users').where({id: userId}).update({selected_role: desiredRole, auth_state: 'ROLE_SELECTED'});
    await trx('audit_logs').insert({user_id: userId, action: 'role_selected', details: desiredRole, ts: new Date()});
  });

  res.json({status: 'ok'});
});
```

### Django example: view protection

```python
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden

@login_required
def admin_view(request):
    if request.session.get('selected_role') != 'admin':
        return HttpResponseForbidden("Admin role required")
    # normal admin processing
```

---

## Testing requirements (unit, integration, security tests)

### Unit / integration tests (must be automated)

* Test transitions:

  * Attempt direct access `/admin` when `selected_role` is missing → expect 403.
  * Attempt role assignment without session → expect 401.
  * Ensure valid role selection sets server session and allows subsequent privileged access.
* Test replay and forced browsing:

  * Capture role selection flow; replay with missing intermediate request and assert denial.
* Test token single-use:

  * Use confirmation token twice → second attempt must fail.

### Security test cases (pen test checklist)

* Attempt to skip `GET /role-selector` and access `/home` or `/admin`.
* Drop role-selection request in proxy and observe the session.
* Try changing `selected_role` in client session store (if possible) — server must ignore.
* Force browse `/admin` endpoints, POSTs and GETs, and verify server rejects all unauthorized attempts.

---

## Monitoring & detection

* Create alerts for:

  * `403` spikes on role selection endpoints
  * `admin` accesses where `selected_role` was set within last N seconds without token/audit
  * Unexpected defaulting behavior logged
* Monitor audit logs for:

  * role selection events, token issuance/consumption, and admin privilege grants
* Retain logs with adequate retention and tamper protection for post-incident analysis

---

## Deployment and operational considerations

* If you introduce a state machine or tokens, roll out in phases:

  1. Instrument: log precondition failures without blocking (monitoring mode).
  2. Block invalid transitions after monitoring window.
* Test performance: session/state checks add DB reads — use caching carefully (but do not cache stale permission state).
* Migration: ensure legacy sessions are revalidated on next auth event to prevent undefined `selected_role` values.

---

##  checklist

* [ ] Store authoritative auth/workflow state server-side (DB/session).
* [ ] No default privileged role; deny on missing/invalid state.
* [ ] Role selection requires server POST + CSRF + server validation.
* [ ] `/admin` and privileged endpoints always check server session role and permissions.
* [ ] Use one-time/short-lived tokens for role elevation if applicable.
* [ ] Perform role assignment in atomic transactions with audit logging.
* [ ] Put automated tests that attempt step skipping & replay in CI.
* [ ] Log unusual state transitions and alert.
* [ ] Fail closed on ambiguous state.
* [ ] Phase rollout for state machine changes; validate in production with monitoring.

---

# **3. Summary**

**Concept:**
Authentication bypass happens when the application does not enforce the required sequence of steps in the login workflow.
If skipping a step leads to uninitialized/default values (like default admin), attackers can escalate privileges.

**Cause:**
Flawed state machine + missing validation + bad default values.

**Exploit:**
Skip `/role-selector` → default admin → access `/admin`.

**Fix:**
Strict server-side state validation, no default roles, enforce transitions, always validate preconditions.

---
