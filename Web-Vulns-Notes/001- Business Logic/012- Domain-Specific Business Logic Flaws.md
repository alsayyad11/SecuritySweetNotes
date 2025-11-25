
## **1. What Are Domain-Specific Business Logic Flaws?**

Business logic flaws occur when the **rules or workflows of an application**—the way it’s supposed to handle core business operations—are implemented incorrectly or make unsafe assumptions.

**Key points:**

* These flaws are **not typical technical bugs** like SQL Injection or XSS. They happen because the **application’s logic does not correctly enforce business rules**.
* They are often **specific to the domain**: e.g., online shopping, banking, loyalty systems, ticketing, social networks, etc.
* They exploit **developer assumptions about user behavior**, such as assuming users will always follow a sequence or never try to reuse a coupon.

**Example:**
An online store offers a 10% discount for orders over $1000.

* Flawed logic: the system only checks the total **when the discount is applied**, not at checkout.
* Exploit: the attacker adds items to reach $1000, applies the discount, then removes items. The system still grants the discount even though the order no longer qualifies.

**Concept:** The flaw stems from assuming users will behave “correctly” and follow the intended workflow.

---

## **2. How These Flaws Happen**

1. **Assuming Sequential Workflow**

   * Processes are designed as if users will always go step by step: add to cart → apply discount → checkout.
   * Flaw occurs when the system doesn’t **validate each step independently**.
   * Attackers can skip steps, repeat steps, or reorder them.

2. **Blind Trust in Client Parameters**

   * Applications rely on **user-supplied data** such as coupon codes, usernames, or gift card IDs.
   * Flaw: trusting these values without server-side validation.

3. **State Mismanagement**

   * Systems track state incorrectly (e.g., a coupon marked as “used” only in the UI).
   * Attackers can replay actions or automate them to exploit repeated use.

4. **Domain Knowledge Requirement**

   * Exploiting these flaws often requires understanding **how the domain works**: pricing rules, shipping limits, user roles, or loyalty systems.
   * Without this knowledge, subtle vulnerabilities may be missed.

---

## **3. Labs Demonstrating Domain-Specific Flaws**

### **Lab A: Flawed Enforcement of Business Rules**

**Scenario:** Coupon codes in an online store can be applied in sequence, but the server does not fully enforce single-use rules.

**Step-by-Step Exploit:**

1. Log in with your account:

   ```
   wiener:peter
   ```
2. Collect coupon codes:

   * `NEWCUST5` is immediately available.
   * `SIGNUP30` is available after signing up for the newsletter.
3. Add the item (leather jacket) to your cart.
4. Apply both coupon codes **alternately**:

   * Applying the same code twice in a row is blocked.
   * Alternating codes bypasses this restriction.
5. Repeat until the order total drops below your store credit.
6. Complete checkout to get the item **without paying the full price**.

**Underlying Flaw:**

* The system assumes users follow the intended sequence and that coupons are applied once.
* Server-side tracking of coupon usage is missing, enabling abuse.

---

### **Lab B: Infinite Money Logic Flaw**

**Scenario:** Combining gift card redemption and coupon usage can be automated to generate unlimited store credit.

**Step-by-Step Exploit:**

1. Log in with your account:

   ```
   wiener:peter
   ```
2. Turn on **Burp Proxy** and turn off intercept.
3. Add a gift card to your cart, apply coupon `SIGNUP30`, and place the order.
4. Receive a code after placing the order, redeem it to increase credit (e.g., $10 including $3 profit).
5. Automate the sequence using **Burp macros**:

   ```
   /cart
   /cart/coupon
   /cart/checkout
   /cart/order-confirmation?order-confirmation=true
   /gift-card
   ```
6. Extract `gift-card` parameters from responses, replay them multiple times.
7. Use **Intruder** to iterate payloads and sessions.
8. Repeat until store credit is enough to buy the jacket.
9. Complete the purchase.

**Underlying Flaw:**

* Server does **not validate gift card usage or total funds atomically**.
* Assumes users perform actions manually and sequentially.
* Automation bypasses these assumptions.

---

## **4. Why Attackers Exploit These Flaws**

1. **Skipping steps:** Bypass intermediate steps assumed by the server.
2. **Repeating steps:** Apply actions multiple times (coupons, gift cards, discounts).
3. **Reordering actions:** Exploit order of operations in workflows.
4. **Parameter manipulation:** Modify client-supplied data.
5. **Automation:** Tools like Burp Repeater, Intruder, and macros allow rapid exploitation.

---

## **5. How to Prevent Domain-Specific Business Logic Flaws**

### **5.1 Server-Side Validation**

* Validate **every action and parameter** on the server.
* Never rely on client-side enforcement or workflow assumptions.

### **5.2 Proper State Management**

* Track coupon usage, gift card redemption, and discounts **server-side**.
* Enforce **single-use restrictions** consistently across sessions.

### **5.3 Final Checkout Validation**

* Recalculate totals, discounts, and credits **at checkout**.
* Validate that all business rules are satisfied in the **final order state**.

### **5.4 Tie Actions to Session/User**

* Avoid trusting user-supplied parameters for identification or privileges.
* Actions like purchases, discounts, or gift card use must be bound to **authenticated users**.

### **5.5 Detect Automation**

* Monitor for unusual sequences or rapid repeated requests.
* Implement **rate-limiting, anti-bot protections**, or challenge-response mechanisms.

### **5.6 Review Business Logic Thoroughly**

* Conduct **code reviews** and **logic walkthroughs**.
* Understand the business domain to identify subtle exploit scenarios.

---

## **6. Summary**

* Business logic flaws exploit **broken assumptions** about workflows, sequences, and parameter trust.
* Examples: coupon reuse, gift card exploitation, skipping steps in purchasing or authentication.
* Prevention requires **server-side validation, session binding, atomic checks, and proper state management**.
* Understanding the **business domain** is essential to detect and fix these vulnerabilities.

---
