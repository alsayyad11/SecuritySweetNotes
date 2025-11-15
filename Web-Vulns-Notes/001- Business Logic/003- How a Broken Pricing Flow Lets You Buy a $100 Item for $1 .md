
One of the most common mistakes in web application development is **trusting client-side controls too much**. This happens when developers assume that users will only interact with the application through the normal front-end interface, and that all client-side validation is enough to enforce rules and prevent manipulation.

**Why is this dangerous?**
Client-side validation, like HTML input checks, JavaScript form rules, or frontend restrictions, is **not a security mechanism**. It only helps with **user experience (UX)** by preventing obvious mistakes like empty fields, invalid email formats, or numbers out of range. However, attackers don’t have to follow the "normal" way of interacting with your application. They can bypass these controls entirely using simple tools like **Burp Suite**, or by sending requests directly to the server.

When an application blindly trusts data from the client-side, **any input coming from the client can be tampered with**. If the server doesn’t perform proper validation and integrity checks, an attacker can manipulate critical data like prices, quantities, or permissions, leading to **business logic vulnerabilities**, unintended actions, and potentially severe consequences for the application and the business.

---

### How This Happens

1. **Assumption About User Behavior:**
   Developers often assume that users will interact with the web app only through the intended interface. For example, they might make the price of a product “read-only” on the frontend and rely on that to prevent price changes.

2. **No Server-Side Validation:**
   The server simply accepts whatever values the client sends, without verifying them. This is where the problem escalates. If the price, quantity, or other critical parameters are fetched directly from the client request, they can be manipulated to bypass rules like store credit limits, discounts, or workflow steps.

3. **Resulting Vulnerabilities:**
   This leads to **logic flaws**, because the server executes actions it shouldn’t, thinking the data is valid. The attacker can then manipulate transactions, change prices, or perform operations they shouldn’t have access to, all without needing any complex exploit.

---

### Real-World Example (Lab Scenario)

Let’s take a concrete example from a vulnerable e-commerce lab:

1. **Initial Situation:**
   You are logged in with $100 of store credit. You attempt to buy a **leather jacket** priced at $1337. Naturally, the order is **rejected** because your credit is insufficient.

2. **Analyzing Requests with Burp:**

   * Open **Burp Suite** and start intercepting your browser traffic.
   * Go to **Proxy → HTTP history** and examine the request that adds the jacket to your cart.
   * Notice that the **POST /cart** request contains a parameter for the product price.

3. **Manipulating the Price:**

   * Send the **POST /cart** request to **Burp Repeater**.
   * Modify the **price parameter** from `$100` (or the original price) to `$1`.
   * Send the modified request.
   * Refresh your cart page to confirm that the price has now changed to `$1` based on your input.

4. **Completing the Order:**

   * Since the manipulated price is now below your available store credit, you can proceed to **complete the purchase** successfully.
   * This demonstrates that the server was blindly trusting the client-side data, allowing you to bypass the intended business logic.

---

**Mitigation Example:**
Instead of relying on the client to send the price, the server should fetch the price using the **product ID** from the database and calculate totals internally. That way, even if the user tampers with requests, the server-side logic ensures that invalid prices cannot be processed.
