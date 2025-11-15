
## **1) What is an Integer Overflow?**

An **Integer Overflow** happens when a numeric value becomes larger than the maximum number that the system’s integer data type can store. Most back-end systems rely on a **32‑bit signed integer**, which has a fixed numeric range:

* **MAX value (highest possible):** 2,147,483,647
* **MIN value (lowest possible):** -2,147,483,648

When a calculation increases a number beyond **MAX**, the value doesn’t throw an error.
Instead, it **wraps around** and jumps to the minimum value.

Example:

```
MAX_INT = 2,147,483,647
MAX_INT + 1 = -2,147,483,648   // overflow
```

This behavior is identical to an odometer rolling past its limit.

This issue becomes dangerous in web applications when the price, quantity, or total amount is stored or calculated using a vulnerable integer type. If the application doesn't validate or restrict user-controlled numeric input, an attacker can purposely force calculations to exceed the integer limit and flip the value from a large positive number into a large negative number.

This leads to severe **Business Logic flaws**, especially in e-commerce workflows.

---

## **2) Why This Creates a Security Vulnerability**

In purchase flows, totals are often calculated like this:

```
total_price = quantity * unit_price
```

If the attacker keeps increasing the quantity and the system does not enforce upper bounds or server-side validation, the total price eventually becomes too large for a 32‑bit int.
When it exceeds **2,147,483,647**, it wraps around to:

**-2,147,483,648**

Therefore:

### You can make the total price negative.

A negative total confuses business logic:

* The system may assume the customer “has credit”
* Or that the total is low enough to allow purchase
* Or accept the order because the final price is between 0 and their store credit

This is exactly the vulnerability exploited in this lab.

---

## **3) Detailed Explanation of What Happened in the Lab**

Now we apply the Integer Overflow concept directly to the lab scenario.

### **The lab statement:**

> This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".
>
> You can log in using: **wiener:peter**
>
> You will need Burp Intruder with **Maximum concurrent requests = 1** for predictable price increments.

---

# **4) Breakdown of the Vulnerability**

### **Step 1 — You try to buy the leather jacket**

* You log in as **wiener**.
* You add the “Lightweight l33t leather jacket” to your cart.
* The order is rejected because your store credit is only **$100**, while the jacket costs **133700 cents** (~$1337).

You capture the:

```
POST /cart
```

request and send it to **Burp Repeater**.

---

### **Step 2 — Detecting lack of validation**

From Repeater you notice:

* The UI only allows 2-digit quantity input
* But the backend **does not** restrict the quantity
* You can submit quantities like 47, 99, 1500, etc.

This is the first sign of missing **server-side validation**.

---

### **Step 3 — Launching an Intruder attack to inflate the total**

You send the request to **Burp Intruder**.

Configuration:

* Set **quantity = 99**
* Payload type: **Null Payloads**
* Payload configuration: **Continue indefinitely**
* Resource Pool → Maximum concurrent requests: **1**

This makes Burp send one request at a time, each adding 99 jackets at a time.

Because each jacket costs **133700**, the total price grows extremely fast.

---

### **Step 4 — Integer Overflow occurs**

While the Intruder attack blasts requests, you refresh your cart repeatedly.

You notice:

* The total price is skyrocketing upward
* Suddenly the total becomes a **large negative integer**

Example:

```
-1,900,000,000
```

This means:

> The total price exceeded **2,147,483,647** and wrapped around to **-2,147,483,648**, the minimum 32-bit signed integer.

This is the **Integer Overflow**.

---

### **Step 5 — Clear the cart and perform a controlled overflow**

Next, you try to manipulate the overflow so the total lands between **$0 and $100**, because that’s the only range your store credit allows.

But mathematically, using only the jacket price (133700 cents), you cannot reach a stable value between 0 and 100 without overflowing again.

So you do a **controlled attack**:

* Recreate the Intruder attack
* Payloads = **exactly 323**
* Again limit concurrency to **1**
* Run the attack

When it completes:

### Add **47 jackets** manually

The new total becomes:

```
-1221.96$
```

This is a negative number but much closer to zero.
This makes the next step possible.

---

### **Step 6 — Fix the negative total by adding another item**

Now the total is:

```
-1221.96$
```

So you add another item (cheaper product) multiple times until the total becomes:

**Greater than 0
AND
Less than your $100 store credit**

For example:

* Total = -1221
* Add an item costing $60 × 20 units = $1200
* New total ≈ $100

Now the cart total is small enough to purchase.

---

### **Step 7 — Place the order**

The system sees:

* total_price = small positive number
* store credit = $100

So it approves the purchase.

You successfully buy the **$1337 leather jacket** using only **$100 credit**, abusing:

### **Integer Overflow → Negative Price → Logic Manipulation**

---

The vulnerability occurred because:

1. The backend stored the price in a **32-bit signed integer**
2. The application did **not validate quantity input**
3. Multiplying quantity × price caused the integer to overflow into negative values
4. The business logic couldn’t handle negative totals
5. You added another item to bring the total into a valid payable range
6. The system accepted the order

This is a combination of:

* **Integer Overflow**
* **Broken Business Logic**
* **Lack of Server-Side Validation**
* **Purchase Workflow Manipulation**


---

# **How to Prevent This Vulnerability**

# **1) Enforce Strict Server‑Side Validation on Quantity**

Client-side controls (HTML limits, JavaScript) mean nothing.
The backend MUST enforce:

### **Allowed quantity range**

Example:

```
1 <= quantity <= 10
```

Or depending on stock:

```
1 <= quantity <= stock_available
```

If the quantity is:

* negative
* zero
* excessively large
* unrealistic for the business

The server must reject it with:

```
400 Bad Request
```

This prevents attackers from sending custom quantities through Burp.

---

# **2) Validate Total Price Before Storing or Using It**

Never trust `quantity * unit_price` as-is.
Before using or saving the calculated total:

### Check that:

* The multiplication **did not overflow**
* The result **is within a safe numeric range**
* The result **is not negative**
* The result makes sense for the business logic

Example safe check in pseudocode:

```php
$maxPrice = 100000000; // your business threshold

if ($quantity <= 0 ||
    $quantity > $stock ||
    $unit_price <= 0) {
    reject("Invalid quantity or price");
}

$total = $quantity * $unit_price;

if ($total < 0 || $total > $maxPrice) {
    reject("Invalid total price");
}
```

---

# **3) Use Safe Integer Types / Arbitrary Precision Types**

Switch away from **32‑bit integers**.

Use:

* **64‑bit integers**
* **BigInteger**
* **Decimal / Money-safe types**

Or dedicated **monetary libraries** that prevent overflow entirely.

This eliminates Integer Overflow at the data layer.

---

# **4) Implement Business Logic Limits**

Even if the math is correct, you still need **business rules**:

### Examples:

* Maximum allowed cart total
* Maximum quantity per item
* Maximum number of cart updates per minute
* Cannot add items that exceed user credit
* Cannot process negative totals
* Cannot process totals that changed too quickly

This protects the purchase workflow from abuse.

---

# **5) Prevent Negative Prices from Being Accepted**

After any calculation, before committing the cart:

```php
if ($total <= 0) {
    reject("Invalid total price");
}
```

This instantly kills the “negative total + flip to positive” trick used in the lab.

---

# **6) Validate After Integer Overflow Can Happen**

Perform **post-calculation verification**, checking that:

* The total is within valid ranges
* No unexpected wrap-around occurred
* No values exceed financial limits

This ensures the overflow never leads to logic confusion.

---

# **7) Log Abnormal Behavior**

If a user sends:

* huge quantities
* repetitive update requests
* negative numbers
* unrealistic values

Generate alerts.
This helps detect exploitation early in real production systems.

---

# **8) Never Trust Client Calculations**

All calculations (unit_price × quantity × tax, etc.) must be done **server-side only**.
Client-side values can be manipulated by:

* Burp
* Intercepting proxy
* Modified browsers
* Custom scripts

The server should **never** accept the total from the client.

---

# **9) Cap the Number of Cart Updates Per Session**

A simple rate-limiter:

```
Max 20 cart updates per minute
```

prevents tools like Intruder from blasting 300+ requests.

This kills the overflow attack vector entirely.

---

# **Practical Example: Secure Logic**

```php
function updateCart($product_id, $quantity) {

    if (!is_int($quantity)) {
        reject("Quantity must be an integer.");
    }

    if ($quantity <= 0) {
        reject("Quantity must be positive.");
    }

    if ($quantity > 10) {
        reject("Quantity too large.");
    }

    $price = getUnitPrice($product_id);

    $total = bcmul($price, $quantity); // big integer safe math

    if ($total <= 0 || $total > MAX_CART_TOTAL) {
        reject("Invalid total price.");
    }

    saveCart($product_id, $quantity, $total);
}
```

---

# **Prevention Steps**

### **To prevent Integer Overflow + price manipulation:**

1. **Server-side validation** of quantity
2. **Reject negative, zero, and unrealistic values**
3. **Use safe numeric types (64-bit / BigInt / Decimal)**
4. **Check for overflow in calculations**
5. **Reject negative totals immediately**
6. **Verify total price stays within business constraints**
7. **Rate-limit cart update requests**
8. **Remove all trust from client-side input**

With these measures combined, the entire vulnerability disappears.

---
