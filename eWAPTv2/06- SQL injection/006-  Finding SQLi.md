
When trying to exploit a SQL Injection vulnerability, the very first step is **finding a valid injection point** inside the web application. Once you identify that point, you can then craft a malicious **SQL payload** that will be injected into the vulnerable parameter.

Think of it as a door with a loose lock: before you can break in, you need to know which door is weak enough to target.

---

## Step 1: Probing with Special Characters

The most straightforward way to discover SQL Injection is by testing inputs with **special characters** that often break SQL syntax. For example:

* `'` (single quote)
* `"` (double quote)
* `--` (SQL comment)
* `;` (end of statement)

If the application is vulnerable, these characters can cause the SQL query running in the background to become **invalid**, forcing the web app to throw an error message like:

```
You have an error in your SQL syntax...
```

This is a strong indicator that the input you provided is being executed inside an SQL query.

 **Example:**

* Imagine a login form where you enter `test'`.
* If the page shows an SQL error instead of a normal "invalid username/password" message, that’s a sign of SQL injection.

---

## Step 2: Not All Inputs Are Equal

It’s important to remember that **not every input** inside a web app is connected to a database. For instance, a color picker for themes might never interact with SQL. That’s why it’s smart to do **reconnaissance** first: map out the application, categorize all inputs, and prioritize the ones most likely linked to the backend database.

---

## Common Injectable Fields

SQL Injection can appear in many parts of an application. Here are some of the most **common targets**:

### 1. Login Forms

Login pages are classic targets. Attackers often manipulate the **username** or **password** fields to bypass authentication.

* If input is not sanitized, the attacker can inject code like:

  ```
  admin' OR '1'='1
  ```

  This tricks the query into always returning true.

 **Example:**
A query like:

```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'xyz';
```

would log the attacker in without needing the real password.

---

### 2. Search Boxes

Search fields often build dynamic queries. If the input goes directly into SQL without validation, an attacker can inject malicious payloads.

 **Example:**
Searching for:

```
test' UNION SELECT username, password FROM users--
```

could reveal sensitive data if the application is vulnerable.

---

### 3. URL Parameters

Applications often pass data between pages via query strings, like:

```
http://site.com/products?id=5
```

If the `id` parameter is directly placed into SQL without filtering, it can be exploited.
 **Example:**

```
http://site.com/products?id=5 OR 1=1
```

might return all products instead of just one.

---

### 4. Form Fields (Registration, Contact, Comments)

Any input form is a potential target. Attackers can insert SQL payloads into text boxes or comment sections if there’s no proper sanitization.

 **Example:**
Instead of leaving a normal comment, an attacker might post:

```
Nice article!'); DROP TABLE users;--
```

---

### 5. Hidden Fields

Hidden form inputs can still be manipulated by attackers using tools like **Burp Suite**. If the hidden values are passed directly into SQL, they can become dangerous.

---

### 6. Cookies

Sometimes cookies hold user data (like IDs). If these are used directly in SQL queries without validation, attackers can modify them for SQL Injection.

 **Example:**
Changing a cookie value from:

```
user_id=5
```

to

```
user_id=5 OR 1=1
```

could bypass restrictions.

---

## Methods for Identifying SQL Injection

There are two main approaches: **manual testing** and **automated testing**.

---

### Manual Testing

#### 1. Injecting Malicious Input

Start by entering SQL keywords or special characters into input fields (login forms, search boxes, URL params). Look for:

* Error messages
* Unexpected behavior
* Suspicious responses

---

#### 2. Error-Based Testing

Purposely break the query by inserting malformed input like:

```
'
```

If the backend leaks database error messages, you’ve found a vulnerability.

---

#### 3. Union-Based Testing

Try appending `UNION SELECT` statements. If successful, you can extract data from other tables.

 **Example:**

```
' UNION SELECT username, password FROM users--
```

---

#### 4. Boolean-Based Testing

Here, you check how the app reacts to conditions that are always **true** or **false**.

 **Example:**

* Inject: `' OR '1'='1` → If login succeeds, injection works.
* Inject: `' OR '1'='2` → If login fails, that confirms SQL code execution.

---

#### 5. Time-Based Testing

This is useful when no errors are shown (blind SQLi). You inject queries that cause delays.

 **Example:**

```
' OR IF(1=1, SLEEP(5), 0)--
```

If the server delays for 5 seconds, it means SQL injection is possible.

---

#### 6. Input Validation & Sanitization Review

If you have access to source code, check if inputs are **directly concatenated** into SQL strings without using **prepared statements** or **parameterized queries**. That’s a huge red flag.

---

### Automated Testing

Manual testing is powerful, but time-consuming. Automated tools help scale the process:

* **SQLMap** → Industry-standard tool for automated SQL Injection testing and exploitation.
* **OWASP ZAP** → Open-source vulnerability scanner with SQLi detection.
* **Burp Suite** → Professional security testing tool with powerful SQLi scanning features.

 **Example workflow:**
You discover a suspicious parameter manually → You confirm it with SQLMap to dump database contents automatically.

---

 **Summary:**
Finding SQL Injection involves:

1. Identifying potential injection points (manual or automated).
2. Testing with different payloads (error-based, union-based, boolean, time-based).
3. Confirming and exploiting with automated tools.
