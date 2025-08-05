
<img width="1197" height="463" alt="x" src="https://github.com/user-attachments/assets/80be6944-ada1-4ba2-9c78-dddb3e320713" />

###  What is SQL Injection?

**SQL Injection (SQLi)** is a type of web application vulnerability that allows attackers to **inject malicious SQL statements** into input fields of a website or application. These statements are then executed by the backend database, giving attackers access to data or control over the database server.

This happens when:

* User input is not properly **validated or sanitized**.
* The application **dynamically constructs SQL queries** using unsafe input.
* SQL code and **user data are mixed** without separation.

> **Example**:
> A vulnerable login form might generate the following SQL query:

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password';
```

If an attacker inputs:

* `Username: ' OR '1'='1`
* `Password: [blank]`

The query becomes:

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

This condition is always true, allowing the attacker to **bypass authentication** and log in without credentials.

---

###  Why Does SQL Injection Happen?

SQL Injection vulnerabilities are caused by:

* Failure to **validate and sanitize user input**
* Directly inserting user input into SQL queries
* **Dynamic SQL statements** that concatenate strings
* Lack of use of **prepared statements** or **parameterized queries**
* Displaying **detailed error messages** to the user

Applications that interact with databases like **MySQL**, **MSSQL**, **Oracle**, **PostgreSQL**, etc., are especially vulnerable if not properly coded.

---

###  Consequences of SQL Injection

SQL Injection can lead to:

* Unauthorized access to sensitive information
* User login bypass
* Modification or deletion of database records
* Access to other parts of the system or server
* Full database compromise
* Potential access to internal infrastructure

---

###  How SQL Injection is Used

Attackers may use SQLi to:

* **Dump entire databases** (usernames, passwords, credit cards)
* **Extract data one column at a time**
* **Fingerprint** the database type and version
* **Write or delete** data
* **Escalate privileges**
* **Write files** to disk (in some configurations)
* Chain with **RCE (Remote Code Execution)** exploits

---

###  History of SQL Injection

* The term **"SQL Injection"** was first introduced by **Jeff Forristal** (aka *Rain Forest Puppy*) in a paper presented at **DefCon 8** in **2000**.
* One of the earliest SQLi incidents occurred as far back as **1998**, when an attacker used the technique to access systems at the **U.S. Department of Energy**.

---

###  Notable SQL Injection Attacks

| Year | Target                    | Description                                                                  |
| ---- | ------------------------- | ---------------------------------------------------------------------------- |
| 1998 | U.S. Department of Energy | Early documented SQLi used by Rain Forest Puppy to access internal systems.  |
| 2000 | CD Universe               | First widely publicized SQLi attack; credit card info was stolen and leaked. |
| 2002 | United Nations            | Russian group “The Helldiggers” stole sensitive UN data using SQLi.          |
| 2012 | LinkedIn                  | Attackers stole and leaked 6.5 million hashed passwords.                     |
| 2015 | Ashley Madison            | SQLi allowed attackers to steal and dump sensitive private user data.        |

---

###  Types of SQL Injection

1. ### **In-band SQLi (Classic)**

   * Data is extracted using the same channel as the injection.
   * **Subtypes**:

     * **Error-based SQLi**: uses detailed DB errors to extract information.
     * **Union-based SQLi**: uses `UNION SELECT` to fetch data from other tables.

2. ### **Blind SQLi**

   * No direct feedback is given.
   * **Boolean-based Blind**:

     * Sends payloads that evaluate true/false and observes web app behavior.
     * Example:
       `AND 1=1` vs `AND 1=2`
   * **Time-based Blind**:

     * Relies on SQL functions like `SLEEP()` or `WAITFOR DELAY` to delay response.
     * Example:
       `IF(1=1, SLEEP(5), 0)`

3. ### **Out-of-band SQLi**

   * Data is retrieved via a different channel (DNS, HTTP callbacks).
   * Used when no feedback or time delay is possible.

4. ### **Second-order SQLi**

   * Malicious payload is stored in the database and triggered later in a different context.

---

###  SQL Injection Tools

| Tool                   | Purpose                                    |
| ---------------------- | ------------------------------------------ |
| **sqlmap**             | Automated SQLi exploitation tool           |
| **Burp Suite**         | Intercept, modify, and replay web requests |
| **Havij** (deprecated) | GUI-based SQLi tool (detected easily now)  |
| **jSQL Injection**     | Java-based GUI SQLi automation             |
| **Manual Tools**       | Browser Dev Tools, Postman, `curl`, etc.   |

---

##  Summary

SQL Injection remains one of the most dangerous and common web vulnerabilities.
Its simplicity, severity, and potential impact make it a critical concern for developers, testers, and security professionals alike.
Proper input handling, database access control, and secure coding practices are key to defending against SQLi attacks.
