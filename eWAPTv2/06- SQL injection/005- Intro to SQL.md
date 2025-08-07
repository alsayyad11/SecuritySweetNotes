<img width="747" height="418" alt="image" src="https://github.com/user-attachments/assets/18fdca56-0641-43f4-883c-8f1a00769da2" />


## 1. Introduction to SQL  
Modern web applications—from simple blogs to enterprise CMSs—almost always rely on a **database** to store and retrieve data such as user accounts, content, or analytics. To communicate with these databases, applications use **Structured Query Language (SQL)**.

- **What is SQL?**  
  SQL is a domain-specific, interpreted language designed to **query**, **insert**, **update**, and **delete** data in a relational database.

- **Where is SQL used?**  
  - Content Management Systems (WordPress, Drupal)  
  - E-commerce sites (product catalogs, orders)  
  - Social networks (user profiles, posts)  
  - Enterprise applications (ERP, CRM)

- **Popular SQL databases:**  
  MySQL, Microsoft SQL Server, Oracle, PostgreSQL, SQLite

---

## 2. Database Connectors (Drivers)  
Applications do not speak SQL natively—they use **connectors** or **drivers** to translate language constructs into the database’s protocol.

- **Definition**  
  A database connector is a library or API that an application uses to:
  1. **Open** a network connection to the database server  
  2. **Authenticate** (provide credentials)  
  3. **Send** SQL commands  
  4. **Receive** results (rows of data, status codes)  
  5. **Manage** transactions (BEGIN, COMMIT, ROLLBACK)

- **Examples**  
  - **PHP**: `mysqli`, `PDO`  
  - **Python**: `psycopg2`, `mysql-connector-python`  
  - **Java**: JDBC drivers  
  - **Node.js**: `node-postgres`, `mysql2`

---

## 3. Core SQL Concepts  
Before advanced operations (e.g., SQLi testing), understand:

1. **SQL Syntax** (statement structure)  
2. **Basic Queries** (`SELECT`, `INSERT`, `UPDATE`, `DELETE`)  
3. **Combining Results** with `UNION`  
4. **Comments** (disable or annotate parts of a query)

### 3.1 Important SQL Commands

| Command    | Purpose                                                     |
| ---------- | ----------------------------------------------------------- |
| `SELECT`   | Read data from one or more tables                           |
| `UNION`    | Combine results from two or more `SELECT` queries           |
| `INSERT`   | Add a new row to a table                                    |
| `UPDATE`   | Modify existing rows                                        |
| `DELETE`   | Remove rows                                                 |
| `ORDER BY` | Sort query results (`ASC` or `DESC`)                        |
| `LIMIT`    | Restrict number of rows returned                            |

### 3.2 SQL Special Characters

| Character                               | Use                                              |
| --------------------------------------- | ------------------------------------------------ |
| `'` or `"`                              | Surround string literals                         |
| `/* ... */`                             | Multi-line comment                               |
| `-- ` or `#`                            | Single-line comment                              |
| `+`                                     | Addition or (in some dialects) string concatenation |
| `||`                                    | String concatenation (standard SQL)              |
| `%`                                     | Wildcard in `LIKE` comparisons                   |
| `@variable`                             | Local variable (some SQL dialects)               |
| `@@variable`                            | Global variable (some SQL dialects)              |
| `WAITFOR DELAY 'hh:mm:ss'` / `SLEEP(n)` | Time-delay functions                             |

---

## 4. SELECT and UNION Statements

### 4.1 SELECT Syntax

```sql
SELECT <column1>, <column2>, ...
  FROM <table_name>
 WHERE <condition>;
````

**Example**
Retrieve the name and description of the product with `id = 9`:

```sql
SELECT name, description
  FROM products
 WHERE id = 9;
```

### 4.2 UNION Syntax

```sql
<first SELECT query>
UNION
<second SELECT query>;
```

* **Requirements:** same column count and compatible data types.
* **Example:** combine product details with its price:

```sql
SELECT name, description
  FROM products
 WHERE id = 9

UNION

SELECT CAST(price AS CHAR), NULL
  FROM products
 WHERE id = 9;
```

---

## 5. SQL Comments

Comments let you annotate or disable parts of a query:

* **Single-line:**

  ```sql
  SELECT field FROM table;  -- comment
  SELECT field FROM table;  # comment
  ```
* **Multi-line:**

  ```sql
  /*
    This is a
    multi-line comment
  */
  SELECT field FROM table;
  ```

---

## 6. How Web Applications Execute SQL

Typical flow:

1. **Retrieve** user input (query parameters, forms, cookies)
2. **Construct** SQL string (often dynamically)
3. **Submit** query via connector
4. **Fetch** and **render** results

### 6.1 Static Query Example (PHP + MySQLi)

```php
$dbhost = '1.2.3.4';
$dbuser = 'username';
$dbpass = 'password';
$dbname = 'database';

$connection = mysqli_connect($dbhost, $dbuser, $dbpass, $dbname);

$query = "
  SELECT Name, Description
    FROM Products
   WHERE ID = '3'
  UNION
  SELECT Username, Password
    FROM Accounts;
";

$results = mysqli_query($connection, $query);
display_results($results);
```

---

## 7. Vulnerable Dynamic Queries

Dynamic queries built with unsanitized user input are risky.

### 7.1 Example of a Vulnerable Query

```php
$id         = $_GET['id'];  // user-controlled
$connection = mysqli_connect($dbhost, $dbuser, $dbpass, $dbname);

$query = "
  SELECT Name, Description
    FROM Products
   WHERE ID = '$id';
";

$results = mysqli_query($connection, $query);
display_results($results);
```

* If `id = 3`:

  ```sql
  SELECT Name, Description
    FROM Products
   WHERE ID = '3';
  ```
* If `id = ' OR 'a'='a`:

  ```sql
  SELECT Name, Description
    FROM Products
   WHERE ID = '' OR 'a'='a';
  ```

  The condition `'a'='a'` always true ⇒ returns **all rows**.

### 7.2 Why This Matters

* **Injection Point:** any direct insertion of user data into SQL
* **Impact:** read unauthorized data, modify/delete records, escalate privileges

---
