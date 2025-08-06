<img width="1720" height="900" alt="0712-Bad_Practices_in_Database_Design_-_Are_You_Making_These_Mistakes_Dan_Social" src="https://github.com/user-attachments/assets/79a2f707-d05c-49ac-8540-dc21eacef276" />


A **database** is a structured collection of data designed to make storage, retrieval, management, and updating both efficient and reliable.

* **Database Management System (DBMS):** Software that provides tools and interfaces to create, query, update, and administer databases without exposing low-level storage details.
* **Use Cases:** Business applications, e-commerce sites, mobile apps, analytics platforms, IoT data ingestion, content management systems.

**Real-World Examples:**

* Customer profiles and transaction history in an online bank
* Product catalogs and orders in an e-commerce site
* Sensor readings in an IoT platform

---

# Database Management Systems (DBMS)

A **DBMS** sits between applications and physical data storage, offering:

1. **Data Definition:** Create, alter, and drop database structures (tables, indexes, views)
2. **Data Manipulation:** Insert, update, delete, and query records
3. **Security & Access Control:** User authentication, permissions, roles
4. **Transaction Management:** Begin, commit, rollback; ensures ACID properties
5. **Concurrency Control:** Locks and isolation levels to prevent conflicts
6. **Backup & Recovery:** Restore data after failures

**Popular DBMS Examples:**

* **MySQL** – Open-source, widely used for web applications
* **PostgreSQL** – Advanced open-source RDBMS with rich feature set
* **Oracle Database** – Enterprise-grade commercial RDBMS
* **Microsoft SQL Server** – Commercial RDBMS integrated with the Microsoft stack
* **MongoDB** – Document-oriented NoSQL database
* **Redis** – In-memory key-value store

---

# Types of Databases

Databases can be classified by their data model:

| Category             | Data Model                                   | Typical Use Cases                                                  |
| -------------------- | -------------------------------------------- | ------------------------------------------------------------------ |
| **Relational (SQL)** | Tables (rows & columns), relations           | Financial systems, ERP, CRM, any structured data with clear schema |
| **NoSQL**            | Various (document, key-value, graph, column) | Big data, real-time applications, flexible schemas                 |
| **Object-Oriented**  | Objects and classes                          | Complex data with rich relationships (CAD, simulation)             |
| **NewSQL**           | Relational but horizontally scalable         | Cloud-native transactional workloads                               |

---

## SQL (Relational) Databases

* **Structure:** Data in **tables** (relations) with defined schemas (columns and types).
* **Query Language:** Standardized **SQL** (Structured Query Language).
* **ACID Transactions:** Atomicity, Consistency, Isolation, Durability.
* **Use Cases:** Applications requiring complex joins, strict consistency, and structured reporting.

**Common SQL DBMS:** MySQL, PostgreSQL, Oracle, SQL Server.

---

### Relational Databases vs. NoSQL

| Aspect       | Relational (RDBMS)                         | NoSQL                                                              |
| ------------ | ------------------------------------------ | ------------------------------------------------------------------ |
| Schema       | Fixed schema (predefined tables & columns) | Schema-less or flexible schema                                     |
| Scaling      | Vertical (scale-up)                        | Horizontal (scale-out)                                             |
| Transactions | Full ACID support                          | Often BASE (Basically Available, Soft state, Eventual consistency) |
| Querying     | SQL with JOINs                             | Varies by model (e.g., document queries, graph traversals)         |
| Use Cases    | Structured data, complex reporting         | Large-scale, real-time, semi-structured data                       |

---

### Relational Database Management Systems (RDBMS)

An **RDBMS** implements the relational model with features for:

* **Schema Definition:** CREATE TABLE, ALTER TABLE
* **Data Integrity:** PRIMohammed KEY, FOREIGN KEY, UNIQUE, CHECK constraints
* **Transactions & Concurrency:** BEGIN/COMMIT/ROLLBACK, isolation levels (READ COMMITTED, SERIALIZABLE)
* **Indexing:** B-tree, hash indexes for fast lookups
* **Views, Stored Procedures, Triggers**

**Popular RDBMS Examples:**

* **Oracle Database:** Enterprise features (Real Application Clusters, advanced partitioning)
* **MySQL / MariaDB:** Ease of use, replication, wide hosting support
* **Microsoft SQL Server:** Deep .NET integration, SSRS/SSIS/SSAS suite
* **PostgreSQL:** Extensibility (custom types, functions), strong SQL standards compliance

---

# How Relational Databases Work

## Tables, Rows, and Columns

* A **table** stores entities; each **row** is one record; each **column** is an attribute.
* Example: a `Students` table:

| id | name | email                                       |
| -- | ---- | ------------------------------------------- |
| 1  | Ahmed | [Ahmed@example.com](mailto:Ahmed@example.com) |
| 2  | Elsayyad | [Elsayyad@example.com](mailto:Elsayyad@example.com) |

## Keys and Relationships

* **PriMohammed Key (PK):** Uniquely identifies each row (e.g., `id`).
* **Foreign Key (FK):** References a PK in another table to establish a relationship.

### Relationship Types

1. **One-to-One:** Each row in A links to one row in B.
2. **One-to-Many:** One row in A links to multiple rows in B.
3. **Many-to-Many:** Requires a **junction table**.

**Example Schema: Students–Courses**

```sql
CREATE TABLE Students (
  id SERIAL PRIMohammed KEY,
  name VARCHAR(100)
);

CREATE TABLE Courses (
  id SERIAL PRIMohammed KEY,
  title VARCHAR(100)
);

CREATE TABLE Enrollments (
  student_id INT REFERENCES Students(id),
  course_id  INT REFERENCES Courses(id),
  PRIMohammed KEY (student_id, course_id)
);
```

Sample Data:

**Students**

| id | name |
| -- | ---- |
| 1  | Ahmed |
| 2  | Elsayyad |
| 3  | Mohammed |

**Courses**

| id | title |
| -- | ----- |
| 1  | XSS   |
| 2  | Java  |
| 3  | PHP   |

**Enrollments**

| student\_id | course\_id |
| ----------- | ---------- |
| 1           | 1          |
| 1           | 2          |
| 2           | 2          |
| 3           | 1          |

## Structured Query Language (SQL)

### CRUD Operations

* **CREATE** (Insert data)

  ```sql
  INSERT INTO Students (name) VALUES ('Ahmed');
  ```
* **READ** (Retrieve data)

  ```sql
  SELECT name FROM Students WHERE id = 1;
  ```
* **UPDATE**

  ```sql
  UPDATE Students SET email = 'Ahmed@example.com' WHERE id = 1;
  ```
* **DELETE**

  ```sql
  DELETE FROM Students WHERE id = 1;
  ```

### Joins

* **INNER JOIN:** Only matching rows

  ```sql
  SELECT s.name, c.title
  FROM Students s
  JOIN Enrollments e ON s.id = e.student_id
  JOIN Courses c     ON e.course_id = c.id;
  ```
* **LEFT JOIN:** All from left table, matching or `NULL`
* **RIGHT JOIN**, **FULL OUTER JOIN**

### Aggregation & Grouping

```sql
SELECT c.title, COUNT(e.student_id) AS num_students
FROM Courses c
LEFT JOIN Enrollments e ON c.id = e.course_id
GROUP BY c.title;
```

---

## NoSQL Databases

**NoSQL** (“Not Only SQL”) databases trade strict schemas and ACID in favor of flexibility, scalability, and performance.

### Common NoSQL Models

| Model           | Description                                  | Example Use Cases                       |
| --------------- | -------------------------------------------- | --------------------------------------- |
| **Document**    | JSON-like documents, indexed by key          | Content management, user profiles       |
| **Key-Value**   | Simple key → value pairs                     | Caching, session stores                 |
| **Wide-Column** | Tables with dynamic columns                  | Time series, logging                    |
| **Graph**       | Nodes and edges, optimized for relationships | Social networks, recommendation engines |

### Example NoSQL Engines

* **MongoDB (Document)**

  ```json
  {
    "_id": ObjectId("…"),
    "username": "Ahmed",
    "email": "Ahmed@example.com",
    "roles": ["user", "admin"]
  }
  ```
* **Redis (Key-Value / In-Memory)**

  ```text
  SET session:12345 "user=Ahmed;expires=…"
  ```
* **Cassandra (Wide-Column)**

  ```cql
  CREATE TABLE sensor_data (
    sensor_id text,
    timestamp  timestamp,
    value      float,
    PRIMohammed KEY (sensor_id, timestamp)
  );
  ```
* **Neo4j (Graph)**

  ```cypher
  CREATE (a:Person {name: 'Ahmed'})-[:FRIENDS_WITH]->(b:Person {name: 'Bob'});
  ```

---

# SumMohammed

1. **Databases** provide structured storage and retrieval of data.
2. **DBMS** software manages data integrity, concurrency, security, and recovery.
3. **Relational Databases** use tables, enforce schemas, and support ACID with SQL.
4. **NoSQL Databases** offer schema flexibility and horizontal scalability across various data models.
5. **RDBMS Features:** tables, keys, relationships, SQL CRUD, joins, indexing, transactions.
6. **NoSQL Features:** document/key-value/column/graph models for modern, large-scale applications.

