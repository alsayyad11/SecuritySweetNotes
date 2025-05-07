## 🔍 What is Input Sanitization?

![image](https://github.com/user-attachments/assets/ac8148c3-8c66-4634-9d88-fe9aa845a598)

**Input sanitization**, also known as **data sanitization**, is the process of cleansing user input before it is processed by an application or system. It has nothing to do with physical input devices; rather, it focuses on the data itself, aiming to remove or alter any content that could pose a threat or cause unexpected behavior.

This process applies to:

* Data submitted through web forms.
* Uploaded files.
* Inputs from APIs or database queries.

The core idea is to **filter out potentially malicious or malformed data** before it reaches the processing logic or is stored in a database.

🛡 The main objective of sanitization is to minimize the risk of security vulnerabilities such as script injections, command injections, and data corruption.

---

## Input Sanitization Methods

### 1. **Blacklist Sanitizing**

This approach involves defining a list of known malicious patterns or strings (e.g., `<script>`, `DROP TABLE`, etc.) and blocking any input that matches them.

 **Major drawback**:
Attackers can easily bypass blacklists using encoded payloads, character casing tricks (e.g., `<ScRiPt>`), or character substitution (e.g., `%3Cscript%3E`). Because of this, blacklisting is generally considered ineffective as a standalone defense.

---

### 2. **Whitelist Sanitizing**

Instead of blocking known bad inputs, this method defines exactly what is allowed and **only permits explicitly defined safe content**.

Examples:

* If expecting a numeric value, only allow digits 0–9.
* For names, allow only alphabetic characters and spaces.

**Whitelist-based sanitization is more secure** because it reduces the input surface area, effectively minimizing the chance of unexpected or malicious content.

---

## Benefits of Input Sanitization

1. **Prevention of Injection and Inclusion Attacks**
   Proper sanitization helps prevent critical security threats like **SQL Injection**, **Cross-Site Scripting (XSS)**, and **Command Injection** by removing or neutralizing potentially dangerous elements.

2. **Regulatory Compliance**
   Sanitization assists in meeting data protection standards such as **GDPR**, **HIPAA**, and **PCI-DSS**, which require secure data handling and input hygiene.

3. **Preservation of System and Data Integrity**
   Ensuring that only clean and valid data enters the system prevents corruption of business logic and protects against accidental or intentional tampering.

4. **Improved Application Stability and Performance**
   Applications operate more reliably when they process clean data, reducing the likelihood of runtime exceptions, crashes, or performance degradation due to malformed input.

---

##  Input Sanitization vs Input Validation

| Aspect                | Input Validation                           | Input Sanitization                                      |
| --------------------- | ------------------------------------------ | ------------------------------------------------------- |
| **Purpose**           | To check if input meets expected criteria  | To clean or modify input to make it safe                |
| **When it's applied** | Before processing input                    | After validation, before storing or using input         |
| **Common Techniques** | Type checks, format matching, value ranges | HTML escaping, encoding, script stripping               |
| **Example**           | Ensure age is an integer between 18 and 60 | Convert `<script>` into `&lt;script&gt;`                |
| **Protection from**   | User errors, invalid or unexpected input   | Malicious payloads, executable code, structural attacks |

![image](https://github.com/user-attachments/assets/97c5b1fa-154a-45f1-bcab-db790df23dd0)

**Summary:**

* **Validation** checks whether the data is correct and expected.
* **Sanitization** ensures the data is safe and cannot harm the system.

---

## Combined Approach: Validate ➝ Sanitize ➝ Escape

Relying on a single technique is never sufficient. A secure data handling pipeline should include **all three stages**:

1. **Input Validation**: Reject obviously invalid data at the earliest point.
2. **Input Sanitization**: Clean data of any potentially harmful elements.
3. **Contextual Output Escaping**: Encode or escape output based on context (e.g., HTML, JavaScript, SQL) before rendering it back to the user or using it in queries.

---

# Test Code : 

### 1. **SQL Injection**

#### **Before** (Without Protection)

In this case, if there’s a user input field like a username and password, and the user enters malicious data like `' OR 1=1 --`, it could execute a dangerous query.

**Code before protection:**

```php
<?php
// User entered username and password
$username = $_POST['username'];
$password = $_POST['password'];

// Vulnerable SQL query
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

// Execute query
$result = mysqli_query($conn, $query);
?>
```

If the user enters:

```sql
' OR 1=1 -- 
```

The query becomes:

```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = 'password';
```

This query will return all data from the database because of **OR 1=1**.

#### **After** (With Protection)

In this case, we use **prepared statements** or **parameterized queries** to prevent SQL Injection.

**Code after protection:**

```php
<?php
// User entered username and password
$username = $_POST['username'];
$password = $_POST['password'];

// Use prepared statements to prevent SQL Injection
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password); // "ss" means string, string

// Execute the query
$stmt->execute();
$result = $stmt->get_result();
?>
```

This approach makes the query safe because the user inputs are treated as **parameters**, not directly in the query. Even if the user enters something harmful like `OR 1=1 --`, it won’t affect the query.

---

### 2. **Cross-Site Scripting (XSS)**

#### **Before** (Without Protection)

In this case, if a user enters **script** in a text box or any data input field, it can execute the code in the user's browser.

**Code before protection:**

```php
<?php
// User entered text in the search box
$user_input = $_POST['search'];

// Display input directly on the page
echo "Your search: " . $user_input;
?>
```

If the user enters:

```html
<script>alert('XSS');</script>
```

This will execute the script in the browser and show the `alert('XSS')`.

#### **After** (With Protection)

In this case, we use **htmlspecialchars()** in PHP to prevent scripts from running.

**Code after protection:**

```php
<?php
// User entered text in the search box
$user_input = $_POST['search'];

// Use htmlspecialchars to convert special characters into HTML entities
echo "Your search: " . htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
?>
```

If the user enters:

```html
<script>alert('XSS');</script>
```

It will be converted to a safe HTML representation like:

```html
&lt;script&gt;alert('XSS');&lt;/script&gt;
```

So the script will not execute in the browser.

---

### 3. **Comparison Between Code Before and After Protection**

| **Before Protection** (Vulnerable)                                                | **After Protection** (Safe)                                  |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Uses **direct SQL query** without protection against SQL Injection.               | Uses **prepared statements** with **parameterized queries**. |
| Directly outputs **user input** without sanitization, allowing **XSS** execution. | Uses **htmlspecialchars()** to convert input into safe HTML. |

---


