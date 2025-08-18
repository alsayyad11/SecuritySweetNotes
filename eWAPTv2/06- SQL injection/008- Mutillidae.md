## What is Mutillidae?

Mutillidae is a **deliberately vulnerable web application** created for training and practicing different web security concepts. It is widely used by penetration testers, bug bounty hunters, and security students to practice exploiting common vulnerabilities such as **SQL Injection, XSS, CSRF, File Inclusion, Authentication Bypass**, and many more.

Unlike real-world applications where vulnerabilities are hidden and patched, Mutillidae provides an environment where these flaws are intentionally included and documented, making it easier for learners to **practice, break, and understand web security issues**.

---

## Key Features

* Over **40+ web vulnerabilities** to practice with.
* Comes with **OWASP Top 10 vulnerabilities** implemented.
* Runs on simple stacks such as **XAMPP, LAMP, WAMP, or Docker**.
* Easy to install and configure.
* Contains **hints and help** for beginners to learn step-by-step exploitation.
* Great for **CTFs, bug bounty preparation, and hands-on labs**.

---

## Installation – Step by Step

You can install Mutillidae in different ways depending on your system. Here are the most common methods:

---

### **1. Installation on Windows using XAMPP**

1. Download and install **XAMPP** from: [https://www.apachefriends.org/index.html](https://www.apachefriends.org/index.html).

   * XAMPP comes with **Apache + MySQL (MariaDB) + PHP + Perl**.

2. Once installed, open the **XAMPP Control Panel** and start:

   * `Apache`
   * `MySQL`

3. Download Mutillidae from GitHub:

   * [https://github.com/webpwnized/mutillidae](https://github.com/webpwnized/mutillidae)

4. Extract the Mutillidae folder into the `htdocs` directory of XAMPP:

   * Example path: `C:\xampp\htdocs\mutillidae`

5. Open your browser and visit:

   * `http://localhost/mutillidae`

6. Configure the database:

   * Mutillidae will prompt you to set up the database tables.
   * Click “Setup/Reset DB” from the web interface.

 Now Mutillidae is running on your local machine.

---

### **2. Installation on Linux using LAMP**

1. Install Apache, MySQL, and PHP:

   ```bash
   sudo apt update
   sudo apt install apache2 mysql-server php php-mysqli unzip git -y
   ```

2. Navigate to the web root directory:

   ```bash
   cd /var/www/html
   ```

3. Clone Mutillidae from GitHub:

   ```bash
   sudo git clone https://github.com/webpwnized/mutillidae.git
   ```

4. Adjust permissions:

   ```bash
   sudo chown -R www-data:www-data mutillidae
   ```

5. Restart Apache:

   ```bash
   sudo systemctl restart apache2
   ```

6. Open in browser:

   * `http://localhost/mutillidae`
   * Setup database by clicking “Setup/Reset DB”.

---

### **3. Installation with Docker (Recommended for Quick Setup)**

1. Make sure Docker is installed:

   * [Install Docker](https://docs.docker.com/get-docker/)

2. Pull Mutillidae Docker image:

   ```bash
   docker pull citizenstig/nowasp
   ```

3. Run Mutillidae container:

   ```bash
   docker run -d -p 8080:80 citizenstig/nowasp
   ```

4. Access Mutillidae in browser:

   * `http://localhost:8080`

 This method is the easiest since everything is preconfigured.

---

## Examples of Usage

* **SQL Injection Practice:**
  Try classic payloads such as `' OR '1'='1` in the login forms.
* **XSS Practice:**
  Inject `<script>alert('XSS')</script>` into comment boxes.
* **Authentication Bypass:**
  Learn how weak login systems can be bypassed with crafted inputs.

---

## Learning Resources for Mutillidae

* Official GitHub Repo: [https://github.com/webpwnized/mutillidae](https://github.com/webpwnized/mutillidae)
* Tutorials:

  * [OWASP Mutillidae II on YouTube](https://www.youtube.com/playlist?list=PLZOToVAK85MbxK9gWcNGRhWjXTE9X2lF5)
* Recommended Books:

  * *Web Application Hacker’s Handbook*
  * *OWASP Testing Guide*

---

