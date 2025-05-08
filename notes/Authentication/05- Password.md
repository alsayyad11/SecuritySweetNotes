# Password Security Overview

![image](https://github.com/user-attachments/assets/f8c8bf3d-5f4a-464c-a07b-4dd323355abc)

## **Password**

The first thing we start with is the password. A password is a word or phrase that we use to prove our identity in systems or websites. For example, if you want to log into your account on a website, you'll need to enter your password to verify that you are the person who created that account.

Initially, the password is stored as **plaintext**, meaning it's not encrypted yet. A password might look like "MyP\@ssword1", which you enter when you create a new account.

When you try to log in again, you enter the **username** and password, and a process happens behind the scenes to check if the password you entered is correct. If it's correct, you gain access to your account.

But how does the website know this? Because the website has a stored copy of the password in the form of a **hash** and it can compare the entered password with the stored **hash**.

Luckily, the website doesn't store your password as **plaintext** in the database. If it did, if the database were compromised, an attacker could easily access all accounts.

---

## **Hashing**

Instead, we use a process called **hashing** to hide the password in the database. This is a transformation of the password into a fixed-length string that can’t be reversed back to the original password. For example, if the password "MyP\@ssword1" is hashed, the result might look like:

**SHA256 Hash**: `55BFFD094830B5D09311BB357C415D8D1323F8185EE2F0C1F94E96C3E2BDD1B5`

This **hash** cannot be reversed to retrieve the original password, so even if it is leaked, the attacker cannot determine the real password.

But the issue is, attackers can still try to steal the data and perform attacks on the **hash**.

---

## **Password Hashing Algorithms**

There are different algorithms we use to **hash** passwords, and each has its advantages and disadvantages:

1. **SHA256**: A fast algorithm, but it's not as secure for password protection because it can be attacked easily via **brute force**.
2. **bcrypt**: A strong and secure algorithm because it uses **salt** and makes the hashing process slower, making attacks harder.
3. **PBKDF2**: Another secure algorithm that uses multiple **iterations**, making attacks more difficult.
4. **Argon2**: The latest and strongest algorithm for password protection, considered the best currently because it takes both speed and memory usage into account, making attacks more challenging.

---

## **The Problem...**

**Hashing** alone is not enough because older algorithms like **SHA256** aren't as secure as they used to be. For example, if many people are using the same password like "MyP\@ssword1", each one will generate the same **hash**. This makes it easier for attackers to use **rainbow tables**, which are large precomputed lists of **hashes** for common passwords.

---

## **Salting**

To improve security, we add something called a **salt**, which is a random string of characters and symbols that is added to the password before it is hashed. This makes each **hash** unique.

For example, if your password is "MyP\@ssword1" and your **salt** is "XElWz9WPwSLK3y0jUP6KhO", the password would be:

**MyP\@ssword1XElWz9WPwSLK3y0jUP6KhO**

The **salt** makes it much harder for attackers to use **rainbow tables** because it ensures that each **hash** is unique, even if many people use the same password.

---

## **Password Spraying**

Another type of attack is **password spraying**, where the attacker tries a single password across many different accounts. For example, if an attacker knows your **username**, they might try the same password on many accounts until they find one that isn't well-secured.

---

## **Password Cracking Tools**

There are tools available for attacking passwords and **cracking** the **hashes**, such as:

1. **John the Ripper**: A powerful tool for **cracking** passwords via **dictionary attacks** or **brute force**.
2. **Hashcat**: An advanced tool capable of cracking **hashes** using multiple techniques.
3. **Cain and Abel**: A popular tool for **cracking** passwords, especially for **Windows** systems.

---

## **Degrees of Password Security**

1. **Weak Passwords**: These are easy-to-guess passwords like "123456" or "password".

   * **Characteristics**: Common words, short, or easy patterns.
   * **Protection Level**: **Very Low**. These passwords offer little protection and should be avoided.

2. **Moderate Passwords**: These passwords mix numbers, letters, and symbols but can still be cracked with certain attacks like **brute force** or **dictionary attacks**.

   * **Characteristics**: A combination of letters, numbers, and symbols.
   * **Protection Level**: **Low to Moderate**. These are better than weak passwords, but still not secure enough.

3. **Strong Passwords**: These passwords are complex, long, and random, providing strong protection.

   * **Characteristics**: 12–16 characters, a random mix of uppercase and lowercase letters, numbers, and symbols.
   * **Protection Level**: **High**. These are difficult to crack and secure.

4. **Very Strong Passwords**: These passwords are completely random and 20+ characters long, often generated by a **password manager**.

   * **Characteristics**: More than 20 characters, random, and a complete mix of letters, numbers, and symbols.
   * **Protection Level**: **Very High**. These are extremely hard to crack.

5. **Password with Multi-Factor Authentication (MFA)**: If you enable **MFA**, even if the password is compromised, the attacker won't be able to access your account without the second factor (such as a code sent to your phone or via an app like Google Authenticator).

   * **Protection Level**: **Extremely High**. MFA adds a significant layer of security.

6. **Biometric Authentication**: Options like **fingerprint** or **facial recognition** add another layer of security on top of passwords and **MFA**.

   * **Protection Level**: **Extremely High**. These are very difficult to hack, though there are some vulnerabilities (e.g., fingerprint or facial spoofing).

---

## **Best Practices for Password Security**

* **Always use strong or very strong passwords**.
* **Enable Multi-Factor Authentication (MFA)** whenever possible.
* **Store your passwords in a secure password manager**.
* **Avoid reusing passwords across different websites**.
* **Consider using biometric authentication** for added security.

---

## **Password Expiry**

It's best to change your passwords periodically, especially if there has been a data breach on any site. But make sure that your new password is strong and not just a random change.

---

## **Password Recovery**

* If you forget your password, ensure the **password recovery** process is secure. This means the site should ask for additional identity verification before allowing you to reset your password, such as **email verification** or **MFA**.
* **Security Questions** should be difficult to answer for someone else (e.g., avoid easy questions like "What is your mother's maiden name?").

---

## **Conclusion: Don't Use the Same Password on Multiple Sites!**

If you use the same password across multiple sites, and one site is breached, attackers could gain access to all your accounts. The solution is to use complex, unique passwords for each site and use a **password manager** like 1Password or Bitwarden to store them.

---
