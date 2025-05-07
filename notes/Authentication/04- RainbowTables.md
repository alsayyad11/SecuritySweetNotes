![image](https://github.com/user-attachments/assets/d718c412-31dc-41f0-b100-d4a2ea075473)

## Some Interesting Facts
- According to Naked Security, 55% of internet users use the same password for most websites.
- Over 30% of websites store passwords in plain text, including some well-known sites like Google, which stored some passwords in plain text for 14 years!
  
## How Does the Login Process Work?

Let’s walk through how the typical login process works:

### 1. Storing the Plain Text Password in the Database
- The user enters their credentials (Username: Admin, Password: Welcome@123), and the application compares the entered credentials with those stored in the database. If the credentials match, the user is authenticated; otherwise, they’re rejected.

### 2. Storing the Hashed Password in the Database
- To enhance security, we hash the password before storing it in the database. Since we store a hashed password, it cannot be directly compared with the entered plain text password. So, we hash the entered password and compare the resulting hash with the password stored in the database.

  **Note**: This process cannot be reversed. In other words, we cannot retrieve the original password from the hash in the database because hashing is a one-way function, whereas encryption is two-way. An encrypted string can be reversed, but a hash cannot.

## What Are Rainbow Tables?


![image](https://github.com/user-attachments/assets/2e746c5a-de1f-47b6-be0d-f4f64331bfb7)

Rainbow tables are precomputed tables used in cryptography to crack passwords. They contain a vast number of commonly used passwords and their corresponding hashes, making it easier for hackers to figure out the original password from the hash.

In fact, there is a large amount of leaked password data available on the internet, which can be used to create rainbow tables.

## How Do Rainbow Tables Work?

- First, the hacker gains access to the password hashes from a target system (e.g., via an SQL injection attack).
- Then, the hacker compares the hashes from the target system with the hashes stored in the rainbow table. If there is a match, the hacker can easily determine the corresponding plain-text password.

### Sample Rainbow Table Example:

| Plain Text Password | Hash                                   |
|---------------------|----------------------------------------|
| password            | 5f4dcc3b5aa765d61d8327deb882cf99       |
| 123456              | 8d969eef6ecad3c29a3a629280e686cf       |
| qwerty              | d8578edf8458ce06fbc5bb5c1cb5c55d6       |
| welcome123          | 24b7e1f75893fded3c780db45bce92fa       |
| letmein             | 0d107d09f5bbe40d4f4a3c8db07f6f8f       |

If the hacker obtains a hash like "5f4dcc3b5aa765d61d8327deb882cf99", it matches the hash for "password" in the table, allowing them to easily know the user’s original password.

## What Is Salting?


![image](https://github.com/user-attachments/assets/e8d52fb5-cd99-43a6-9286-131be7225565)

Salting is the process of adding a random string of characters to a password before it’s hashed. The goal of salting is to make it much harder for a hacker to crack the password, even if the password is commonly used.

**Example**:
- If the password is "Welcome@123" and the salt is "$Do0Ap#1", the hashed result for the string "Welcome@123$Do0Ap#1" is stored in the database instead of the hash for "Welcome@123" alone.

## Types of Salting:

### 1. Static Salt:
- In this method, a single salt is used for all passwords. It’s concatenated with the password before hashing. Even if two users have the same password, their hashes will be different due to the added salt. However, if the attacker gains access to this salt, they can regenerate the hashes by adding it to each password.

### 2. Dynamic Salt:
- In dynamic salting, each user gets a unique salt. The salt is stored in the database for each user. When the user logs in, the dynamic salt is retrieved and added to the user’s entered password, then hashed and compared with the stored hash.

  **Advantages of Dynamic Salt**: Even if the hacker gains access to the salt and the hash, they still need to rebuild the rainbow table for each individual user. This makes it much more difficult and time-consuming to crack passwords.

## Protecting Against Rainbow Table Attacks:

Here are a few tips to protect passwords from rainbow table attacks:

1. **Salting**:
   - **Salting** is the best protection against rainbow table attacks. By adding a random salt to each password before hashing, it makes it extremely difficult for attackers to determine the original password just by looking at the hash.

2. **Password Policies**:
   - Educate users about the importance of strong passwords. When users are forced to create complex passwords (with uppercase, lowercase, numbers, and special characters), it helps defend against rainbow table attacks.

3. **Multi-Factor Authentication (MFA)**:
   - Enabling **MFA** adds another layer of protection. Even if the hacker knows the user’s password, they will not be able to access the account without the second factor (such as a code sent to the user’s mobile device or a fingerprint scan).



