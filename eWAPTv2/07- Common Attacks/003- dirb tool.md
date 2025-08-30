
![0](https://github.com/user-attachments/assets/d5f1b680-ea84-4a99-8d47-8d005b5652dc)

## 1. What is DIRB?

`dirb` is a **web content scanner**. Its main job is to **brute force directories and files on a web server** by trying many possible names (from a wordlist) to find hidden resources.

It’s especially useful in **penetration testing and bug bounty hunting**, where applications may expose sensitive files or admin panels that aren’t linked anywhere.

Think of it as:

* You have a dictionary (wordlist).
* You try each word as a possible folder or file name on the target website.
* If the server responds positively (e.g., status code 200, 301, 403), you’ve discovered something interesting.

---

## 2. How DIRB Works

* It sends HTTP requests to the target web server.
* It uses a **wordlist** of common directory and file names.
* It checks the response status code and reports potential valid files or directories.

Example process:

```
Target: http://example.com/
Wordlist contains: admin, login, images, index.php
Requests:
http://example.com/admin      → 200 OK (directory found)
http://example.com/login      → 200 OK (login page found)
http://example.com/images     → 301 Redirect (directory exists)
http://example.com/index.php  → 200 OK (file found)
```

---

## 3. Basic Syntax

```
dirb <url> [wordlist] [options]
```

* `<url>` → target website (e.g., `http://example.com/`)
* `[wordlist]` → optional, if not specified, DIRB uses its default wordlist located in `/usr/share/dirb/wordlists/`
* `[options]` → extra settings (like extensions, proxy, output, etc.)

---

## 4. Key Options

Here are the most commonly used options in `dirb`:

* `-X <ext>` → specify file extensions to search for (e.g., `.php,.html,.bak`)
* `-r` → do not search recursively
* `-R` → enable recursive search (go deeper into discovered directories)
* `-o <file>` → save results to an output file
* `-p <proxy>` → use proxy (useful with Burp Suite or intercepting traffic)
* `-S` → silent mode (only outputs found results)
* `-w` → do not stop when encountering warning codes
* `-z <milisecs>` → add delay between requests (to avoid detection or reduce server load)

---

## 5. Examples

### Example 1: Simple Scan with Default Wordlist

```
dirb http://example.com/
```

This will run against `http://example.com/` using the default wordlist.

---

### Example 2: Using a Custom Wordlist

```
dirb http://example.com/ /usr/share/wordlists/dirb/common.txt
```

Here we tell `dirb` to use `common.txt` instead of the default list.

---

### Example 3: Searching for Specific File Extensions

```
dirb http://example.com/ /usr/share/wordlists/dirb/common.txt -X .php,.bak,.txt
```

This will search not just for directories but also for files ending in `.php`, `.bak`, and `.txt`.

For example, it may find:

* `http://example.com/admin.php`
* `http://example.com/backup.bak`
* `http://example.com/readme.txt`

---

### Example 4: Recursive Search

```
dirb http://example.com/ /usr/share/wordlists/dirb/common.txt -R
```

This tells `dirb` to scan deeper into any directories it discovers.

For example:

* Finds `/admin/`
* Then scans inside `/admin/` for more files like `/admin/login.php`

---

### Example 5: Saving Results to a File

```
dirb http://example.com/ /usr/share/wordlists/dirb/common.txt -o results.txt
```

This will output all results into a file named `results.txt`.

---

### Example 6: Using Proxy (e.g., Burp Suite at 127.0.0.1:8080)

```
dirb http://example.com/ -p 127.0.0.1:8080
```

This allows you to capture and inspect all requests in Burp Suite.

---

## 6. When to Use DIRB

* During **reconnaissance** to find hidden resources.
* To discover:

  * `/admin` panels
  * `/backup/` directories
  * hidden `.php` files
  * sensitive files like `db_backup.sql` or `config.bak`
* As a quick, lightweight alternative to tools like **Gobuster** or **FFUF**.

---

## 7. Limitations

* Can generate a lot of requests (may trigger WAF/firewalls).
* Wordlist dependent → if the word isn’t in the list, it won’t find it.
* Slower compared to multithreaded tools like `ffuf` or `gobuster`.

---
