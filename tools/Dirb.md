<div align="center">
  <img src="https://github.com/user-attachments/assets/55f4eb90-b417-417d-bb72-0b17f879ae5b" alt="image">
</div>

---

## What is `dirb`?

`dirb` is a simple command-line tool used to discover **hidden directories and files** on a web server. These are pages or resources that don’t appear in the website navigation or links but may still be accessible if you know their name.

Examples of such hidden paths:

* `/admin`
* `/test.php`
* `/backup.zip`
* `/hiddenpanel.html`

---

## How Does `dirb` Work?

`dirb`:

1. Takes a target URL.
2. Uses a **wordlist** (a list of common directory and file names).
3. Appends each word to the URL and makes a request.
4. Analyzes the HTTP response code to determine if the resource exists.

---

## Where to Find Wordlists?

In Kali Linux, some default wordlists are included, such as:

```
/usr/share/wordlists/dirb/common.txt
```

This wordlist includes common names like:

```
admin
login
test
upload
images
config
backup
```

---

## Practical Example (DVWA)

Assume you are running DVWA on:

```
http://localhost/dvwa/
```

Run this command:

```bash
dirb http://localhost/dvwa/ /usr/share/wordlists/dirb/common.txt
```

`dirb` will attempt:

* `/dvwa/admin`
* `/dvwa/upload`
* `/dvwa/backup`
* and more...

If any of these exist, you’ll see a response with status code 200 or 403, which means the resource is there.

---

## Useful Options and Commands

### 1. Basic Scan:

```bash
dirb http://192.168.1.100
```

If you don’t provide a wordlist, it uses the default one.

---

### 2. Add Specific File Extensions:

```bash
dirb http://example.com /usr/share/wordlists/dirb/common.txt -X .php
```

This will try:

* `/admin.php`
* `/upload.php`
* `/login.php`

You can add multiple extensions:

```bash
-X .php,.html,.bak
```

---

### 3. Save Output to a File:

```bash
dirb http://example.com -o results.txt
```

---

### 4. Scanning HTTPS Sites:

```bash
dirb https://target.com
```

---

## Understanding HTTP Status Codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| 200  | Resource found and accessible    |
| 403  | Resource found but access denied |
| 401  | Requires authentication          |
| 404  | Not found                        |
| 500  | Server error                     |

---

## Why Is `dirb` Useful?

It helps discover:

* Hidden admin panels (`/admin`)
* Upload pages (`/upload`)
* Backup files (`/backup.zip`)
* Configuration files (`/config.php`)
* Developer test pages (`/test.php`)

These resources may contain vulnerabilities if not properly secured.

---

## Real Scenario: Hidden Admin Panel

Assume a site has a hidden file:

```
http://target.com/hidden_admin_panel.php
```

No links point to it.

You run:

```bash
dirb http://target.com /usr/share/wordlists/dirb/common.txt -X .php
```

Output shows:

```
+ http://target.com/hidden_admin_panel.php (CODE:200|SIZE:5421)
```

This indicates the file exists and is accessible.

---

## When `dirb` May Not Work Well

* If the server has **rate limiting** or **WAF** (Web Application Firewall).
* If the resources are behind **authentication or sessions**.
* If you want faster scanning, consider using `gobuster` or `ffuf`.

---

## Quick Comparison

| Tool       | Speed     | Multithreading | Beginner Friendly | Best For                       |
| ---------- | --------- | -------------- | ----------------- | ------------------------------ |
| `dirb`     | Slow      | No             | Yes               | Learning and basic scans       |
| `gobuster` | Fast      | Yes            | Intermediate      | Speed and customization        |
| `ffuf`     | Very fast | Yes            | Advanced          | API endpoints and JSON support |

---
