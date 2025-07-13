<p align="center">
  <img src="https://github.com/user-attachments/assets/de70db1e-e60d-4865-8237-e4b0ee28b1bc" alt="ffuf" width="100%">
</p>

---

##  What is Fuzzing?

**Fuzzing** is a powerful software testing technique used to identify bugs, misconfigurations, and security vulnerabilities. It works by sending unexpected, invalid, or random input to a program, web application, or server, then monitoring how it behaves. If the system reacts in an unusual way — such as crashing, exposing errors, or leaking data — that could indicate a vulnerability.

In real-world bug bounty and penetration testing, fuzzing is often used to:

* Discover **hidden directories or files** not intended for public access
* Identify **undocumented parameters** in URLs or forms (e.g., `debug=true`, `test=1`)
* Detect **vulnerable input fields** that can be abused for injection attacks
* Find **user IDs** or sensitive endpoints via bruteforce (e.g., `/user/123`, `/invoice/999`)

Think of fuzzing as **trial-and-error at scale**, done automatically using tools and curated wordlists.

---

##  What is ffuf?

**ffuf** ("Fuzz Faster U Fool") is a high-performance, flexible, and user-friendly tool specifically designed for HTTP-based fuzzing.

ffuf allows you to:

* Brute-force **directories** and **files** on a web server
* Test for **parameter discovery**
* Fuzz **POST request bodies** or **JSON payloads**
* Brute-force **virtual hosts**
* Inject and fuzz **custom headers**

It supports filtering by status code, content length, word count, and response size. It also handles recursion, auto-calibration, and allows for very fast multi-threaded fuzzing.

---

##  Basic Usage of ffuf

###  Goal: Discover Hidden Directories

```bash
ffuf -u https://example.com/FUZZ -w /path/to/wordlist.txt
```

* `-u`: Specifies the target URL, using `FUZZ` as a placeholder for the wordlist input.
* `-w`: Specifies the wordlist file to use. Each line in this file is inserted in place of `FUZZ`.

This will test paths like `https://example.com/admin`, `https://example.com/login`, etc.

---

##  Using Wordlists

Wordlists are at the heart of fuzzing. Better wordlists often lead to better results.

Common sources include:

* **SecLists**: A well-known repository of curated lists (paths, extensions, parameters, etc.)
* Custom lists generated from recon tools like `gau`, `waybackurls`, or `hakrawler`
* Project-specific wordlists from JavaScript or source code analysis

Example:

```bash
ffuf -u https://target.com/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt
```

---

##  Filtering by Status Codes

Use the `-mc` (match codes) option to only show results with specific HTTP status codes:

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,204,301,302,403,405,415
```

This ensures you don't miss paths that respond with important non-200 codes (e.g., `403 Forbidden` or `401 Unauthorized`).

---

##  Recursive Fuzzing

Enable recursion to automatically fuzz discovered directories:

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion
```

If `https://target.com/admin/` is found, ffuf will automatically run:
`https://target.com/admin/FUZZ`

---

##  Adding File Extensions

You can append file extensions using the `-e` flag:

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.log,.bak
```

This will test `debug.php`, `debug.log`, `debug.bak`, etc.

---

##  Fuzzing Parameters (GET Requests)

Fuzzing hidden parameters can reveal debug modes or admin functions:

```bash
ffuf -u https://target.com/page.php?FUZZ=test -w parameters.txt
```

You might discover parameters like:

* `debug`
* `test`
* `env`
* `auth`

---

##  Filtering by Response Size or Words

Useful for detecting duplicate responses:

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1024
ffuf -u https://target.com/FUZZ -w wordlist.txt -fw 123
```

* `-fs`: Filters out responses of a specific byte size
* `-fw`: Filters out responses with a specific word count

---

##  Auto Calibration

To automatically ignore pages with wildcard or generic responses:

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -ac
```

This helps ffuf detect and ignore pages that return false positives (e.g., custom 404 pages).

---

##  Speeding Up the Scan

Increase the number of threads (default is 40):

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -t 100
```

* Higher threads = faster scans, but can overwhelm small servers.

---

##  Advanced Features

### 1. HTTP Methods (POST Fuzzing)

```bash
ffuf -X POST -u https://target.com/login -w creds.txt -d "username=admin&password=FUZZ"
```

* `-X`: HTTP method
* `-d`: POST body

### 2. Header Injection / Header Fuzzing

```bash
ffuf -u https://target.com/ -H "FUZZ: test" -w headers.txt
ffuf -u https://target.com/admin -H "X-Forwarded-For: FUZZ" -w ips.txt
```

### 3. Virtual Host Fuzzing

```bash
ffuf -u http://1.2.3.4/ -H "Host: FUZZ.example.com" -w subdomains.txt
```

Useful for bypassing host-based routing.

### 4. JSON API Fuzzing

```bash
ffuf -X POST -u https://target.com/api -H "Content-Type: application/json" -w words.txt -d '{"param": "FUZZ"}'
```

For APIs accepting JSON data.

### 5. Multiple FUZZ Placeholders

```bash
ffuf -u https://target.com/FUZZ/FIZZ -w list1.txt:FUZZ -w list2.txt:FIZZ
```

Supports complex payload combinations.

### 6. Output and Result Formatting

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json
```

* `-o`: Output file
* `-of`: Output format (json, csv, html, etc.)

### 7. Integration with Recon Workflows

```bash
cat domains.txt | ffuf -u https://FUZZ.example.com -w sublist.txt -mc 200 -o found.json
jq '.results[] | .url' found.json
```

Can be integrated into bash scripts and automation pipelines.

---

##  Tools Similar to ffuf

| Tool                        | Notes                                        |
| --------------------------- | -------------------------------------------- |
| **wfuzz**                   | Advanced injection and multiple placeholders |
| **gobuster**                | Simple and fast                              |
| **feroxbuster**             | Rust-based, supports recursion well          |
| **dirsearch**               | Quick and practical                          |
| **Burp/Kaydo/ZAP Intruder** | UI-based fuzzing with filters                |

---

##  Common Mistakes to Avoid

| Mistake                 | Why It's a Problem                                                     |
| ----------------------- | ---------------------------------------------------------------------- |
| Only matching 200 codes | You may miss 403, 401, or 415 which reveal blocked but valid paths     |
| Ignoring response size  | Wildcard 404 pages return identical sizes — leading to false positives |
| Not using recursion     | You miss content inside discovered folders                             |
| Not fuzzing headers     | May overlook header-based authentication bypass                        |
| Not saving output       | You lose valuable results after terminal closes                        |

---


## Wordlist Resources


### 1. SecLists

* **Name**: SecLists
* **GitHub**: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
* **Clone**:

  ```bash
  git clone https://github.com/danielmiessler/SecLists.git
  ```

---

### 2. OneListForAll

* **Name**: OneListForAll
* **GitHub**: [https://github.com/six2dez/OneListForAll](https://github.com/six2dez/OneListForAll)
* **Clone**:

  ```bash
  git clone https://github.com/six2dez/OneListForAll.git
  ```

---

### 3. PayloadsAllTheThings

* **Name**: PayloadsAllTheThings
* **GitHub**: [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* **Clone**:

  ```bash
  git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
  ```

---

