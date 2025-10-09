
## 1. What is ParamSpider?

**ParamSpider** is an open-source tool designed for **collecting URLs that contain parameters** from a given target domain.

It’s mainly used by **bug bounty hunters** and **web penetration testers** to:

* Discover endpoints with **query parameters**, which are often **potential injection points** (for example, XSS, SQLi, SSRF, or LFI).
* Gather **dynamic URLs** from multiple sources, such as search engines and archive platforms, to enhance the recon and fuzzing process.

> **ParamSpider helps you find URLs like `https://target.com/page.php?id=123` that can later be tested for vulnerabilities.**

---

## 2. Why is ParamSpider Important?

When doing recon, discovering **parameters** is crucial because:

* Parameters often interact with backend logic.
* Many **vulnerabilities** (like XSS or SQL Injection) exist due to improper parameter handling.
* Automated tools (like `paramspider`, `gau`, `waybackurls`, etc.) help save hours of manual crawling.

So, ParamSpider is usually used **after subdomain enumeration** to dig deeper into each subdomain for parameterized URLs.

---

## 3. How ParamSpider Works

ParamSpider uses:

* **Search engines** (like Bing, Yahoo, Ask, etc.)
* **Wayback Machine (Internet Archive)**
* **CommonCrawl dataset**

to passively gather URLs belonging to your domain.
Then, it **filters** only the ones containing a `?` character (indicating a parameter).

It does **not send requests to the target**, so it’s considered **passive enumeration** — safe and stealthy.

---

## 4. Installation

You can install ParamSpider easily from GitHub.

### Step 1 — Clone the Repository

```bash
git clone https://github.com/devanshbatham/ParamSpider.git
```

### Step 2 — Change Directory

```bash
cd ParamSpider
```

### Step 3 — Install Requirements

```bash
pip3 install -r requirements.txt
```

This will install Python libraries needed for crawling and parsing (like `requests`, `tldextract`, etc.).

---

## 5. Basic Usage

### Syntax

```bash
python3 paramspider.py -d <domain>
```
## OR 
```bash
paramspider -d <domain>
```

### Example

```bash
python3 paramspider.py -d example.com
```

This will start gathering URLs from multiple sources and automatically filter out URLs containing parameters.

The output file is usually saved in:

```
results/example.com.txt
```

---

## 6. Command-Line Options and Flags

| Flag        | Description                                                        | Example                         |
| ----------- | ------------------------------------------------------------------ | ------------------------------- |
| `-d`        | Specify the **domain** to scan                                     | `-d example.com`                |
| `-l`        | Specify a **list of domains** from a file                          | `-l domains.txt`                |
| `-o`        | Output file name (optional, not built-in in old versions)          | `-o params.txt`                 |
| `-s`        | Include **subdomains** in results                                  | `-s`                            |
| `--exclude` | Exclude certain subdomains or keywords                             | `--exclude dev,test,staging`    |
| `--level`   | Crawl level (default: 1)                                           | `--level 2`                     |
| `--proxy`   | Use a proxy (HTTP or SOCKS5)                                       | `--proxy http://127.0.0.1:8080` |
| `-p`        | Placeholder to replace parameter values (e.g., fuzzing-ready URLs) | `-p FUZZ`                       |

---

## 7. Common Examples

### Example 1 — Basic Scan

```bash
python3 paramspider.py -d example.com
```

Collects parameterized URLs from `example.com`.

---

### Example 2 — Include Subdomains

```bash
python3 paramspider.py -d example.com -s
```

Finds URLs with parameters **across subdomains** like:

* `api.example.com`
* `blog.example.com`

---

### Example 3 — Exclude Unwanted Subdomains

```bash
python3 paramspider.py -d example.com --exclude test,dev,staging
```

This skips URLs that belong to testing or development environments.

---

### Example 4 — Replace Parameter Values

```bash
python3 paramspider.py -d example.com -p FUZZ
```

This outputs URLs like:

```
https://example.com/page.php?id=FUZZ
```

which can be directly used with fuzzers such as `ffuf` or `x8`.

---

## 8. Filtering the Output with `grep` and `awk`

After running ParamSpider, you’ll get a large list of URLs in a text file (e.g., `results/example.com.txt`).
You can filter and organize them using Linux command-line tools:

### A. Show only URLs with parameters

```bash
cat results/example.com.txt | grep '?' | tee parameters.txt
```

* `cat` reads the file.
* `grep '?'` filters only lines containing a `?` (which means they have parameters).
* `tee parameters.txt` saves them into a new file while also displaying them on the screen.

---

### B. Show only JavaScript files

```bash
cat results/example.com.txt | grep -E "\.js" | tee js_files.txt
```

* `grep -E` enables extended regular expressions.
* `\.js` matches `.js` files.
* Useful for **JavaScript recon**, where you look for endpoints or secrets inside JavaScript files.

---

### C. Count how many URLs collected

```bash
cat results/example.com.txt | wc -l
```

This tells you how many URLs ParamSpider found for the target.

---

### D. Use `awk` for cleaner formatting

If you want to remove duplicates or filter out specific patterns:

```bash
cat results/example.com.txt | awk '!seen[$0]++' > unique_urls.txt
```

This keeps only **unique** URLs.

Or, if you want to extract only domains:

```bash
cat results/example.com.txt | awk -F/ '{print $3}' | sort -u > domains.txt
```

---

## 9. Example Workflow (Practical Scenario)

Here’s how a typical recon workflow looks with ParamSpider:

```bash
# Step 1: Run ParamSpider
python3 paramspider.py -d example.com -s

# Step 2: Extract parameterized URLs
cat results/example.com.txt | grep '?' | tee parameters.txt

# Step 3: Extract JS files
cat results/example.com.txt | grep -E "\.js" | tee js_files.txt

# Step 4: Count total URLs
cat results/example.com.txt | wc -l

# Step 5: Check for live URLs (optional)
cat results/example.com.txt | httpx -silent -mc 200 | tee live_urls.txt
```

This gives you:

* `parameters.txt` → URLs for testing injection points
* `js_files.txt` → JavaScript files for further analysis
* `live_urls.txt` → Active endpoints

---

## 10. Summary

| Step              | Command                                   | Output             |
| ----------------- | ----------------------------------------- | ------------------ |
| Run ParamSpider   | `python3 paramspider.py -d target.com -s` | Collect URLs       |
| Filter parameters | `grep '?'`                                | Parameterized URLs |
| Filter JS files   | `grep -E '\.js'`                          | JavaScript URLs    |
| Count results     | `wc -l`                                   | Number of URLs     |
| Remove duplicates | `awk '!seen[$0]++'`                       | Unique URLs        |

---

## 11. Notes

* **ParamSpider** works best when combined with tools like:

  * `gau` (to get archived URLs)
  * `waybackurls`
  * `katana`
  * `httpx` (for validation)
* It is **passive**, meaning no direct requests to the target.
* Always respect **legal and scope boundaries** in bug bounty programs.

