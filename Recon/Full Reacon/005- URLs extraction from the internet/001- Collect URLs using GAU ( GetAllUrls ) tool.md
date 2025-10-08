## **1. What is GAU?**

**GAU** (short for **GetAllUrls**) is a command-line tool that collects all known URLs associated with a given domain or subdomain from **public data archives** and **web indexing services**.

It was created by **LukaS** and is now part of the **ProjectDiscovery** ecosystem — a suite of powerful tools for bug bounty hunters and penetration testers.

GAU helps you find:

* Old or forgotten endpoints
* Hidden directories and files
* APIs and parameterized URLs
* Archived or outdated routes (which might still be exploitable)

---

## **2. Why Use GAU?**

In **bug bounty** or **web application penetration testing**, recon is all about **finding as much attack surface as possible**.
GAU helps by discovering URLs that:

* Are no longer linked on the main website
* Still exist in old archives
* Contain parameters useful for XSS, LFI, SQLi, or IDOR testing

It’s **fast**, **passive**, and integrates easily with other tools like `httpx`, `gf`, `nuclei`, and `waybackurls`.

---

## **3. How GAU Works**

GAU queries multiple **passive sources** (no direct requests to the target):

| Source               | Description                                |
| -------------------- | ------------------------------------------ |
| **Common Crawl**     | Massive internet archive updated regularly |
| **Wayback Machine**  | Historical snapshots of websites           |
| **URLScan.io**       | Scans and indexes URLs for analysis        |
| **OTX (AlienVault)** | Community threat intelligence database     |

When you run GAU, it searches those sources for all URLs that contain your domain (e.g., `example.com`).

Example:

```bash
gau example.com
```

Output:

```
https://example.com/login
https://example.com/api/v1/user
https://cdn.example.com/js/main.js
https://test.example.com/admin
```

---

## **4. Installation**

### **Using Go**

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

Make sure your `$GOPATH/bin` is added to your `$PATH`.

### **Verify Installation**

```bash
gau -h
```

If you see the help menu, you’re ready to go.

---

## **5. Basic Usage**

### **Single Domain**

```bash
gau example.com
```

### **Multiple Domains**

```bash
gau example.com google.com
```

### **From a File**

```bash
cat domains.txt | gau --threads 5
```

### **Save Output**

```bash
gau --o example-urls.txt example.com
```

### **Blacklist File Extensions**

```bash
gau --blacklist png,jpg,gif example.com
```

### **Get Help Menu**

```bash
gau -h
```

---

## **6. Usage Examples**

| Command                                     | Description                                    |
| ------------------------------------------- | ---------------------------------------------- |
| `$ printf example.com \| gau`               | Fetch URLs for a single domain                 |
| `$ cat domains.txt \| gau --threads 5`      | Process multiple domains from a file           |
| `$ gau example.com google.com`              | Fetch URLs for multiple domains in one command |
| `$ gau --o example-urls.txt example.com`    | Save output to a file                          |
| `$ gau --blacklist png,jpg,gif example.com` | Skip certain file types (reduce noise)         |

---

## **7. Flags and Options**

| **Flag**      | **Description**                                                                             | **Example**                                 |
| ------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `--blacklist` | List of extensions to skip                                                                  | `gau --blacklist ttf,woff,svg,png`          |
| `--config`    | Use alternate configuration file (default `$HOME/config.toml` or `%USERPROFILE%\.gau.toml`) | `gau --config $HOME/.config/gau.toml`       |
| `--fc`        | List of status codes to filter (exclude)                                                    | `gau --fc 404,302`                          |
| `--from`      | Fetch URLs from date (format: YYYYMM)                                                       | `gau --from 202101`                         |
| `--ft`        | List of MIME types to filter (exclude)                                                      | `gau --ft text/plain`                       |
| `--fp`        | Remove different parameters of the same endpoint                                            | `gau --fp`                                  |
| `--json`      | Output as JSON                                                                              | `gau --json example.com`                    |
| `--mc`        | List of status codes to match (include only these)                                          | `gau --mc 200,500`                          |
| `--mt`        | List of MIME types to match                                                                 | `gau --mt text/html,application/json`       |
| `--o`         | Filename to write results to                                                                | `gau --o out.txt`                           |
| `--providers` | List of providers to use (`wayback`, `commoncrawl`, `otx`, `urlscan`)                       | `gau --providers wayback`                   |
| `--proxy`     | HTTP proxy to use (`socks5://` or `http://`)                                                | `gau --proxy http://proxy.example.com:8080` |
| `--retries`   | Number of retries for HTTP client                                                           | `gau --retries 10`                          |
| `--timeout`   | Timeout (in seconds) for HTTP client                                                        | `gau --timeout 60`                          |
| `--subs`      | Include subdomains of target domain                                                         | `gau example.com --subs`                    |
| `--threads`   | Number of workers to spawn                                                                  | `gau example.com --threads 10`              |
| `--to`        | Fetch URLs to date (format: YYYYMM)                                                         | `gau example.com --to 202101`               |
| `--verbose`   | Show verbose output                                                                         | `gau --verbose example.com`                 |
| `--version`   | Show GAU version                                                                            | `gau --version`                             |

---

## **8. Filtering and Post-Processing**

You can combine GAU with UNIX commands to refine results.

### **Filter Parameterized URLs**

```bash
gau example.com | grep "=" > params.txt
```

Example output:

```
https://example.com/search?q=test
https://example.com/api?id=42
```

### **Remove Duplicates**

```bash
gau example.com | sort -u > clean_urls.txt
```

### **Filter by File Extension**

```bash
gau example.com | grep "\.js$"
gau example.com | egrep "\.(php|aspx|jsp)$"
```

### **Remove Images and Static Files**

```bash
gau example.com | egrep -v "\.(jpg|jpeg|png|gif|svg|ico)$"
```

---

## **9. Chaining GAU with Other Tools**

GAU becomes powerful when used in pipelines.

### **(a) GAU → HTTPX**

Check which URLs are alive:

```bash
gau example.com | httpx -silent -status-code
```

Example output:

```
https://example.com/login [200]
https://admin.example.com [403]
```

---

### **(b) GAU → GF → Dalfox**

Find potential XSS points:

```bash
gau example.com | grep "=" | gf xss | dalfox pipe
```

---

### **(c) GAU + Waybackurls**

Combine both for maximum coverage:

```bash
gau example.com > gau.txt
waybackurls example.com > wayback.txt
cat gau.txt wayback.txt | sort -u > combined.txt
```

---

## **10. Example Real Workflow**

### Step 1: Get Subdomains

```bash
subfinder -d example.com -silent > subs.txt
```

### Step 2: Get URLs from All Subdomains

```bash
cat subs.txt | gau --threads 10 > all_urls.txt
```

### Step 3: Filter Parameterized URLs

```bash
cat all_urls.txt | grep "=" > params.txt
```

### Step 4: Check Live URLs

```bash
cat all_urls.txt | httpx -silent -status-code -mc 200,403,500 > live_urls.txt
```

### Step 5: Scan with Nuclei or Dalfox

```bash
cat params.txt | gf xss | dalfox pipe
```

---

## **11. Example Output**

```bash
$ gau example.com | head -n 10
https://example.com/login
https://example.com/register
https://api.example.com/v1/user?id=12
https://cdn.example.com/js/main.js
https://test.example.com/admin
https://example.com/contact?ref=home
```

---

## **12. Advantages and Limitations**

| **Advantages (✅)**                     | **Limitations (⚠️)**                  |
| -------------------------------------- | ------------------------------------- |
| Fast, passive, and reliable            | Some URLs may be outdated or 404      |
| Covers historical and hidden endpoints | May include irrelevant assets         |
| Works well with automation             | Doesn’t find new/undiscovered URLs    |
| Supports subdomain inclusion           | Requires filtering for useful results |

---

## **13. Summary **

| Feature          | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| **Tool Name**    | GAU (GetAllUrls)                                                 |
| **Purpose**      | Collect all known URLs for a given domain                        |
| **Method**       | Passive (uses public archives)                                   |
| **Sources**      | Wayback, Common Crawl, OTX, URLScan                              |
| **Installation** | `go install github.com/lc/gau/v2/cmd/gau@latest`                 |
| **Best Use**     | Recon and finding hidden endpoints                               |
| **Output**       | URLs (optionally JSON)                                           |
| **Integration**  | Works well with `httpx`, `gf`, `nuclei`, `waybackurls`, `dalfox` |

---

For best results:

1. Combine it with subdomain tools (`subfinder`, `amass`)
2. Filter with `grep`, `sort`, and `uniq`
3. Chain with `httpx`, `gf`, and `nuclei`
4. Focus on parameterized endpoints for testing

Example workflow:

```
subfinder → gau → httpx → gf → dalfox/nuclei
```
