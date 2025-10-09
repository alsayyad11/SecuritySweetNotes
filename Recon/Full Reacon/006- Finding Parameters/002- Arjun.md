

## **1. What is Arjun?**

**Arjun** is a powerful tool used to **discover hidden GET and POST parameters** in web applications.
When you visit a website, you might see parameters in the URL like:

```
https://example.com/page.php?id=10
```

Here, `id` is a **GET parameter**. But often, there are **hidden parameters** that aren’t visible in the URLs — they may be used internally or for specific features like search, filters, or admin actions.

**Arjun** helps you **discover those hidden parameters** by **sending multiple requests** with different parameter names and analyzing the server’s response to identify which parameters seem valid or trigger a change.

---

## **2. Why Do We Use Arjun?**

During recon or testing, after you find URLs (for example using `gau`, `waybackurls`, `gospider`, etc.), you might want to check if the endpoint accepts **extra hidden parameters** that could reveal new functionality or vulnerabilities.

This is very useful for finding:

* Parameters that might be vulnerable to **SQL Injection**
* Hidden **debug** or **test** parameters
* Parameters that trigger **file uploads** or **path traversal**
* **Bypass parameters** used internally by the backend

---

## **3. Installation**

Arjun is written in **Python**, so you can install it easily using **pip**.

```bash
pip install arjun
```

Or clone it directly from GitHub:

```bash
git clone https://github.com/s0md3v/Arjun.git
cd Arjun
python3 arjun.py
```

After installation, you can verify it works by running:

```bash
arjun -h
```

This will show the help menu with all options.

---

## **4. Basic Usage**

The most basic command to run Arjun on a target domain is:

```bash
arjun -u https://example.com
```

This means:

* `-u` → the **target URL** to test for parameters

Arjun will send requests with common parameter names (like `id`, `q`, `page`, `search`, etc.) and monitor the response length and behavior.
If it detects a difference (for example, response size changes), it assumes that parameter exists.

---

## **5. Example: Finding Parameters**

Let’s say we have this URL:

```
https://test.com/api.php
```

You can run:

```bash
arjun -u https://test.com/api.php
```

Output might look like:

```
Analyzing: https://test.com/api.php
Found: q, search, filter
```

This means the endpoint responds differently when parameters like `q`, `search`, or `filter` are used — so those parameters **probably exist** and are processed by the server.

---

## **6. Testing Multiple URLs**

If you already have a list of URLs (for example from `gau` or `paramspider`), you can scan them all with Arjun using a file:

```bash
arjun -i urls.txt
```

Here:

* `-i` specifies the **input file** containing URLs (one per line).

---

## **7. Output Results to a File**

You can save the discovered parameters to a file for later analysis:

```bash
arjun -u https://test.com/api.php -o results.json
```

or

```bash
arjun -i urls.txt -o results.txt
```

Arjun can output in both **JSON** and **plain text** formats.

---

## **8. Discovering POST Parameters**

By default, Arjun checks **GET** parameters (parameters in the URL).
To discover **POST** parameters (parameters in the request body, like in login forms), use:

```bash
arjun -u https://example.com/login -m POST
```

Here:

* `-m` specifies the **HTTP method** (POST in this case).

This helps you find parameters that might be hidden in form submissions.

---

## **9. Speed and Threads**

If you want to make Arjun run faster (for example when scanning multiple URLs), you can increase the number of threads:

```bash
arjun -u https://example.com -t 10
```

* `-t 10` means using **10 concurrent threads** to speed up the scan.
  Be cautious though — high thread counts might cause rate limits or WAF blocking.

---

## **10. Using Custom Wordlists**

By default, Arjun uses its own parameter wordlist, which is large and optimized.
But you can also use your **own custom wordlist** of parameter names.

Example:

```bash
arjun -u https://example.com -w custom_params.txt
```

This is useful if you have collected specific parameter names from previous recon or other sources.

---

## **11. Practical Workflow Example**

Let’s see how Arjun fits into a **real recon pipeline**:

1. **Collect URLs:**

   ```bash
   gau example.com | tee urls.txt
   ```

   This gathers all URLs related to `example.com`.

2. **Filter dynamic URLs:**

   ```bash
   cat urls.txt | grep "?" | tee params_urls.txt
   ```

   These are URLs that already have parameters.

3. **Run Arjun:**

   ```bash
   arjun -i params_urls.txt -o arjun_results.txt
   ```

   This will check all parameterized URLs for additional hidden parameters.

4. **Review discovered parameters:**
   You can then test the discovered parameters for vulnerabilities like XSS, SQLi, or SSRF.

---

## **12. Summary**

| Feature          | Description                             |
| ---------------- | --------------------------------------- |
| **Tool Name**    | Arjun                                   |
| **Author**       | s0md3v                                  |
| **Purpose**      | Discover hidden GET and POST parameters |
| **Language**     | Python                                  |
| **Usage**        | `arjun -u <URL>` or `arjun -i <file>`   |
| **Supports**     | GET, POST methods                       |
| **Outputs**      | JSON, Text                              |
| **Common Flags** | `-u`, `-i`, `-o`, `-m`, `-t`, `-w`      |

---

## **13. Example Summary Commands**

```bash
# Scan a single URL
arjun -u https://target.com

# Scan multiple URLs from file
arjun -i urls.txt

# Save results to file
arjun -u https://target.com -o results.json

# Scan POST parameters
arjun -u https://target.com/login -m POST

# Use custom wordlist
arjun -u https://target.com -w params.txt
```
