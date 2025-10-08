

When performing **recon** or **bug bounty enumeration**, you usually end up with a large list of URLs (for example, from `gau` or `gospider`).
Before moving to testing or fuzzing, you need to **filter and organize** these URLs based on patterns, extensions, or parameters.
That’s where **`grep`** and **`awk`** come in.

---

## 1. **Using `grep`**

`grep` is a text-search tool that allows you to **filter lines containing specific patterns**.

### **Basic Syntax**

```bash
grep [options] 'pattern' filename
```

### **Example 1 — Filter URLs with parameters**

If you have a file named `urls.txt` containing thousands of URLs:

```bash
cat urls.txt | grep "?" | tee parameters.txt
```

#### **Explanation**

* `cat urls.txt` → reads all URLs from the file.
* `grep "?"` → searches for URLs that contain `?`, meaning they have parameters (like `id=1`, `page=2`, etc.).
* `tee parameters.txt` → saves the filtered results into a new file called `parameters.txt` while also displaying them on the terminal.

#### **Result**

The `parameters.txt` file now contains only URLs that have parameters, which are valuable for testing:

```
https://example.com/profile.php?id=2
https://test.example.com/page?user=admin
```

---

### **Example 2 — Extract all JavaScript files**

```bash
cat urls.txt | grep -E "\.js$" | tee js_files.txt
```

#### **Explanation**

* `grep -E` → enables **Extended Regular Expressions (ERE)**, allowing more complex patterns.
* `"\.js$"` → matches lines ending with `.js` (the backslash escapes the dot).
* `tee js_files.txt` → saves the result into a file named `js_files.txt`.

#### **Result**

Now `js_files.txt` contains only JavaScript file links:

```
https://example.com/assets/app.js
https://cdn.example.net/main.min.js
```

> 💡 **Tip:** JavaScript files are great sources for discovering hidden endpoints, API keys, or sensitive paths.

---

## 2. **Using `awk`**

`awk` is a powerful command-line tool for text processing.
It can extract, modify, or filter specific columns or patterns from structured text.

### **Basic Syntax**

```bash
awk 'condition {action}' filename
```

---

### **Example 1 — Filter URLs from a specific domain**

```bash
awk '/example\.com/' urls.txt > example_urls.txt
```

#### **Explanation**

* `/example\.com/` → matches any line containing “example.com”.
* `>` → redirects the matched lines into a new file `example_urls.txt`.

---

### **Example 2 — Print only unique hostnames**

If you have URLs and want to extract only the base domains:

```bash
awk -F/ '{print $3}' urls.txt | sort -u > unique_hosts.txt
```

#### **Explanation**

* `-F/` → sets the field separator as `/`.
  For a URL like `https://www.example.com/page`, the parts are:

  * `$1` = `https:`
  * `$2` = (empty, because of `//`)
  * `$3` = `www.example.com`
* `{print $3}` → prints the hostname only.
* `sort -u` → sorts results and removes duplicates.
* The final result in `unique_hosts.txt` is:

  ```
  example.com
  www.example.com
  api.example.com
  ```

---

### **Example 3 — Filter only `.php` URLs**

```bash
awk '/\.php/' urls.txt > php_urls.txt
```

This filters all URLs that contain “.php” — useful when looking for dynamic pages that may contain parameters or be vulnerable to injection.

---

### **Example 4 — Combine `awk` and `grep`**

You can chain both tools for advanced filtering:

```bash
cat urls.txt | grep "?" | awk '/\.php/ {print $0}' | tee php_params.txt
```

#### **Explanation**

* `grep "?"` → gets all URLs with parameters.
* `awk '/\.php/'` → filters only those that contain `.php`.
* `tee php_params.txt` → saves the result to a new file.

Result: only PHP URLs that contain parameters — perfect for testing things like **SQLi**, **LFI**, or **XSS**.

---

## 3. **Useful Filtering Patterns**

| Goal                               | Command                              |          |
| ---------------------------------- | ------------------------------------ | -------- |
| URLs with parameters               | `grep "?" urls.txt`                  |          |
| JavaScript files                   | `grep -E "\.js$" urls.txt`           |          |
| PHP files                          | `grep "\.php" urls.txt`              |          |
| JSON endpoints                     | `grep "\.json" urls.txt`             |          |
| Filter subdomain `api.example.com` | `grep "api.example.com" urls.txt`    |          |
| Remove duplicates                  | `sort -u urls.txt > unique_urls.txt` |          |
| Extract hostnames only             | `awk -F/ '{print $3}' urls.txt       | sort -u` |

---

## 4. **Counting Results**

After filtering, you can count how many lines (URLs) you have:

```bash
wc -l parameters.txt
```

This tells you the total number of URLs containing parameters.

---

## 5. **Putting It All Together**

Let’s say you ran `gau` or `gospider` and got `urls.txt`.
Here’s a simple post-processing workflow:

```bash
# 1. Filter URLs with parameters
cat urls.txt | grep "?" | tee parameters.txt

# 2. Filter JavaScript files
cat urls.txt | grep -E "\.js$" | tee js_files.txt

# 3. Extract only PHP URLs with parameters
cat urls.txt | grep "?" | awk '/\.php/' | tee php_params.txt

# 4. Count total collected URLs
wc -l urls.txt
```
