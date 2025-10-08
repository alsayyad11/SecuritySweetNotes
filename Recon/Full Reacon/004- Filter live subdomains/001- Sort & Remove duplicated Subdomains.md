

When collecting subdomains from multiple sources, the resulting list often contains duplicates and is usually unordered. Keeping a clean, unique, and sorted list of subdomains is essential for further processing, such as scanning with tools like `httpx` or `nmap`. This guide explains how to sort subdomains, remove duplicates, and count the unique entries using Linux command-line tools.

---

## 1. Basic Concept

The main goals are:

1. **Sort the subdomains alphabetically** – this makes the list organized and easier to read or compare.
2. **Remove duplicates** – eliminates repeated entries to avoid unnecessary scanning or analysis.
3. **Count unique subdomains** – helps track how many distinct subdomains you have.

---

## 2. Using `cat`, `sort`, and `uniq`

Suppose you have multiple files containing subdomains:

```
subdomains1.txt
subdomains2.txt
subdomains3.txt
```

You can combine them, sort them, and remove duplicates as follows:

```bash
cat subdomains*.txt | sort -u > sorted_subdomains.txt
```

### OR 

```bash
cat * | sort -u > sorted_subdomains.txt
```

### Explanation:

* `cat subdomains*.txt`
  Reads the contents of all files matching the pattern `subdomains*.txt`.

* `sort -u`

  * `sort` → arranges the lines alphabetically.
  * `-u` → removes duplicate lines automatically.

* `> sorted_subdomains.txt`
  Saves the output to a new file called `sorted_subdomains.txt`.

---

## 3. Counting Unique Subdomains

To quickly check how many unique subdomains you have **without creating a file**, you can use:

```bash
cat * | sort -u | wc -l
```

### Step-by-Step:

1. `cat *` → combines the contents of all files in the current directory into a single stream.
2. `sort -u` → sorts the combined lines alphabetically and removes duplicates.
3. `wc -l` → counts the number of lines, giving you the **total number of unique subdomains**.

Example:

```
subdomains1.txt:      subdomains2.txt:
example.com           test.example.com
demo.example.com      example.com
```

Command output:

```
cat * | sort -u | wc -l
3
```

This shows there are **3 unique subdomains** across the files.

---

## 4. Handling Subdomain Lists with Extra Details

Sometimes subdomain lists include extra information, such as DNS records:

```
xray.highway.porsche.com (FQDN) --> a_record --> 84.21.32.154
your.porsche.com (FQDN) --> cname_record --> yourporsche.onlinemedianet.de
956.porsche.com
abeo-dev.dpp.porsche.com
```

If you want **only the clean subdomains**, you can use `grep` with a regular expression:

```bash
grep -Eo '([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}' all_subdomains.txt | sort -u > subdomains_only.txt
```

### Explanation:

* `grep -Eo` → searches using Extended Regex and prints only the matching part.
* `([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}` → matches valid domain/subdomain patterns.
* `sort -u` → sorts alphabetically and removes duplicates.
* `> subdomains_only.txt` → saves the cleaned list in a new file.

---

## 5. Summary Workflow

1. Collect subdomains from multiple sources (tools, APIs, etc.).
2. Combine all files into one list.
3. Remove duplicates and sort the list.
4. Optionally, filter out any extra DNS information to keep only the subdomain names.
5. Count unique entries using `cat * | sort -u | wc -l`.
6. Save the cleaned list for use in further scanning.

---
