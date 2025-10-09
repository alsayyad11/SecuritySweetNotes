
## What is Archive.org?

**Archive.org** is a non-profit digital library that stores historical versions of websites, books, videos, audio files, and more.
For cybersecurity researchers and bug bounty hunters, the most important feature is the **Wayback Machine**, which allows you to view and retrieve **older versions of websites**.

In other words, it lets you see what a website looked like in the past — including old pages, JavaScript files, and parameters that might no longer exist today but could still be useful for reconnaissance.

---

## The Wayback Machine

The **Wayback Machine** takes snapshots of websites at different points in time.
Each snapshot captures:

* The HTML source code of the page.
* Linked assets like JavaScript, CSS, and images.
* Sometimes, URL query parameters and file names.

You can manually access the Wayback Machine through:
**[https://web.archive.org/](https://web.archive.org/)**

Or use this format to explore archived versions of a specific domain:

```
https://web.archive.org/web/*/https://example.com/*
```

This view allows you to choose from different timestamps (years, months, and days) to see how the website evolved over time.

---

## Why It’s Useful in Bug Bounty or Reconnaissance

The Wayback Machine is extremely valuable during **passive reconnaissance**, because it can reveal information that is no longer publicly accessible. Some key use cases include:

1. **Discovering old endpoints**
   You might find endpoints like `/admin_old`, `/debug.php`, or `/beta/` that are no longer visible on the live site but could still exist on the backend.

2. **Finding old parameters**
   Historical URLs may contain query parameters such as `?id=`, `?user=`, `?file=`, or `?redirect=` which are often potential vectors for vulnerabilities like XSS, SQLi, or open redirects.

3. **Recovering deleted or hidden files**
   Files like `/backup.zip`, `/config.old`, `/test.php`, or `/staging/` might appear in archived versions but not in the current one.

4. **Identifying technology changes**
   By comparing old and new versions, you can see if a site switched from, for example, **WordPress to a custom CMS** or changed server frameworks. This can guide your testing strategy.

5. **Collecting old JavaScript files**
   Old JS files often contain API endpoints, internal IPs, or credentials that were accidentally exposed in the past.

---

## Manual Usage Example

Let’s say your target is `example.com`.
You can open:

```
https://web.archive.org/web/*/https://example.com/*
```

You’ll get a calendar view with snapshots from different years.
Clicking on any date shows how the site looked at that time.

You might find URLs like:

* `https://example.com/admin_login.php`
* `https://example.com/index.php?debug=true`
* `https://example.com/js/app_old.js`

Even if these pages are not accessible now, they provide valuable clues for fuzzing or deeper exploration.

---

## Automating Archive.org Data Extraction

While you can browse the Wayback Machine manually, automation saves time. Several tools use Archive.org’s APIs to extract archived URLs efficiently.

---

### 1. `waybackurls`

**Developer:** Tomnomnom
**Purpose:** Fetches all known archived URLs for a given domain from the Wayback Machine.

**Installation:**

```bash
go install github.com/tomnomnom/waybackurls@latest
```

**Basic Usage:**

```bash
echo "example.com" | waybackurls > wayback.txt
```

This saves all archived URLs related to `example.com` in the file `wayback.txt`.

**Filtering Examples:**

```bash
cat wayback.txt | grep "?" > parameters.txt      # URLs containing parameters
cat wayback.txt | grep -E "\.js" > js_files.txt  # JavaScript files
cat wayback.txt | grep "admin" > admin_urls.txt  # Admin-related pages
```

---

### 2. `gau` (GetAllUrls)

**Developer:** lc/gau (GetAllURLs)
**Purpose:** Collects URLs not only from the Wayback Machine but also from sources like **Common Crawl**, **VirusTotal**, and **URLScan**.

**Installation:**

```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

**Usage:**

```bash
echo "example.com" | gau > allurls.txt
```

**Filtering Examples:**

```bash
cat allurls.txt | grep "?" | tee parameters.txt
cat allurls.txt | grep -E "\.js" | tee js_files.txt
```

These commands filter URLs that contain parameters or point to JavaScript files, which are often the first things a bug hunter inspects.

---

## Practical Example for Recon Workflow

Target: `porsche.com`

1. **Collect archived URLs**

   ```bash
   echo "porsche.com" | waybackurls > wayback_porsche.txt
   ```

2. **Filter parameterized URLs**

   ```bash
   cat wayback_porsche.txt | grep "?" | tee params.txt
   ```

3. **Filter JavaScript files**

   ```bash
   cat wayback_porsche.txt | grep -E "\.js" | tee js_files.txt
   ```

4. **Filter possible admin panels**

   ```bash
   cat wayback_porsche.txt | grep "admin" | tee admin_urls.txt
   ```

5. **Check which of the archived URLs are still live**

   ```bash
   cat wayback_porsche.txt | httpx -silent > live_urls.txt
   ```

---

## Combining Archive.org Data with Other Tools

After gathering URLs from the Wayback Machine, you can integrate them with other tools for deeper analysis:

* **ParamSpider / Arjun:** To detect hidden or unlisted parameters.
* **Httpx:** To validate which URLs are still active.
* **GF Patterns:** To match interesting endpoints (e.g., for XSS, SSRF, RCE).
* **Ffuf or Dirsearch:** To brute-force old paths or parameters found in archived data.

Example combination:

```bash
cat wayback.txt | httpx -silent | tee live.txt
cat live.txt | waybackurls | tee combined_urls.txt
```

---

## Tips for Efficient Use

1. Always check **old subdomains** from archived data — some might no longer resolve via DNS but still host content on the server.
2. Don’t skip **JavaScript files** — archived JS often exposes sensitive paths and internal endpoints.
3. Use `sort -u` to remove duplicates when merging multiple URL sources:

   ```bash
   cat wayback.txt gau.txt | sort -u > unique_urls.txt
   ```
4. Use **grep patterns** for specific technologies or file types:

   ```bash
   cat wayback.txt | grep -E "(\.php|\.aspx|\.jsp)" > tech_specific.txt
   ```

---

## Summary Table

| Purpose                        | Command Example                                    | Description                        |
| ------------------------------ | -------------------------------------------------- | ---------------------------------- |
| Get all archived URLs          | `echo "target.com" \| waybackurls > wayback.txt`   | Extracts URLs from Wayback Machine |
| Get URLs from multiple sources | `echo "target.com" \| gau > allurls.txt`           | Combines multiple archives         |
| Filter parameterized URLs      | `cat wayback.txt \| grep "?" > params.txt`         | Finds URLs with parameters         |
| Filter JS files                | `cat wayback.txt \| grep -E "\.js" > js_files.txt` | Extracts JavaScript files          |
| Filter admin pages             | `cat wayback.txt \| grep "admin" > admin.txt`      | Finds admin endpoints              |
| Validate live URLs             | `cat wayback.txt \| httpx -silent > live.txt`      | Checks which are active            |
| Remove duplicates              | `sort -u`                                          | Cleans the list                    |

---

## Conclusion

Archive.org’s Wayback Machine is one of the most powerful **passive reconnaissance tools** for bug bounty hunters.
By analyzing historical snapshots of a website, you can uncover:

* Old functionalities,
* Deprecated parameters,
* Exposed files,
* And insights about the target’s technology stack.

When combined with tools like `waybackurls`, `gau`, and `httpx`, it becomes an essential part of every recon workflow.
