## 1. Source Code Analysis

### What Is It?

**Source code analysis** refers to inspecting the **client-side source code** of a web application (HTML, CSS, JavaScript) to extract useful information during recon. This technique helps identify hidden endpoints, comments, sensitive keys, and logic flaws.

### Why Use It?

Attackers and pentesters use source code analysis to:

* Discover **hidden API endpoints**
* Identify **debug parameters** or test routes
* Find **commented-out code**, internal notes, or credentials
* Understand **client-side logic** (e.g., form validation)
* Extract **JWT secrets**, **API keys**, or **environment variables**

### How to Do It

#### In Browser (Manual):

1. Open any website
2. Right-click > `View Page Source` or press `Ctrl+U`
3. Search using keywords like:

   * `key=`
   * `token`
   * `api`
   * `debug`
   * `TODO`, `FIXME`, or developer notes

#### With Tools:

* **Burp Suite (Spider)** – passively collects all JavaScript files and endpoints
* **LinkFinder** – scans JS files for URLs:

  ```bash
  python3 linkfinder.py -i https://target.com/app.js -o cli
  ```

#### Example:

```html
<!-- TODO: Remove debug mode after testing -->
<script>
  const debugMode = true;
  const apiKey = "test-123456";
</script>
```

This might reveal a **hardcoded key** or clue that debug features are active.

---

## 2. Copying a Website with HTTrack

### What Is HTTrack?

[**HTTrack**](https://www.httrack.com/) is a free, open-source tool used to **clone or mirror websites** by recursively downloading their public content, including HTML, CSS, images, and client-side JS.

### Why Use It?

* Perform **offline analysis** of a web application
* Search the website structure, paths, and resources
* Use it in **air-gapped environments** or slow connections
* Identify all reachable public pages (useful for mapping content)

### How It Works

HTTrack crawls the target site like a search engine, downloading all files it can access without authentication.

### Installation

* **Linux:**

  ```bash
  sudo apt install httrack
  ```

* **Windows:**
  Use the GUI version [WinHTTrack](https://www.httrack.com/page/2/en/index.html)

### Basic Usage

```bash
httrack https://target.com -O /path/to/save/files
```

This creates a full offline copy of the website.

### Real Example:

```bash
httrack https://vulnerable-app.com -O ./vulnapp-copy
```

Then, navigate to the saved files and explore `/index.html`, JavaScript files, and hidden directories.

> Note: HTTrack **does not bypass authentication** or crawl behind login-protected areas.

---

## 3. Website Screenshots with EyeWitness

### What Is EyeWitness?

[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness) is a tool that **automates taking screenshots** of websites or web services. It’s useful for quickly reviewing a list of targets or open ports discovered during scanning.

It also provides:

* HTTP header info
* Title & status code
* Basic fingerprinting

### Why Use It?

* Great for **bug bounty recon** when scanning wide IP ranges
* Helps visually identify **interesting panels** (admin, login, dev)
* Makes **reporting easier** with visual evidence
* Speeds up identifying web-based services on non-standard ports

### Installation (Kali / Linux)

```bash
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness
sudo ./setup/setup.sh
```

### Basic Usage

```bash
./EyeWitness.py -f targets.txt -d /output/screenshots
```

Where `targets.txt` contains a list of URLs or IPs with ports:

```
https://admin.target.com
http://192.168.1.10:8080
```

### Output

* A directory with:

  * Full screenshots of each web page
  * HTML report (`report.html`)
  * Header and status info for each URL

---

## Summary

| Technique               | Purpose                                            | Tools               |
| ----------------------- | -------------------------------------------------- | ------------------- |
| Source Code Analysis    | Extract info from HTML/JS (endpoints, keys, logic) | Browser, LinkFinder |
| HTTrack Website Cloning | Download entire website for offline analysis       | HTTrack, WinHTTrack |
| EyeWitness Screenshots  | Visually identify interesting web apps & ports     | EyeWitness          |

---

