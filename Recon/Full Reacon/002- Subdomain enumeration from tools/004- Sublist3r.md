
### What is Sublist3r?

Sublist3r is a **subdomain enumeration tool** written in Python. It’s widely used in bug bounty hunting and penetration testing for **reconnaissance (recon)** — the phase where you map out the attack surface of a target.

* Purpose: Find **subdomains** of a given domain (`api.example.com`, `dev.example.com`, `shop.example.com`).
* Method: It queries **public sources** like search engines, VirusTotal, crt.sh (certificate transparency), Netcraft, DNSDumpster, etc.
* Type: **Passive enumeration** (doesn’t brute force aggressively by default).
* Why important: Each subdomain is potentially a separate application/service with its own vulnerabilities. Missing subdomains means missing attack surface.

---

## 2. Installing Sublist3r

### Requirements

* Python 3
* `git` and `pip`
* Internet connection (it queries online APIs)

### Step-by-step installation

```bash
# clone the repo
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r

# install dependencies
pip install -r requirements.txt

# verify installation
python3 sublist3r.py -h
```

You should see the help menu.

---

## 3. How Sublist3r Works (Under the Hood)

When you run `sublist3r -d example.com`, it does the following:

1. Sends queries to multiple online sources:

   * Google, Bing, Yahoo, Baidu (search engines)
   * VirusTotal, ThreatCrowd, PassiveDNS, crt.sh (security datasets)
   * Netcraft, DNSDumpster (recon services)
2. Collects all discovered subdomains.
3. Removes duplicates.
4. Outputs them to the terminal (and optionally a file).

> Note: It doesn’t validate them by default (some may be dead). That’s your job with tools like `dnsx` or `httpx`.

---

## 4. Basic Usage

### Find subdomains

```bash
python3 sublist3r.py -d example.com
```

### Save results to file

```bash
python3 sublist3r.py -d example.com -o subs.txt
```

### Increase speed with threads

```bash
python3 sublist3r.py -d example.com -t 50 -o subs.txt
```

### Verbose mode (see progress)

```bash
python3 sublist3r.py -d example.com -v
```

---

## 5. Options and Parameters

| Flag | Description                                     | Example          |
| ---- | ----------------------------------------------- | ---------------- |
| `-d` | Domain name to scan                             | `-d example.com` |
| `-o` | Output file                                     | `-o subs.txt`    |
| `-t` | Number of threads                               | `-t 50`          |
| `-v` | Verbose output                                  | `-v`             |
| `-b` | Enable brute force mode (if available)          | `-b`             |
| `-p` | Ports to scan for discovered domains (optional) | `-p 80,443,8080` |

---

## 6. Workflow (Step by Step)

Let’s build a **real workflow** for recon with Sublist3r.

### Step 1 — Enumerate subdomains

```bash
python3 sublist3r.py -d tesla.com -o tesla_subs.txt
```

### Step 2 — Clean and deduplicate

```bash
sort -u tesla_subs.txt -o tesla_subs.txt
```

### Step 3 — Resolve DNS (filter out dead subdomains)

```bash
cat tesla_subs.txt | dnsx -silent -a -resp > resolved.txt
```

### Step 4 — Check which hosts are alive (HTTP/S)

```bash
cat resolved.txt | httpx -title -status-code -content-length -silent > live_hosts.txt
```

### Step 5 — Dig deeper (crawl/fuzz/scan)

* Use `ffuf` for fuzzing directories.
* Use `nuclei` for vulnerability templates.
* Use `BurpSuite` for manual testing.

---

## 7. Example Output

Running:

```bash
python3 sublist3r.py -d tesla.com -o tesla_subs.txt
```

Might give:

```
shop.tesla.com
service.tesla.com
inventory.tesla.com
energy.tesla.com
dev.tesla.com
```

After resolution:

```
shop.tesla.com     104.18.12.15
energy.tesla.com   104.18.14.20
```

Live probe (`httpx`):

```
https://shop.tesla.com [200] [title: Tesla Shop]
https://energy.tesla.com [200] [title: Tesla Energy]
```

---

## 8. Strengths and Weaknesses

**Strengths**

* Simple and fast.
* Aggregates many sources at once.
* Good for initial recon.

**Weaknesses**

* Passive only — may miss subdomains.
* Doesn’t validate results by default.
* Some sources rate-limit (results can vary).

---

## 9. Advanced Tips

* Combine with **Subfinder** and **Amass** for better coverage.
* Use `dnsx` to filter valid domains.
* Schedule cron jobs to track newly discovered subdomains.
* Automate with bash pipelines.

Example combined:

```bash
sublist3r -d example.com -o subs1.txt
subfinder -d example.com -silent -o subs2.txt
amass enum -passive -d example.com -o subs3.txt
cat subs*.txt | sort -u | dnsx -a -silent > resolved.txt
```

---

## 10. Practical Lab Example

Target: `example.com`

1. Run Sublist3r:

   ```bash
   python3 sublist3r.py -d example.com -o subs.txt
   ```

   Found:

   ```
   www.example.com
   blog.example.com
   dev.example.com
   ```
2. Resolve them:

   ```bash
   cat subs.txt | dnsx -silent -a -resp > resolved.txt
   ```

   Output:

   ```
   www.example.com A 93.184.216.34
   blog.example.com A 93.184.216.35
   ```
3. Probe HTTP:

   ```bash
   cat resolved.txt | httpx -silent -status-code -title
   ```

   Output:

   ```
   https://www.example.com [200] [Example Domain]
   https://blog.example.com [302] [Redirect]
   ```

Now you know `blog.example.com` exists and redirects — potential testing point.

---

## 11. Comparison Table

| Tool      | Style            | Coverage  | Speed     | Best Use         |
| --------- | ---------------- | --------- | --------- | ---------------- |
| Sublist3r | Passive          | Medium    | Fast      | Quick recon      |
| Subfinder | Passive          | High      | Very fast | Modern default   |
| Amass     | Active + Passive | Very high | Slower    | Deep recon       |
| massdns   | Brute force      | Custom    | Very fast | Exhaustive brute |

---
