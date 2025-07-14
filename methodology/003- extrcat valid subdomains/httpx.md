
##  What is `httpx`?

`httpx` is a **fast and flexible HTTP probing tool** built by [ProjectDiscovery](https://github.com/projectdiscovery/httpx). It’s mainly used in **bug bounty and reconnaissance workflows** to check if a list of subdomains or URLs are live (responding over HTTP/S).

Instead of manually visiting each domain in a browser or sending one request at a time, `httpx` can process **hundreds or thousands** of targets in seconds.

---

##  Why Use `httpx`?

When you gather subdomains using tools like:

* `subfinder`
* `amass`
* `sublist3r`

You usually end up with a long list. But **not all of them are live**.

`httpx` helps you:

* **Filter live hosts** (which return HTTP responses)
* **Collect information** like status codes, titles, IPs, and technologies
* **Speed up your workflow** before scanning, fuzzing, or exploiting

---

## How to Install `httpx`

If you have Go installed:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Make sure your `$GOPATH/bin` is in your system’s `$PATH`.

To verify it works:

```bash
httpx -h
```

---

##  Basic Command Structure

```bash
httpx -l <input_file> -o <output_file> [options]
```

* `-l`: Path to your input file (list of domains/subdomains)
* `-o`: Output file where results will be saved
* `[options]`: Optional flags to customize behavior and output

---

##  Commonly Used Options

| Option               | Description                                        |
| -------------------- | -------------------------------------------------- |
| `-l`                 | Read input from a file                             |
| `-o`                 | Save output to a file                              |
| `-t 40`              | Use 40 threads for faster execution                |
| `-random-agent`      | Use a random User-Agent header in requests         |
| `-mc 200`            | Show only responses with status code 200 (OK)      |
| `-silent`            | Minimal output (just live URLs)                    |
| `-status-code`       | Show HTTP status code                              |
| `-title`             | Show page title                                    |
| `-ip`                | Show IP address                                    |
| `-tech-detect`       | Detect technologies (like Apache, WordPress, etc.) |
| `-timeout 5`         | Set timeout for each request (in seconds)          |
| `-ports 80,443,8080` | Custom ports to scan                               |

---

## Example #1: Basic Live Host Filtering

You have a file called `subdomains.txt` with subdomains like:

```
admin.example.com
login.example.com
dev.example.com
```

Run:

```bash
httpx -l subdomains.txt -o valid-subdomains.txt -t 40 -random-agent -mc 200
```

###  What this does:

* Reads the input file `subdomains.txt`
* Sends requests using 40 threads
* Uses random User-Agent headers
* Only saves URLs that respond with HTTP 200
* Saves output to `valid-subdomains.txt`

###  Output:

```
https://admin.example.com
https://login.example.com
```

Now you know which subdomains are live and returning valid pages.

---

##  Example #2: Get More Info

```bash
httpx -l subdomains.txt -o detailed.txt -t 50 -status-code -title -ip -tech-detect
```

### This will give you:

```
https://dev.example.com [200] [Internal Dashboard] [192.168.1.100] [Apache, PHP]
```

You now have:

* The URL
* HTTP status
* Page title
* IP address
* Technologies used

Useful before fingerprinting or choosing the right exploit/fuzzing approach.

---

##  Common Recon Workflow Using `httpx`

```bash
# Step 1: Subdomain Enumeration
subfinder -d example.com -o subs1.txt
sublist3r -d example.com -o subs2.txt
amass enum -passive -d example.com -o subs3.txt

# Step 2: Merge and Deduplicate
cat subs1.txt subs2.txt subs3.txt | sort -u > all_subs.txt

# Step 3: Filter Live Hosts
httpx -l all_subs.txt -o alive.txt -t 50 -random-agent -mc 200

# Step 4: Use alive.txt for fuzzing, scanning, or exploitation
```

---

##  Summary

| Feature             | Purpose                                         |
| ------------------- | ----------------------------------------------- |
| Live filtering      | Keep only subdomains that are alive             |
| Fast execution      | Multi-threaded for speed                        |
| Custom headers      | Avoid detection or blocks                       |
| Tech fingerprinting | Understand the tech stack before attacking      |
| Script integration  | Easily fits into recon and automation pipelines |

---
