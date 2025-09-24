
## What is EyeWitness?

**EyeWitness** is a reconnaissance tool that:

* **Takes screenshots** of web services, web apps, RDP/VNC/SSH banners, and other services (HTTP/S) found by scanners.
* **Collects HTTP response headers and title/meta information**.
* **Generates an HTML report** that lets you quickly triage interesting hosts and pages found during recon.

Why use it? When you run automated discovery (nmap, masscan, ffuf), you often get thousands of hosts/endpoints. EyeWitness turns those endpoints into screenshots + summary data so you can rapidly review what’s interesting visually (admin panels, login pages, debug pages) rather than reading dozens of raw responses.

---

## Main features

* Headless screenshots of URLs and services.
* Capture HTTP title, response code, server header and other metadata.
* Screenshot RDP/VNC/SSH if configured (legacy feature).
* Generates a browsable HTML report with thumbnails, details and links.
* Accepts multiple input formats (plain URL lists, nmap xml, masscan output, aquatone output).

---

## Installation

> Note: There are multiple EyeWitness projects/forks. These notes assume the commonly used Python-based **EyeWitness** (originally by Chris Truncer) or maintained forks. Commands below work on most Linux distros.

### 1) Quick Docker (recommended for isolated runs)

```bash
# Pull a community Docker image (example)
docker pull evilsocket/eyewitness  # (if available) - check image name in your environment

# Or run with local binary mount
docker run --rm -v $(pwd):/out evilsocket/eyewitness --help
```

*(Swap image name for a current, maintained image; Docker images change over time.)*

### 2) Install from system packages (Ubuntu/Debian)

Some distros don’t have a package. If available:

```bash
sudo apt update
sudo apt install eyewitness
```

### 3) Manual install from Git (recommended if package not available)

```bash
# prerequisites
sudo apt update
sudo apt install -y git python3 python3-pip wmctrl xvfb

# clone
git clone https://github.com/FortyNorthSecurity/EyeWitness.git eyewitness
cd eyewitness/setup

# install python deps
sudo pip3 install -r requirements.txt

# copy or run
cd ..
./EyeWitness.py --help
```

If the repo differs in your fork, adapt accordingly.

### 4) Install using pip (if available)

Some forks publish packages; not always up to date:

```bash
pip3 install eyewitness
```

---

## How EyeWitness works (internals)

* EyeWitness uses a **headless browser** (usually a webkit or selenium/PhantomJS/Chrome headless depending on version) to render pages and take screenshots.
* It can parse results from **nmap XML**, **masscan**, **aquatone**, **ffuf** output or raw URL lists.
* Produces **thumbnails** and a **static HTML** report (index.html) with metadata: title, response code, server header, screenshot, and original URL.
* For speed, EyeWitness can run multiple browser instances in parallel.

---

## Basic usage examples

### 1) From a simple URL list

Create `targets.txt` (one URL per line, include scheme `http://` or `https://`):

```
http://example.com
https://admin.example.com
http://10.0.0.5:8080
```

Run:

```bash
./EyeWitness.py --web -f targets.txt -d /path/to/output
```

Options:

* `--web` : tell EyeWitness to process web URLs
* `-f targets.txt` : input file
* `-d /path/to/output` : output directory

After run: open `/path/to/output/EyeWitness_report.html`.

### 2) From nmap XML

Scan (example):

```bash
nmap -p80,443,8080 -sV -oX nmap-http.xml 10.0.0.0/24
```

Then:

```bash
./EyeWitness.py --nmap nmap-http.xml -d /path/to/output
```

EyeWitness extracts URLs from Nmap XML and screenshots them.

### 3) From masscan

Example masscan to find web ports:

```bash
masscan -p80,443,8080 10.0.0.0/24 --rate=1000 -oL masscan.out
```

Transform lines to URLs and feed:

```bash
# create urls.txt from masscan.out (simplest approach)
cat masscan.out | awk '/open/ {print "http://"$4}' > urls.txt
# then run EyeWitness
./EyeWitness.py --web -f urls.txt -d /path/to/output
```

### 4) From Aquatone

If you used aquatone that outputs `aquatone_urls.txt`:

```bash
./EyeWitness.py --web -f aquatone_urls.txt -d /path/to/output
```

### 5) With additional options

```bash
./EyeWitness.py --web -f targets.txt --no-prompt -d /path/to/output --single 5 --threads 20
```

Common options:

* `--threads N` : number of concurrent workers
* `--single` : timeout per site (seconds)
* `--no-prompt` : run non-interactively
* `--headless` : run headless mode (if supported)
* `--no-screenshot` : metadata-only (fast)
* `--proxy PROXY` : route requests through proxy (e.g., Burp)
* `--user-agent "UA string"` : custom user-agent
* `--verifyssl` / `--no-verify` : verify TLS certs or not
* `--add` : additional ports
* `--use-ntlm` : if needs NTLM auth support (some forks)

Run `./EyeWitness.py --help` to see options in your installed version.

---

## Typical recon pipelines integration

### a) Masscan → Eyewitness

1. Masscan for web ports.
2. Convert masscan results to URL list (http/https heuristics).
3. Run EyeWitness.

### b) Nmap → EyeWitness

1. Nmap with `-sV -p` and `-oX`.
2. EyeWitness parses `nmap.xml` directly.

### c) Subdomain discovery (subfinder/amass) → ffuf → EyeWitness

1. Enumerate subdomains with `subfinder/amass`.
2. Fuzz directories with `ffuf` / `gobuster`.
3. Collect discovered URLs and run EyeWitness to screenshot them and triage.

### d) Burp → EyeWitness

* Extract interesting URLs from Burp's site map and feed them into EyeWitness for thumbnail generation.

---

## Output & report

Typical EyeWitness output directory structure:

```
/output/
  ├─ screenshots/
  │   ├─ screenshot_1.png
  │   └─ ...
  ├─ data/
  │   └─ metadata.json (some forks)
  ├─ EyeWitness_report.html
  └─ report_files...
```

The HTML report includes:

* Thumbnails for each screenshot
* Title, URL, response code, server header
* Link to full-size screenshot and raw response
* Search/filter UI to quickly find pages like "login", "admin", "dashboard"

---

## Triage methodology (how to review results fast)

EyeWitness produces lots of images. Use a triage strategy:

1. **Sort by response code** — prioritize 200 responses first, then 3xx (redirects), ignore 4xx/5xx unless interesting.
2. **Search for keywords** in titles/URLs: `admin`, `login`, `dashboard`, `portal`, `wp-admin`, `phpmyadmin`, `debug`, `stash`.
3. **Visual patterns** — look for logos, "Admin", input fields, default pages.
4. **Flag unique headers or server banners** (Apache old version, Nginx, app server).
5. **Export "interesting" URLs** to a smaller file and further fuzz or manual test.

---

## Automation & scaling tips

* Run EyeWitness on a beefy machine (lots of RAM + CPU) for parallel screenshots.
* Use `--threads` to increase concurrency, but tune down if target infra is fragile.
* Use headless Chrome/Chromium backend for more consistent rendering (some EyeWitness forks provide this option).
* Run EyeWitness in Docker with mounted output directory to easily capture HTML.
* Integrate EyeWitness as a stage in recon pipelines:

  * `discover → scan → screenshot → triage → manual testing`
* Optionally, use automated image comparison / OCR to detect login forms or presence of keywords in screenshots.

---

## Parsing EyeWitness programmatically

* Some EyeWitness versions emit JSON/CSV with metadata. If available, parse `metadata.json` or CSV using Python:

```python
import csv
with open('eyewitness_output.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if 'admin' in row['title'].lower() or 'login' in row['url'].lower():
            print(row['url'])
```

* If only HTML available, use BeautifulSoup to extract entries from the report.

---

## Common pitfalls & gotchas

* **HTTP vs HTTPS**: masscan/nmap give ports — you must guess scheme. EyeWitness will try, but prefer to build full URLs with proper scheme when possible.
* **Self-signed certs**: EyeWitness may fail TLS verification. Use `--no-verify` or allow insecure certs.
* **Rate-limits & WAF**: too many concurrent screenshots can trigger WAF or rate-limiting; pace runs responsibly per RoE.
* **JavaScript-heavy sites**: some EyeWitness versions struggle with SPAs — try using a fork that uses headless Chrome or use **gowitness** (see alternatives).
* **Rendering differences**: screenshots depend on rendering engine — what you see in EyeWitness might differ from a real user's browser (fonts, JS execution).
* **Outdated forks**: EyeWitness has had multiple maintainers; pick a maintained fork or use alternatives.

---

## Alternatives & complements

* **gowitness** — Go-based tool, uses headless Chrome; faster and often more reliable on modern JS sites. Has similar HTML report output. Install via `go install github.com/sensepost/gowitness@latest`.
* **aquatone** — great for domain takeovers and screenshotting via Chromium; integrates nicely with masscan/subdomain lists.
* **webscreenshot / webanalyze** — variant tools for capturing and analyzing web endpoints.
* **EyeWitness + gowitness combo** — use both to maximize coverage (some sites render better in one or the other).

---

## Security & Legal considerations

* Only run EyeWitness against assets **in-scope** with authorization (RoE).
* EyeWitness makes many automated requests and renders JavaScript — that can be disruptive to fragile apps (CMS admin pages, dev environments).
* Do not exfiltrate or store PII unless agreed and secure (redact screenshots with sensitive data).
* Keep runs auditable: store input lists, timestamps, and maintain logs.

---

## Lab example — end-to-end pipeline (practical)

### Goal

Find web admin panels on `10.10.10.0/24` and create a report.

### Steps

1. **Discover live hosts (fast ping scan)**

```bash
# find live hosts using nmap
nmap -sn 10.10.10.0/24 -oG livehosts.gnmap
awk '/Up/ {print $2}' livehosts.gnmap > livehosts.txt
```

2. **Masscan for web ports**

```bash
masscan -p80,443,8080,8443 -iL livehosts.txt --rate=1000 -oL web_hits.out
```

3. **Convert masscan to URL list (assume http for port 80/8080 and https for 443/8443)**

```bash
awk '/open/ {ip=$4; port=$3; if (port==80 || port==8080) print "http://"ip":"port; else print "https://"ip":"port}' web_hits.out > urls.txt
# Optionally remove ports when default: map 80 -> http://ip, 443 -> https://ip
```

4. **Run EyeWitness**

```bash
./EyeWitness.py --web -f urls.txt -d ./eyewitness_output --threads 20 --single 7 --no-prompt
```

5. **Triage**

* Open `./eyewitness_output/EyeWitness_report.html` in your browser.
* Search for `admin`, `login`, `dashboard`.
* Export interesting URLs to `interesting.txt`.

6. **Follow-up**

* Run Burp on `interesting.txt` or use `ffuf` to fuzz admin endpoints deeper.

---

## Sample quick commands cheat-sheet

```bash
# Basic: URLs file
./EyeWitness.py --web -f targets.txt -d ./out

# From nmap XML
./EyeWitness.py --nmap nmap.xml -d ./out

# Increase concurrency and timeout
./EyeWitness.py --web -f urls.txt -d ./out --threads 40 --single 10

# Use proxy (route via Burp for request inspection)
./EyeWitness.py --web -f urls.txt -d ./out --proxy http://127.0.0.1:8080

# Disable SSL verification (insecure, for self-signed certs)
./EyeWitness.py --web -f urls.txt -d ./out --no-verify

# Docker example (adapt to image you have)
docker run --rm -v $(pwd)/out:/out my/eyewitness image --web -f /out/urls.txt -d /out
```

---

## Quick comparison: EyeWitness vs gowitness vs aquatone

| Feature                 |             EyeWitness |    gowitness |       aquatone |
| ----------------------- | ---------------------: | -----------: | -------------: |
| Language                |                 Python |           Go |             Go |
| Headless Chrome support |         Varies by fork | Yes (Chrome) | Yes (Chromium) |
| Speed                   |               Moderate |         Fast |           Fast |
| Nmap support            |                    Yes |          Yes |            Yes |
| HTML report             |                    Yes |          Yes |            Yes |
| Active JS rendering     | Limited in older forks |         Good |           Good |

If you are targeting modern SPAs, **gowitness** or **aquatone** (headless Chrome) often give better rendering results.

---

## Example report snippet (for your pentest report)

```
Finding: Exposed Admin Panel - http://10.10.10.5:8080/admin
Severity: Medium
Discovery method: EyeWitness screenshot (masscan -> EyeWitness pipeline)
Evidence:
 - Thumbnail: eyewitness_output/screenshots/screenshot_12.png
 - URL: http://10.10.10.5:8080/admin
 - Title: "Admin Console - ExampleApp"
 - Server: "Apache/2.4.29 (Ubuntu)"
Recommendations:
 - Restrict access to /admin via IP allowlist or VPN
 - Add authentication controls (MFA) and rate limiting
 - Move admin panel to subdomain accessible only from internal network
```

