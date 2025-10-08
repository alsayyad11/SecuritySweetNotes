
# 1 — What gospider is 

`gospider` is a fast web spider written in Go. Its purpose is to crawl a website starting from seed URL(s), discover links and endpoints, and output the URLs it finds for further analysis. It is typically used during reconnaissance to expand an application’s attack surface (endpoints, files, JS assets, parameters).

Important properties:

* Fast, concurrent crawling (Go goroutines under the hood).
* Focused on HTTP-level crawling — it fetches HTML and extracts links, not executing JavaScript.
* Produces URL lists that are easy to pipe into tools like `httpx`, `ffuf`, `nuclei`, `gf`, `dalfox`, etc.

---

# 2 — Install

Two common ways:

1. **Go (recommended if you have Go environment)**

```bash
GO111MODULE=on go install github.com/your-org/gospider/cmd/gospider@latest
# ensure $GOPATH/bin or $GOBIN is in your PATH
```

(Replace the module path with the correct upstream one on your system; if unsure, download the release binary from the project repo.)

2. **Download binary / releases**

* Download the prebuilt binary for your OS from the project’s releases page, unpack, and place the binary in `~/bin` or `/usr/local/bin`.

After install, verify:

```bash
gospider -h
```

That prints help and confirms the binary is runnable.

> Note: exact install paths and module names vary by project forks; use the repository you trust and run the help command to confirm flags.

---

# 3 — Basic usage pattern (conceptual)

A typical crawl consists of three steps:

1. Provide a starting URL or list of seed URLs.
2. Configure concurrency and depth limits.
3. Save/find the output (URLs, discovered resources).

Minimal example (conceptual):

```bash
gospider -s https://example.com -t 20 -d 2 -o output-dir
```

Explanation:

* `-s` (seed): starting URL(s) — single URL or file of URLs.
* `-t` (threads): concurrency / number of worker goroutines.
* `-d` (depth): how deep from the seed to follow links (0 = seed only, 1 = follow links on seed, etc.).
* `-o` (output): directory or file where results are written.

Always run `gospider -h` to see the exact flags your version expects.

---

# 4 — Important flags & concepts (detailed)

Below are the practical flags and their purpose. Use `gospider -h` to confirm exact names.

* **Seed input**

  * `-s <url>` — single seed URL.
  * `-S <file>` — read seeds from a file (one per line).

* **Concurrency / performance**

  * `-t <n>` — threads / concurrent workers (higher = faster, but more load).
  * `-timeout <s>` — request timeout in seconds.

* **Depth and recursion**

  * `-d <n>` — crawl depth (0 = only the seed page; 1 = seed + links found on it; 2 = follow links one more level, etc.)
  * `--follow-redirects` — whether to follow 3xx redirects.

* **Output**

  * `-o <dir>` — output directory for gospider artifacts (screenshots, lists).
  * `--output-file <file>` — write discovered URLs to a single file (if supported).
  * `--json` — JSON output (if supported) for structured processing.

* **Politeness & filtering**

  * `--rate-limit <r>` — limit requests per second (if supported); otherwise emulate with `-t`/sleep between runs.
  * `--blacklist <pattern>` — skip specific file extensions or URL patterns (images, fonts).
  * `--same-host` / `--follow-host` — limit crawling to the same host (prevent cross-domain crawling).
  * `--sitemap` — fetch and parse `sitemap.xml` first (if supported).

* **Authentication & headers**

  * `--header "Name: Value"` — add headers, e.g., `User-Agent` or `Authorization`.
  * `--cookie 'SESSION=abcd'` — supply a session cookie for authenticated crawling.
  * `--auth` / `--login` hooks — for sites that require login (usually you perform login outside gospider and supply resulting cookie/session).

* **JS & rendering**

  * gospider does **not** execute JavaScript like a browser (unless the particular fork has a headless-browser option). For JS-heavy applications, feed gospider with URLs discovered by a headless browser (Playwright, Puppeteer) or use tools that render JS.

* **Respect robots & scope**

  * Check `robots.txt` (gospider may not auto-honor it). If you need to be polite, parse `robots.txt` yourself or set flags to honor it.

---

# 5 — Output formats & where to find useful artifacts

gospider usually writes:

* A list of discovered URLs (one-per-line): `urls.txt` or similar.
* Optional categorized lists: `js.txt`, `forms.txt`, `images.txt` depending on features.
* Screenshots (if supported) saved under the output directory.
* JSON files for each crawl (if supported).

If your version writes into an output directory, look for:

```
output-dir/
  urls.txt
  js_files.txt
  forms.txt
  screenshots/
  results.json
```

If the tool does not produce a `js_files.txt`, you can extract JS URLs afterward (see post-processing below).

---

# 6 — Practical examples & pipelines

### Example 1 — Single-site crawl (safe defaults)

```bash
gospider -s https://example.com -t 30 -d 2 -o ./gospider-out
# then
cat ./gospider-out/urls.txt | sort -u > urls.txt
```

### Example 2 — Crawl a list of hosts (file input)

```bash
gospider -S targets.txt -t 50 -d 1 -o ./multi-out
# combine results
find ./multi-out -name 'urls.txt' -exec cat {} \; | sort -u > all_urls.txt
```

### Example 3 — Crawl and pipe to next stages

```bash
gospider -s https://example.com -t 50 -d 2 -o ./out && \
cat ./out/urls.txt | httpx -silent -status-code -o live_urls.txt
```

### Example 4 — Crawl, extract JS, validate with httpx

```bash
# get raw urls (from gospider or direct)
cat urls.txt | grep -iE '\.js($|\?)' | sed 's/[?].*$//' | sort -u > js_files.txt
# check live JS files
cat js_files.txt | httpx -silent -mc 200 -o js_live.txt
```

---

# 7 — Integration with recon tools (typical workflows)

**Common pipeline**

```
gospider -> dedupe -> dnsx (resolve) -> httpx (probe) -> nuclei/ffuf/gf/dalfox
```

* Use `gospider` to expand endpoints.
* Deduplicate and normalize URLs: `sort -u`, `sed 's/[?].*$//'` as needed.
* Resolve hostnames: `dnsx -a -resp`.
* Probe which URLs are live and gather metadata: `httpx`.
* Run signatures/templates: `nuclei` (vuln checks), `ffuf` (fuzzing), `dalfox` (XSS payloads), `gf` patterns for quick filtering.

Example combined command:

```bash
gospider -s https://example.com -t 50 -d 2 -o /tmp/gospider-out
cat /tmp/gospider-out/urls.txt | sort -u > /tmp/all_urls.txt
cat /tmp/all_urls.txt | httpx -threads 200 -status-code -title -o /tmp/httpx.json
cat /tmp/httpx.json | jq -r '.url' | nuclei -t ~/nuclei-templates/ -o findings.txt
```

---

# 8 — Handling JavaScript-heavy sites

* gospider does not run JS. To handle Single Page Applications or JS-discovered endpoints:

  1. Use a headless browser crawler (Playwright, Puppeteer, or Browsh) to render pages and extract URLs.
  2. Feed that list into gospider (or directly to `httpx`) to continue discovery and probing.
  3. Alternatively, use `gau` and `waybackurls` to collect archived URLs (they often include API endpoints referenced by JS).

---

# 9 — Forms, authentication, and POST endpoints

* gospider primarily finds links (GET endpoints). For forms:

  * Use a crawler that extracts `<form>` tags and posts (gospider may include forms list; check its feature set).
  * For authenticated areas, perform a login manually (or via script), capture cookies, and pass them to gospider with `--cookie` or `--header 'Cookie: ...'`.
  * For CSRF-protected endpoints, you must emulate a logged-in browser session and respect tokens; usually done by browser automation and then feeding found endpoints to scanners.

---

# 10 — Performance, politeness and safety

* **Concurrency**: increase threads for speed, but this increases load on target. Start modest (50–200) and raise/decrease based on target response and rules of engagement.
* **Rate-limiting**: if gospider supports a rate-limit flag, use it to avoid DoS. Otherwise, reduce `-t` or add sleeps in your orchestration.
* **Respect scope and law**: never crawl outside scope, don’t attack production beyond allowed limits.
* **robots.txt**: check and respect robots if required by policy.
* **User-Agent**: set a descriptive `User-Agent` so target owners can identify your scans:

  ```bash
  gospider --header 'User-Agent: recon@example.com - yourname'
  ```
* **Time windows**: run heavy crawls off-peak if testing production systems (with permission).

---

# 11 — Common pitfalls and how to avoid them

* **Missing JS endpoints**: gospider won’t execute JavaScript — combine it with headless crawlers or archived sources.
* **Infinite loops via parameters**: set a reasonable depth and avoid following query strings that create infinite unique URLs.
* **Duplicate/Noisy results**: dedupe via `sort -u` and normalize by stripping ephemeral query parameters.
* **Huge output**: limit scope, use `--same-host` or `--follow-host`, and process in chunks.
* **Auth-protected content**: provide cookies/headers, or pre-authenticate via headless browser and export cookies.

---

# 12 — Post-processing recipes (copy-paste)

**Deduplicate and save canonical URLs**

```bash
cat out/urls.txt | sed 's/[?].*$//' | sort -u > canonical_urls.txt
```

**Extract parameterized URLs**

```bash
grep -F '?' canonical_urls.txt | tee parameters.txt
wc -l parameters.txt
```

**Extract JS files (canonical)**

```bash
cat out/urls.txt | grep -iE '\.js($|\?)' | sed 's/[?].*$//' | sort -u | tee js_files.txt
wc -l js_files.txt
```

**Resolve hostnames and probe**

```bash
cat canonical_urls.txt | awk -F/ '{print $3}' | sort -u | dnsx -a -o resolved.txt
cat canonical_urls.txt | httpx -threads 200 -status-code -o httpx_results.txt
```

**Run nuclei on live URLs**

```bash
cat httpx_results.txt | nuclei -t ~/nuclei-templates/ -o nuclei_findings.txt
```

---

# 13 — Example full script (production-ready)

Save as `run_gospider_pipeline.sh` and adapt paths/flags.

```bash
#!/usr/bin/env bash
set -euo pipefail

SEED="$1"            # e.g., https://example.com
OUTDIR="${2:-./gospider-out}"
THREADS=100
DEPTH=2

mkdir -p "$OUTDIR"

# 1) Crawl
gospider -s "$SEED" -t "$THREADS" -d "$DEPTH" -o "$OUTDIR"

# 2) Consolidate URLs
RAW_URLS="$OUTDIR/urls.txt"
CANON="$OUTDIR/canonical_urls.txt"
JS="$OUTDIR/js_files.txt"
PARAMS="$OUTDIR/parameters.txt"
LIVE="$OUTDIR/live_urls.txt"

# canonicalize (strip query strings) and dedupe
cat "$RAW_URLS" | sed 's/[?].*$//' | sort -u > "$CANON"

# extract parameterized URLs
grep -F '?' "$RAW_URLS" | sort -u | tee "$PARAMS"

# extract JS files (canonical)
cat "$RAW_URLS" | grep -iE '\.js($|\?)' | sed 's/[?].*$//' | sort -u | tee "$JS"

# 3) probe live URLs
cat "$CANON" | httpx -threads 200 -status-code -o "$LIVE"

# 4) run nuclei on live URLs
cat "$LIVE" | nuclei -t ~/nuclei-templates/ -o "$OUTDIR/nuclei_results.txt"

echo "Done. Outputs in $OUTDIR"
```

Run:

```bash
bash run_gospider_pipeline.sh https://example.com ./out-example
```

---

# 14 — When gospider is the right tool (and when not)

Use gospider when:

* You need a fast, concurrent, link-focused crawler to collect endpoints.
* You want a simple starting point to augment passive discovery (crt.sh, gau, waybackurls).
* Your target is not heavily JS-dependent.

Do not rely solely on gospider when:

* Most endpoints are created dynamically by JS — use a headless-browser crawler instead.
* You must interact with forms and authenticated flows in-depth — use browser automation scripts.

---

# 15 — recommendations

* Read `gospider -h` to verify flags on your installed version.
* Start with modest `-t` and `-d`, then scale up after testing.
* Combine `gospider` with `gau`, `waybackurls`, and `crt.sh` for maximum coverage.
* Normalize and dedupe output before running high-throughput scanners.
* Validate live endpoints with `httpx` and run templates with `nuclei`.
* Respect scope, robots.txt, and rules of engagement.
