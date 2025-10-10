

**GF** is a small tool that applies simple regular-expression patterns (called “gf patterns”) to large lists of strings (usually URLs, responses, or filenames) to quickly filter and categorize items of interest. It is most often used in web reconnaissance to extract candidate endpoints for manual testing (XSS, SQLi, LFI, admin panels, JS files, etc.).

Typical workflow:

1. Collect many URLs (waybackurls, gau, gospider, etc.).
2. Pipe those URLs into `gf <pattern>`.
3. `gf` prints only lines matching the chosen pattern — reducing noise and focusing your testing.

---

## 2 — Why use GF

* Saves time: matches common vulnerability-relevant patterns so you don’t manually scan thousands of URLs.
* Reproducible: pattern files live in `~/.gf` so you can version control and share them.
* Flexible: you can use built-in patterns or create your own tailored to a target.
* Composable: integrates with other CLI tools (`httpx`, `jq`, `sort`, `uniq`, `nuclei`, `dalfox`, etc.).

---

## 3 — Installation and initial setup

### Install GF

If you have Go installed:

```bash
GO111MODULE=on go install github.com/tomnomnom/gf@latest
```

After installation, ensure `$GOPATH/bin` or `$GOBIN` is in your `PATH`.

### Download a curated pattern set (recommended)

There are several pattern repositories (popular: `1ndianl33t/Gf-Patterns`). Clone and copy patterns to your GF config directory:

```bash
git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/Gf-Patterns
mkdir -p ~/.gf
cp /tmp/Gf-Patterns/*.json ~/.gf/
rm -rf /tmp/Gf-Patterns
```

Note: some pattern repos use `.json` files, others `.pattern` or plain text. GF expects pattern files in `~/.gf`; the format widely used is a single JSON object or a simple file containing a regex — GF command-line reads them and exposes the name (filename without extension) as the pattern name.

### Verify installation

Run:

```bash
gf -h
```

Then test:

```bash
echo "https://example.com/index.php?id=1" | gf sqli
```

If `sqli` exists in `~/.gf`, matching lines will be printed.

---

## 4 — How pattern files are structured (what GF reads)

Pattern files placed in `~/.gf` are normally single-regex definitions (common practice). The exact format in pattern repos varies:

* Simple (recommended): a file containing **one** regex — e.g., `~/.gf/xss` with a single line:

  ```
  (?i)(<script|onerror=|onload=|document\.cookie)
  ```

* JSON-style (used by some repos): one JSON file per pattern containing fields like `name`, `description`, and `pattern`. GF-compatible repos often include tooling to convert JSON to the simple file layout.

Best practice: keep **one logical pattern per file** so you call `gf <name>` easily.

---

## 5 — Common built-in / popular patterns (examples + explanations)

Below are many practical pattern examples you can copy into `~/.gf/<name>` files. Each example shows the regex and a short explanation.

**Note**: these examples are heuristics — they generate candidate lists which you must validate manually.

### xss

File `~/.gf/xss`:

```
(?i)(\b(alert|prompt|confirm)\s*\(|<script\b|document\.cookie|<img[^>]+onerror=|<svg[^>]+onload=|javascript:)
```

Explanation: matches inline JS indicators and common injection vectors.

### sqli

File `~/.gf/sqli`:

```
(?i)(\bunion\b.*\bselect\b|\'\s*or\s*\'1\'=\'1|--\s*$|/\*.*\*/|;--|xp_)
```

Explanation: looks for SQL keywords or SQLi payload artifacts.

### lfi

File `~/.gf/lfi`:

```
(?i)(\.(?:php|asp|aspx|jsp|cgi)$|\.\./|\.\.\\|etc/passwd|/proc/self/fd)
```

Explanation: matches path traversal patterns and local file targets.

### ssti

File `~/.gf/ssti`:

```
(?i)(\{\{.*\}\}|\%\{.*\}|<%.*%>|jsp:|velocity)
```

Explanation: checks for template tags and common engine markers.

### admin

File `~/.gf/admin`:

```
(?i)(/admin\b|/administrator\b|/manage\b|/wp-admin\b|/adminpanel)
```

Explanation: finds admin-like paths.

### backup

File `~/.gf/backup`:

```
(?i)\.(bak|old|backup|zip|tar|tar\.gz|sql|db)$
```

Explanation: matches file extensions typically indicating backups.

### js

File `~/.gf/js`:

```
(?i)\.js($|\?)
```

Explanation: JS files, possibly with query strings.

### jwt

File `~/.gf/jwt`:

```
([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})
```

Explanation: basic JWT detection (three base64-looking parts separated by dots).

### token

File `~/.gf/token`:

```
(?i)(api_key|apikey|access_token|auth_token|token|secret)[:=]?[\"']?([A-Za-z0-9-_]{16,})
```

Explanation: finds parameter names commonly used for secrets.

---

## 6 — Using GF — core commands and pipelines

GF’s core use is piping lists of URLs into `gf`:

```bash
cat urls.txt | gf xss > xss_candidates.txt
cat urls.txt | gf admin > admin_urls.txt
```

You can chain filters:

```bash
cat urls.txt | gf admin | gf login | httpx -silent -mc 200,401
```

Typical recon pipeline:

```bash
# 1. Collect
gau example.com | sort -u > urls.txt

# 2. Filter interesting candidates
cat urls.txt | gf xss > xss.txt
cat urls.txt | gf sqli > sqli.txt
cat urls.txt | gf lfi > lfi.txt
cat urls.txt | gf js > js_files.txt

# 3. Validate live ones
cat xss.txt | httpx -silent -mc 200,302 -o xss_live.txt
```

Use `tee` to save and see output:

```bash
cat urls.txt | gf admin | tee admin_urls.txt | httpx -silent
```

Combine with `jq` after `httpx -json` for complex automation.

---

## 7 — How to write effective gf patterns (regex guidance)

Writing useful gf patterns requires balancing precision and recall:

* **Prefer anchored sub-patterns**: avoid overly broad patterns that catch everything.
* **Use case-insensitive matching**: include `(?i)` unless the pattern must be case-sensitive.
* **Match the context**: match parameter names (`[?&](id|user|file)=`) for parameter-based fuzzing.
* **Avoid catastrophic backtracking**: keep regex simple or use non-greedy qualifiers.
* **Test locally**: verify regex against a small sample before running on huge lists.

Examples for parameter detection:

* Generic parameter existence:

  ```
  [\?&][^=]+=
  ```

  Matches any query parameter in a URL.

* Parameter `id`:

  ```
  [\?&]id=\d+\b
  ```

  Matches `?id=123` or `&id=5`.

Use lookarounds for precision if your regex engine supports them (GF uses Go regex, which supports RE2 syntax; RE2 does **not** support lookbehind but supports lookahead).

---

## 8 — Creating custom patterns and organizing ~/.gf

### Create a custom pattern

1. Create file `~/.gf/myparam`:

   ```
   [\?&](token|apikey|access_token)[=]
   ```
2. Use:

   ```bash
   cat urls.txt | gf myparam > tokens.txt
   ```

### Naming convention

* Use clear names: `xss`, `sqli`, `lfi`, `admin`, `jwt`, `js`, `backup`, `token`, `email`, `oauth`.
* Keep one main regex per file for clarity.

### Distribute patterns

* Keep your ~/.gf under version control:

  ```bash
  mkdir -p ~/tools/gf-patterns
  cp ~/.gf/* ~/tools/gf-patterns/
  cd ~/tools/gf-patterns
  git init
  git add .
  git commit -m "My GF patterns"
  ```

---

## 9 — Testing and debugging patterns

* Test a single pattern on a sample list:

  ```bash
  printf "https://site.com/?id=1\nhttps://site.com/admin\n" | gf admin
  ```

* If a pattern returns no results, run the raw regex through `rg` (ripgrep) for faster local tests:

  ```bash
  rg --pcre2 -n "(?i)/admin\b" sample_urls.txt
  ```

  Note: `rg` supports PCRE2; GF uses RE2 syntax — adapt regex accordingly.

* Add verbose logging to pipelines (use `tee` to inspect intermediate output).

* If GF appears to ignore your pattern, check:

  * Pattern filename exists in `~/.gf`.
  * Pattern file contains a valid RE2 regex (no unsupported constructs).
  * Use `cat ~/.gf/<pattern>` to confirm content.

---

## 10 — Performance considerations

* GF itself is fast — the bottleneck is usually upstream (URL collection) or downstream validation (httpx).
* For very large URL sets (millions), pre-filter by host or extension:

  ```bash
  rg -i "example.com" all_urls_large.txt | gf xss
  ```
* Use `sort -u` early to dedupe and reduce duplicate processing:

  ```bash
  cat all_urls.txt | sort -u > urls_uniq.txt
  ```
* Parallelize heavy post-filtering steps (httpx checks) by splitting files into chunks:

  ```bash
  split -l 10000 urls_uniq.txt chunk_
  for f in chunk_*; do cat $f | gf xss | httpx -threads 100 -o ${f}_xss_live.txt & done
  wait
  ```

---

## 11 — Integration with other tools (practical pipelines)

### Recon pipeline example (full)

```bash
# collect
subfinder -d example.com -silent > subs.txt
cat subs.txt | gau | sort -u > urls.txt

# categorize with GF
cat urls.txt | gf js > js_files.txt
cat urls.txt | gf admin > admin_urls.txt
cat urls.txt | gf xss > xss_candidates.txt
cat urls.txt | gf sqli > sqli_candidates.txt
cat urls.txt | gf lfi > lfi_candidates.txt

# validate and triage
cat xss_candidates.txt | httpx -threads 200 -mc 200,302 -o xss_live.txt
cat sqli_candidates.txt | httpx -threads 200 -mc 200 -o sqli_live.txt

# run focused tools
cat xss_live.txt | dalfox pipe -b -w payloads.txt
cat sqli_live.txt | sqlmap -list  # example only, adapt usage

# scan live hosts with nuclei
cat xss_live.txt sqli_live.txt admin_urls.txt | sort -u | httpx -threads 200 -o live_all.txt
cat live_all.txt | nuclei -t ~/nuclei-templates/ -o nuclei_results.txt
```

### Use gf with `httpx -json` and jq

```bash
cat urls.txt | gf admin | httpx -json -threads 150 | jq -r '.url + " " + (.status_code|tostring)' > admin_status.txt
```

---

## 12 — Common pitfalls and how to avoid them

* **Overbroad patterns**: Accept higher false positive rate to ensure recall, but include downstream validation step to filter false positives.
* **Unsupported regex features**: GF uses Go's RE2 flavor (no lookbehind, limited backtracking). Avoid constructs RE2 does not support.
* **Case sensitivity**: forget `(?i)` — patterns may miss uppercase variants.
* **Pattern collisions**: avoid multiple patterns that capture the same lines unless you want multiple classifications.
* **Processing huge datasets without dedupe**: use `sort -u` early to avoid repeated work.

---

## 13 — Example pattern files (ready to copy)

Save each of these single-line regexes into `~/.gf/<name>` filenames as shown.

`~/.gf/xss`

```
(?i)(<script\b|javascript:|document\.cookie|<img[^>]+onerror=|onload=|alert\(|prompt\(|confirm\()
```

`~/.gf/admin`

```
(?i)(/admin\b|/administrator\b|/adminpanel|/wp-admin\b|/manage\b)
```

`~/.gf/js`

```
(?i)\.js($|\?)
```

`~/.gf/backup`

```
(?i)\.(bak|old|backup|zip|tar|sql|db|gz)(?:$|\?)
```

`~/.gf/jwt`

```
([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})
```

`~/.gf/params`

```
[\?&][a-zA-Z0-9_%-]{1,30}=
```

---

## 14 — Example full script (automated GF categorization)

Save as `gf_categorize.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

IN="$1"   # e.g., urls.txt
OUTDIR="${2:-./gf-output}"
mkdir -p "$OUTDIR"

# patterns to run
patterns=(xss sqli lfi js admin backup jwt params)

for p in "${patterns[@]}"; do
  echo "[*] running gf $p"
  cat "$IN" | gf "$p" | sort -u | tee "$OUTDIR/${p}.txt"
done

echo "[*] done. outputs in $OUTDIR"
```

Usage:

```bash
bash gf_categorize.sh urls.txt ./out
```

---

## 15 — Maintenance and community patterns

* Periodically pull updated pattern repositories from community sources (1ndianl33t, other forks) — new patterns are added as new vulnerabilities/paths are discovered.
* Keep your own `~/.gf` patterns under Git for traceability and reuse across engagements.

---

## 16 — Windows (PowerShell) notes

PowerShell usage is similar but piping differs. A basic example using gf (if gf is on PATH):

```powershell
Get-Content urls.txt | gf admin | Set-Content admin_urls.txt
```

For pattern files, place them in `%USERPROFILE%\.gf`.

---
