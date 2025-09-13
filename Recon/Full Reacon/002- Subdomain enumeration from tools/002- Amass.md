
<img width="1000" height="400" alt="images" src="https://github.com/user-attachments/assets/576262d9-ddbc-48b1-b826-4a3b0f54d97a" />

## 1) What is Amass 

**Amass** (an OWASP project) is a comprehensive attack-surface mapping tool focused on external asset discovery. It gathers subdomains and related network data using many OSINT techniques (certificate logs, public APIs, DNS history, web archives, WHOIS, scraping, etc.). You use Amass in recon to build an inventory of hosts and services for pentesting or bug-bounty work.

**Why use Amass?**

* Wide set of passive sources → finds unique hosts other tools miss.
* Supports active techniques and brute-force when you have permission.
* Stores results in a local DB so you can query, visualize and track changes over time.
* Best used as part of a toolkit (amass + subfinder + httpx + nuclei etc.).

**Example (concept):** running Amass will produce a simple newline list like:

```
api.example.com
dev.example.com
docs.example.com
```

(One hostname per line — that becomes the raw asset list you’ll process further.)

---

## 2) Installation (convenient commands per OS)

You can install Amass several ways. Below are common, practical methods.

### Ubuntu / Debian / Kali

```bash
sudo apt-get update
sudo apt-get install amass
```

or via snap:

```bash
sudo snap install amass
```

(Use whichever your distro prefers — `apt-get` is common on Kali/Ubuntu.)

**Example:** install on Ubuntu

```bash
sudo apt-get install amass
# After install:
amass --version   # verify it runs
```

### macOS (Homebrew)

```bash
brew tap caffix/amass
brew install amass
amass --version
```

### Binary / Releases

Download the prebuilt binary from the Amass GitHub releases page and extract it into `/usr/local/bin` or a directory in your PATH.

**Example:** verify installation

```bash
amass --help
# should display the help/usage and subcommands: enum, intel, db, track, viz ...
```

---

## 3) Viewing help & subcommands

To see Amass top-level help:

```bash
amass --help
```

To see options for the enumeration subcommand:

```bash
amass enum --help
```

Important subcommands you’ll use:

* `enum` — main enumeration engine (passive + active + brute options)
* `intel` — gather seeds/organizational intel (whois, sources)
* `db` — interact with the local database of results
* `track` — track changes over time (new/removed subdomains)
* `viz` — create visual graphs from DB

**Example:** get help for enum

```bash
amass enum --help
# read the flags (domain input, brute, passive, wordlist, output options)
```

---

## 4) Basic usage — passive & active enumeration

### Passive (low-noise)

Use passive mode when you want to avoid making active queries:

```bash
amass enum -d example.com --passive -o amass_passive.txt
```

This queries certificate transparency logs, public APIs and other OSINT sources without heavy probing.

**Example:** run passive

```bash
amass enum -d hackerone.com --passive -o hackerone_passive.txt
# Output: hackerone_passive.txt with lines of discovered subdomains
```

### Default / Mixed

Running `amass enum -d example.com` commonly performs a mix of techniques depending on config, but always check your version’s behavior.

**Example:** mixed run

```bash
amass enum -d example.com -o all_amass.txt
```

### Brute-force (noisy, use with authorization)

To brute-force subdomain names (use only when you have permission):

```bash
amass enum -d example.com -brute -w /path/to/wordlist.txt -o amass_brute.txt
```

This can generate lots of DNS traffic and trigger alerts.

**Example:** brute-forcing

```bash
amass enum -d example.com -brute -w /usr/share/wordlists/dns.txt -o example_brute.txt
# Expect many candidates; validate them with httpx or DNS resolution
```

---

## 5) Saving results and cleaning duplicates

Amass outputs can contain duplicates (same host found from many sources). Typical post-processing commands:

1. Save output:

```bash
amass enum -d hackerone.com -o hackerone_domains.txt
```

2. Count lines (raw):

```bash
wc -l hackerone_domains.txt
# e.g. prints: 34 hackerone_domains.txt
```

3. Remove duplicates and sort:

```bash
sort -u hackerone_domains.txt -o hackerone_domains_unique.txt
wc -l hackerone_domains_unique.txt
# e.g. prints: 22 hackerone_domains_unique.txt
```

**Example session:**

```bash
# Run Amass and get raw file
amass enum -d hackerone.com -o h1_raw.txt

# Count raw
wc -l h1_raw.txt   # -> 34

# Dedupe
sort -u h1_raw.txt -o h1_unique.txt
wc -l h1_unique.txt  # -> 22
```

Explanation: `sort -u` sorts and removes duplicates. The unique list is what you will use for probing and scanning.

---

## 6) Combining Amass with other tools (why & how)

Amass is best used as part of a pipeline. Different tools return different results — combine them.

### Example pipeline (passive collection → probe → scan)

```bash
# Collect from multiple tools
subfinder -d example.com -silent > subfinder.txt
amass enum -d example.com --passive -o amass.txt
assetfinder example.com > assetfinder.txt

# Merge & dedupe
cat subfinder.txt amass.txt assetfinder.txt | sort -u > all_subdomains.txt

# Probe with httpx to get live hosts
cat all_subdomains.txt | httpx -silent -status-code -title -o httpx.txt

# Extract hosts (first field) and dedupe
awk '{print $1}' httpx.txt | sort -u > live_hosts.txt

# Scan live hosts with nuclei
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_findings.txt
```

**Why this works:** Amass gives OSINT-rich results; Subfinder may find other hosts. `httpx` validates which domains respond over HTTP(S) and `nuclei` runs template-based checks on live assets.

**Concrete example run:**

```bash
# merge & dedupe
cat amass.txt subfinder.txt | sort -u > merged.txt

# probe
cat merged.txt | httpx -silent -status-code -title -o probe.txt

# get live
awk '{print $1}' probe.txt | sort -u > live.txt
```

---

## 7) Working with files, counts, and quick checks

Useful commands and patterns:

* Count unique domains:

```bash
cat merged.txt | sort -u | wc -l
```

* Show first 20 results:

```bash
head -n 20 merged.txt
```

* Search for an admin subdomain pattern:

```bash
grep -E 'admin|panel|dashboard' merged.txt | sort -u
```

**Example:** find admin-like hosts

```bash
grep -E 'admin|manage|dashboard|cpanel' merged.txt | sort -u > possible_admins.txt
```

---

## 8) Amass database & tracking changes

Amass can store results in a local database (graph/SQLite) so you can query relationships (which subdomain came from which source), generate visualizations, and track new/removed hosts over time.

* Typical subcommands: `amass db`, `amass track`, `amass viz`.
* Use `track` to periodically run enumeration and detect diffs/new hosts.

**Example concept (track):**

```bash
# Initial run
amass enum -d example.com --passive -o initial.txt
# Later run and track
amass track -d example.com -o tracked_changes.txt
# The tool will show differences between previous and current runs (new / removed)
```

(Consult `amass db --help` and `amass track --help` for exact options on your installed version.)

---

## 9) Practical lecture-style points (from your transcript) — clarified

* The transcript emphasized starting with help menus: run `amass --help` and `amass enum --help` and read the flags. This is critical because versions change.
* `amass` can be slower than some tools (like Subfinder) because it queries many sources and stores results. That slowness often yields unique results.
* You frequently need 3–5 tools to cover the whole surface. This is normal.
* After saving results, use `wc -l`, `sort -u`, and `cat` to clean, count and merge outputs.

**Example recap command set:**

```bash
amass enum -d hackerone.com -o h1.txt
subfinder -d hackerone.com -silent > sf.txt
cat h1.txt sf.txt | sort -u > merged.txt
wc -l merged.txt
```

---

## 10) Common gotchas & troubleshooting (and fixes)

* **Many duplicates** — fix with `sort -u`.
* **Tool slow / long-run** — run `--passive` first, use `-brute` selectively, and chunk targets.
* **Missing providers** — add API keys for services like SecurityTrails, VirusTotal, Censys to increase yield (but never commit keys).
* **No results** — check network, DNS resolver config, and spelling of domain. Try `amass enum -d example.com -v` for verbose output.
* **Rate-limits / quotas** — respect provider TOS and throttle brute runs.

**Example fix for duplicates:**

```bash
sort -u combined_raw.txt -o combined_unique.txt
```

---

## 11) Example scripts (end-to-end recon using Amass + tools)

Save this as `recon_amass.sh` and `chmod +x` it. Edit paths to your wordlists and templates.

```bash
#!/usr/bin/env bash
# recon_amass.sh: Amass + subfinder + httpx + nuclei pipeline
TARGET=$1
if [ -z "$TARGET" ]; then
  echo "Usage: $0 example.com"
  exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
OUT="recon_${TARGET}_${TS}"
mkdir -p "$OUT"

echo "[*] Amass passive"
amass enum -d "$TARGET" --passive -o "$OUT/amass_passive.txt"

echo "[*] Subfinder passive"
subfinder -d "$TARGET" -silent > "$OUT/subfinder.txt"

echo "[*] Merge and dedupe"
cat "$OUT"/*.txt | sort -u > "$OUT/all_passive.txt"

echo "[*] Probe with httpx"
cat "$OUT/all_passive.txt" | httpx -silent -status-code -title -o "$OUT/httpx.txt"

echo "[*] Extract live hosts"
awk '{print $1}' "$OUT/httpx.txt" | sort -u > "$OUT/live_hosts.txt"

echo "[*] Run nuclei"
nuclei -l "$OUT/live_hosts.txt" -t ~/nuclei-templates/ -o "$OUT/nuclei_findings.txt"

echo "[*] Done. Results in $OUT"
```

**Example run:**

```bash
./recon_amass.sh example.com
# results in recon_example.com_20250914_.../
```

---

## 12) Ethics & permissions (must-read)

* Always have explicit written authorization or operate inside a bug-bounty scope.
* Passive collection is lower risk, active probing and brute-force are noisy and may violate laws or program rules.
* Protect provider API keys — never commit them to source control. Use environment configs and `.gitignore`.

---

## 13) Useful short reference commands (cheat-sheet)

```bash
# Basic passive enumeration
amass enum -d example.com --passive -o passive.txt

# Brute-force (noisy)
amass enum -d example.com -brute -w /path/to/wordlist.txt -o brute.txt

# Help
amass --help
amass enum --help

# Dedupe results
sort -u raw.txt -o unique.txt

# Merge output from multiple tools
cat amass.txt subfinder.txt assetfinder.txt | sort -u > merged.txt

# Probe for live hosts
cat merged.txt | httpx -silent -status-code -o httpx.txt

# Count subdomains
wc -l merged.txt
```

---

## 14) Quick examples 

1. **Passive only + count uniques**

```bash
amass enum -d example.com --passive -o ex_passive.txt
sort -u ex_passive.txt -o ex_passive_unique.txt
wc -l ex_passive_unique.txt
```

2. **Combine Amass with Subfinder**

```bash
amass enum -d example.com --passive -o amass.txt
subfinder -d example.com -silent > subfinder.txt
cat amass.txt subfinder.txt | sort -u > all.txt
cat all.txt | httpx -silent -o httpx.txt
```

3. **Brute then validate**

```bash
amass enum -d example.com -brute -w /usr/share/wordlists/dns.txt -o brute.txt
cat brute.txt | httpx -silent -o brute_httpx.txt
```

---
