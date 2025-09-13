![a](https://github.com/user-attachments/assets/785e86f3-7dd2-4647-b95b-02247dad1d0b)


## What is a domain and a subdomain?

* A **domain** is a human-readable name that maps to an IP address through DNS. Example: `example.com`.
* A **subdomain** is a prefix to the domain that designates a separate host or service, e.g., `api.example.com`, `dev.example.com`, `admin.example.com`.

## Why enumerate subdomains?

* Organizations often host services across many subdomains. Some may be legacy, forgotten, or misconfigured.
* Finding subdomains reveals potential testing targets: admin panels, staging sites, developer consoles, misconfigured cloud services.
* Subdomain discovery is a major part of reconnaissance (recon) in penetration testing and bug bounty workflows.

## Passive vs active enumeration

* **Passive enumeration**: collect subdomains from public sources (certificate logs, search engines, third-party APIs). Less noisy, low chance of detection.
* **Active enumeration**: send DNS queries, brute force subdomain names, or probe services directly. More noisy and more likely to trigger alerts. Often used after passive collection to validate results.

## Where passive data comes from

* Certificate Transparency (crt.sh), VirusTotal, Shodan, Censys, BinaryEdge, Public DNS history, archived web (Wayback), and many other sources.

---

# 2. Installation (Linux-focused, with macOS & Windows notes)

This section shows how to install Go and Subfinder. You can follow the same steps on Ubuntu, Debian, Kali, or other Linux distributions.

## 2.1 Install Go (example: Go 1.19)

1. Download Go binary:

```bash
wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
```

2. Extract to `/usr/local`:

```bash
sudo tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
```

3. Add Go and GOPATH to your shell profile:

```bash
echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

4. Verify:

```bash
go version
# expected output: go version go1.19 linux/amd64
```

> Note: If you prefer a package-managed install, use your distro’s package manager, but ensure the version matches subfinder requirements.

## 2.2 Install Subfinder (Go install method)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

* This places the `subfinder` binary in `~/go/bin` (or `$GOPATH/bin`).
* Make it executable from anywhere:

```bash
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
which subfinder
subfinder -h
```

If `subfinder -h` prints help, install succeeded.

## 2.3 Alternative installs

* Docker: Many maintainers provide a Docker image. Check the ProjectDiscovery repo for official images. Use docker if you want container isolation.
* Binary packages: Some distributions or community repos might have packaged versions.

## 2.4 macOS & Windows

* macOS: install Go with Homebrew (`brew install go`), then `go install ...` as above.
* Windows: use WSL2 (recommended). If running natively, install Go for Windows and ensure `%GOPATH%\bin` is in PATH.

---

# 3. First run: minimal examples and what to expect

## 3.1 Minimal command

```bash
subfinder -d example.com
```

* Output: list of discovered subdomains printed one per line.

## 3.2 Save output to file and view simultaneously

```bash
subfinder -d example.com | tee example_passive.txt
```

* `tee` prints and saves output.

## 3.3 Clean output (no banner)

```bash
subfinder -d example.com -silent > passive_clean.txt
```

## 3.4 Check help and flags

```bash
subfinder -h
```

* Always check this for the installed version because flags or names can change between releases.

---

# 4. Detailed explanation of flags and options

Below are the common options and what they do. Exact flag names can differ by version; use `subfinder -h` to confirm.

* `-d <domain>` — target a single domain.
  Example: `subfinder -d example.com`.

* `-dL <file>` — read domains from a file, one per line.
  Example: `subfinder -dL targets.txt`.

* `-silent` — hide banner and non-essential logs. Good for piping to other tools.

* `-active` — probe discovered subdomains to return only live hosts (reduces false positives).

* `-o <file>` — write text output to file (path depends on version). Example: `-o results.txt`.

* `-oJ <file>` — write JSON output to file (`-oJ results.json`).

* `-ls` — list all sources Subfinder is configured to query.

* `-v` or `-vv` — increase verbosity. Shows which source returned which result and plugin/provider warnings.

* `-exclude <source1,source2>` — exclude one or more data sources.

* `-rate-limit <n>` — throttles request rate for providers that enforce limits (usage varies by tool version).

* `-timeout <seconds>` — network timeout for probes where supported.

* `-up` or `-update` — update the tool (method varies by install method).

* `-help`/`-h` — show help.

**Example combined command:**

```bash
subfinder -d example.com -silent -o example_passive.txt
```

---

# 5. Provider API keys — why they matter and how to configure them

## 5.1 Why provider keys

* Some sources (VirusTotal, BinaryEdge, Shodan, Censys, SecurityTrails, etc.) require authentication. Using these providers increases the number and uniqueness of results.
* Without keys, Subfinder will show a warning that certain providers are skipped.

## 5.2 How to obtain keys

* Create accounts on provider websites and retrieve API keys from account/profile pages.

## 5.3 Where to put keys

* Subfinder expects a provider configuration file. Locations vary by version but typical places include:

  * `~/.config/subfinder/`
  * `~/.subfinder/`
  * `~/.config/projectdiscovery/` (or similar)
* There is usually a YAML or JSON config file like `provider-config.yaml` or `providers.yaml`.

## 5.4 Example provider config (YAML example)

```yaml
binaryedge:
  apikey: "YOUR_BINARYEDGE_KEY"

virustotal:
  apikey: "YOUR_VIRUSTOTAL_KEY"

shodan:
  apikey: "YOUR_SHODAN_KEY"

censys:
  uid: "YOUR_CENSYS_UID"
  secret: "YOUR_CENSYS_SECRET"

securitytrails:
  apikey: "YOUR_SECURITYTRAILS_KEY"
```

* Put your keys in the corresponding fields. Exact keys and structure may vary by subfinder release, so check the sample config in your installed version or the GitHub README.

## 5.5 Security for API keys

* Keep provider config files out of version control. Add them to `.gitignore` if using Git.
* Consider storing keys in a local secrets manager if operating in a team environment.

---

# 6. Common practical examples, explained line-by-line

These examples show common workflows and explain what each command does.

## Example 1 — Basic passive enumeration and save

```bash
subfinder -d hackernoon.com | tee hackernoon_passive.txt
```

* `subfinder -d hackernoon.com` collects subdomains passively.
* `tee hackernoon_passive.txt` saves output while showing it on the console.

## Example 2 — Passive + active verification

```bash
subfinder -d hackernoon.com -silent | httpx -silent -status-code -o hackernoon_httpx.txt
```

* `subfinder -d hackernoon.com -silent` outputs clean list of subdomains.
* Piped into `httpx` which probes HTTP(S) and records status code and other info.
* Save to `hackernoon_httpx.txt`.

## Example 3 — Passive -> dedupe -> probe -> nuclei

```bash
subfinder -d example.com -silent | sort -u > passive.txt
cat passive.txt | httpx -silent -status-code -o httpx.txt
awk '{print $1}' httpx.txt | sort -u > live_hosts.txt
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_findings.txt
```

* `sort -u` removes duplicate hostnames.
* `httpx` checks which hosts respond.
* `nuclei` scans live hosts using template suite for common vulnerabilities.

## Example 4 — Batch mode for many targets

File `targets.txt`:

```
example.com
example2.net
example3.org
```

Command:

```bash
subfinder -dL targets.txt -silent -o all_passive_results.txt
```

* Runs passive enumeration for each domain in `targets.txt` and saves results.

## Example 5 — JSON output and parsing

```bash
subfinder -d example.com -oJ results.json
jq -r '.[] | .host' results.json | sort -u > hosts.txt
```

* `-oJ results.json` writes JSON.
* `jq` extracts the host field (adjust depending on actual JSON schema).

---

# 7. Integrations — tools you should know and why

Subfinder is most useful when combined with other tools. Below are the most common.

## 7.1 httpx

* Purpose: probe HTTP(S) endpoints, status codes, titles, TLS info.
* Use to filter passive results to live hosts.

Example:

```bash
cat passive.txt | httpx -silent -status-code -title -o httpx.txt
```

## 7.2 nuclei

* Purpose: scan hosts with templates for known vulnerabilities and misconfigurations.
* Use after `httpx` to scan live hosts.

Example:

```bash
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_out.txt
```

## 7.3 amass

* Purpose: additional enumeration (passive + active + brute-force). Often complements Subfinder.

Example:

```bash
amass enum -passive -d example.com -o amass_passive.txt
```

## 7.4 waybackurls / gau

* Purpose: retrieve archived URLs (useful to discover hidden endpoints and parameters).

Example:

```bash
cat live_hosts.txt | while read host; do gau $host >> archived_urls.txt; done
```

## 7.5 ffuf

* Purpose: fuzz directories and endpoints (find admin panels and hidden pages).

Example:

```bash
ffuf -u https://example.com/FUZZ -w common_wordlist.txt -o ffuf_output.txt
```

## 7.6 dnsx / massdns

* Purpose: fast DNS resolution and detailed DNS records discovery.

Example:

```bash
cat passive.txt | dnsx -resp -o dns_info.txt
```

---

# 8. Typical pipelines at different skill levels

## Beginner pipeline (safe, simple)

1. Passive collection:

```bash
subfinder -d example.com -silent | sort -u > passive.txt
```

2. Probe:

```bash
cat passive.txt | httpx -silent -status-code -o httpx.txt
```

## Intermediate pipeline (automated checks)

1. Passive:

```bash
subfinder -d example.com -silent | sort -u > passive.txt
```

2. Probe with httpx:

```bash
cat passive.txt | httpx -silent -status-code -title -o httpx.txt
```

3. Vulnerability surface scan:

```bash
awk '{print $1}' httpx.txt | sort -u > live_hosts.txt
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_findings.txt
```

## Professional pipeline (streaming & orchestration)

One-line streaming, minimal disk IO:

```bash
subfinder -d example.com -silent | httpx -silent -status-code | nuclei -silent -t ~/nuclei-templates/ -o findings.txt
```

* Streams between tools and completes reconnaissance, probing, and scanning in one flow.

## Large-scale enterprise pipeline

* Chunk targets.
* Use concurrency controls.
* Orchestrate with job scheduler/CI (Airflow, Rundeck) or a custom task runner.
* Store outputs in a database for tracking and historical diffs.

---

# 9. Ready-to-run scripts

## 9.1 Recon pipeline script: `recon_full.sh`

Save and make executable (`chmod +x recon_full.sh`).

```bash
#!/usr/bin/env bash
# recon_full.sh - Passive -> httpx -> nuclei
TARGET=$1
if [ -z "$TARGET" ]; then
  echo "Usage: $0 example.com"
  exit 1
fi

TS=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_${TARGET}_${TS}"
mkdir -p "$OUTDIR"

echo "[*] Passive enumeration"
subfinder -d "$TARGET" -silent | sort -u > "$OUTDIR/passive.txt"

echo "[*] Probing with httpx"
cat "$OUTDIR/passive.txt" | httpx -silent -status-code -title -o "$OUTDIR/httpx.txt"

echo "[*] Extract live hosts"
awk '{print $1}' "$OUTDIR/httpx.txt" | sort -u > "$OUTDIR/live_hosts.txt"

echo "[*] Run nuclei"
nuclei -l "$OUTDIR/live_hosts.txt" -t ~/nuclei-templates/ -o "$OUTDIR/nuclei_findings.txt"

echo "[*] Done. Results in $OUTDIR"
```

## 9.2 Batch runner for many domains: `batch_recon.sh`

```bash
#!/usr/bin/env bash
# batch_recon.sh - Read list of domains from targets.txt and perform fast passive enumeration
INPUT=targets.txt
OUTDIR=batch_results
mkdir -p "$OUTDIR"
while read -r domain; do
  echo "[*] Running subfinder for $domain"
  subfinder -d "$domain" -silent | sort -u > "$OUTDIR/${domain}_passive.txt"
done < "$INPUT"
echo "All done. Results in $OUTDIR"
```

---

# 10. Automation and monitoring

## 10.1 Periodic runs (cron)

Daily snapshot at 03:00:

```cron
0 3 * * * /usr/local/bin/subfinder -d example.com -silent | sort -u > /home/user/recon/example.com_$(date +\%F).txt
```

* Store daily outputs and create diffs to detect new subdomains:

```bash
diff previous_day.txt current_day.txt > new_subdomains.txt
```

## 10.2 Centralized storage & alerting

* Store outputs in a central repository (S3, NAS, or database).
* Alert on new domains (e.g., send email/Slack when diffs are non-empty).

---

# 11. Performance tuning and rate limits

## 11.1 Rate control

* Respect provider quotas. If subfinder supports `-rate-limit`, set it.
* For services with tight quotas (VirusTotal, BinaryEdge), use API keys sparingly and avoid repeated hits.

## 11.2 Chunking

Split large lists to avoid throttling:

```bash
split -l 500 all_targets.txt chunk_
for f in chunk_*; do subfinder -dL $f -silent >> results_all.txt; done
```

## 11.3 Concurrency

* Increase concurrency for `httpx` and `nuclei` carefully, but monitor CPU, memory, network, and provider limits.

---

# 12. Troubleshooting — common errors and fixes

### Error: `no input list provided`

* Cause: you ran `subfinder` without `-d` or `-dL`.
* Fix: supply a domain or a file.

### Error: `command not found: subfinder`

* Cause: GOPATH not in PATH, or binary not installed properly.
* Fix: `echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc; source ~/.bashrc` or copy binary to `/usr/local/bin`.

### Warnings about skipped providers

* Cause: missing API keys for certain providers.
* Fix: add API keys to provider config.

### Rate limit errors / quota exceeded

* Cause: exceeded provider quota.
* Fix: slow down, increase limits carefully, or stagger runs.

### JSON parsing issues with `jq`

* Cause: JSON schema different than assumed.
* Fix: open JSON file and inspect keys, then write appropriate `jq` filter.

---

# 13. Advanced use cases with examples

## 13.1 Subdomain takeover detection

1. Collect subdomains:

```bash
subfinder -d example.com -silent > passive.txt
```

2. Check for unused CNAMEs or responses:

```bash
cat passive.txt | dnsx -resp -cname -o dns_info.txt
```

3. Run takeover scanner (e.g., subjack) on findings (authorized targets only):

```bash
subjack -w passive.txt -t 50 -timeout 30 -o takeover_results.txt -ssl
```

* Confirm manually any positive result.

## 13.2 Admin panel discovery (fuzzing)

```bash
cat live_hosts.txt | while read host; do ffuf -u https://$host/FUZZ -w /path/to/admin_paths.txt -mc 200 -o "$host-admin.txt"; done
```

* `admin_paths.txt` is a curated list of common admin endpoints.

## 13.3 Historical discovery for parameters and endpoints

```bash
cat live_hosts.txt | while read host; do gau $host >> all_urls.txt; done
# Filter for interesting parameters (example)
grep -E "(\?|=)" all_urls.txt | sort -u > urls_with_params.txt
```

---

# 14. Reporting and evidence

## 14.1 What to include in a recon report

* Target(s) and scope.
* Time and date of recon.
* Tools and versions used (Subfinder vX.Y, httpx vA.B, nuclei vC.D).
* Provider APIs used (list, not the keys).
* Raw outputs (passive.txt, httpx.txt, live\_hosts.txt, nuclei findings).
* Steps to reproduce any findings.
* Screenshots or command outputs that prove access or vulnerability (if applicable and authorized).

## 14.2 Keeping evidence secure

* Store sensitive outputs securely (private S3 bucket, encrypted storage).
* Don’t share provider API keys or other secrets in reports.

---

# 15. Ethics, legality, and best practices

* Always have **written authorization** or operate within a defined bug-bounty program scope.
* Passive enumeration is low risk, but active probing can impact systems — get permission.
* Respect provider Terms of Service and API quotas.
* Never abuse or expose API keys; keep them private.
* Disclose vulnerabilities responsibly to the owner and follow the disclosure timeline of the program or organization.

---

# 16. Quick-reference cheat-sheet (most-used commands)

```bash
# Install subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Basic passive enumeration
subfinder -d example.com -silent | sort -u > passive.txt

# Probe live hosts with httpx
cat passive.txt | httpx -silent -status-code -title -o httpx.txt

# Extract hosts for scanning
awk '{print $1}' httpx.txt | sort -u > live_hosts.txt

# Run nuclei on live hosts
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -o nuclei_out.txt

# Batch mode: domain file
subfinder -dL targets.txt -silent -o batch_results.txt

# JSON output
subfinder -d example.com -oJ results.json

# List subfinder sources
subfinder -ls

# Verbose (shows skipped providers)
subfinder -d example.com -v
```

---

# 17. Appendix — sample provider config (example)

Save this as `~/.config/subfinder/providers.yaml` or the path required by your version:

```yaml
binaryedge:
  apikey: "YOUR_BINARYEDGE_API_KEY"

virustotal:
  apikey: "YOUR_VIRUSTOTAL_API_KEY"

shodan:
  apikey: "YOUR_SHODAN_API_KEY"

censys:
  uid: "YOUR_CENSYS_UID"
  secret: "YOUR_CENSYS_SECRET"

securitytrails:
  apikey: "YOUR_SECURITYTRAILS_API_KEY"
```

Remember: check your installed version for exact file location and schema.

---

# 18. Where to go next (learning path)

1. Practice in a safe environment (local VMs or intentionally vulnerable targets like OWASP Juice Shop or DVWA).
2. Learn `httpx` and `nuclei` templates usage.
3. Study `amass` and passive vs active tradeoffs.
4. Learn to read certificate transparency logs and common data sources.
5. Practice writing automated recon scripts and building an asset inventory system.

---

# 19. summary

* Subfinder is a fast, passive-first tool for discovering subdomains.
* It is most powerful when combined with provider API keys and integrated into a pipeline that probes and scans live hosts.
* Follow the beginner → intermediate → pro pipelines in this guide.
* Automate with care, track outputs with timestamps, and report responsibly.
* Always get permission and follow ethical/legal guidelines.

---

[Reference](https://tecadmin.net/install-go-on-debian/)
