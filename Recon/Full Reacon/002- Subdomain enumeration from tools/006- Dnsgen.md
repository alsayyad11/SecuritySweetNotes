
## 1. What is dnsgen and why use it

**dnsgen** (by ProjectDiscovery) is a tool that **takes existing domain/subdomain names** (from passive enumeration results like crt.sh, Amass, Subfinder, assetfinder, waybackurls, etc.) and **generates new candidate subdomains** by applying a set of mutation and permutation rules. The generated names are intended to be fed into fast DNS resolvers (massdns, dnsx) to discover additional hidden subdomains that passive sources missed.

Why use dnsgen:

* Passive data often misses developer/test/temporary hostnames. dnsgen **automates intelligent permutations** (add prefixes/suffixes, replace tokens, expand numeric ranges, insert common words) to create high-value candidate names.
* Cleaner and more effective than blind brute-forcing a million words; dnsgen produces *smarter* candidates derived from real names encountered on the target.
* Greatly increases subdomain discovery yield when combined with fast resolvers.

Typical workflow: gather subdomains/URLs → feed into dnsgen → resolve candidates with massdns/dnsx → probe live HTTP services (httpx) → scan/vuln-test (nuclei etc.)

---

## 2. How dnsgen works (concept)

Input: list of known hostnames, URLs, or words (e.g., `dev.example.com`, `api.eu.example.com`, `login.example.com`, `test.example.net`).

Transformations dnsgen performs (examples):

* Token-based mutations: split tokens at delimiters and permute (`dev`, `test`, `staging`, `api`, etc.).
* Affix additions: add common prefixes/suffixes (`-dev`, `-stg`, `-test`, `-backup`, `-admin`).
* Numeric expansions: expand `app1` → `app-1`, `app01`, `app01`, `1-app`.
* Insert common words: `api` → `api-test`, `api-stage`.
* Word variations (singular/plural, hyphenation/concatenation).
* Domain expansion: if `example.com` and `example.co` present, map tokens between zones.
* Custom mutation rules via templates.

Output: candidate subdomain list (newline separated) suitable for high-speed DNS resolution.

Core idea: use real tokens to produce plausible names that a human admin might create.

---

## 3. Installation

dnsgen is written in Go and available via GitHub releases or `go install`.

### Option A — go install (recommended)

```bash
go install -v github.com/projectdiscovery/dnsgen/cmd/dnsgen@latest
# ensure $GOPATH/bin (or $HOME/go/bin) is in PATH
```

### Option B — download binary

* Visit [https://github.com/projectdiscovery/dnsgen/releases](https://github.com/projectdiscovery/dnsgen/releases) and download the prebuilt binary for your OS, extract to `~/bin` or `/usr/local/bin`.

### Option C — build from source

```bash
git clone https://github.com/projectdiscovery/dnsgen.git
cd dnsgen/cmd/dnsgen
go build
# move binary to /usr/local/bin
```

Verify:

```bash
dnsgen -h
```

---

## 4. Basic usage & examples

### Basic usage (stdin → stdout)

```bash
# feed known subdomains from file
cat subs.txt | dnsgen | tee candidates.txt
```

### Pipe into resolver (fast end-to-end)

```bash
cat subs.txt | dnsgen | massdns -r resolvers.txt -t A -o S -w results.txt
```

### Common one-liner with dnsx (ProjectDiscovery resolver)

```bash
cat subs.txt | dnsgen | dnsx -a -resp -silent > resolved.txt
```

### Example: use waybackurls output

```bash
cat urls.txt | sed -E 's#https?://##' | cut -d/ -f1 | sort -u | dnsgen | dnsx -a -silent > discovered.txt
```

---

## 5. Important flags & options

Run `dnsgen -h` for the full list. Key flags you’ll use:

* `-w, --wordlist` : Use a custom wordlist of affixes/mutations (some versions).
* `-t, --template` : Use a template file (custom mutation rules) — available in some forks.
* `-o, --output` : Write results to a file.
* `-s, --silent` : Minimal output.
* `-d, --dedup` : Deduplicate results (often default).
* `-r, --rate` : Limit generation rate (if implemented). Many versions don’t have rate; you control resolution rate downstream.
* `-c, --concurrency` : Concurrency in generation (rare—main load is resolver side).
* `--no-wildcard-check` : Skip wildcard check (some pipelines perform wildcard domain filtering).
* `--suffixes`: supply a custom list of suffixes to try.
* `--subdomain` / `--domain` : indicate input is subdomain or domain (contextual).

Notes: dnsgen tends to be focused on generation not resolution; so use downstream tools (massdns/dnsx) for high-performance checks and rate control.

---

## 6. Integration patterns (pipelines)

dnsgen is designed to fit into pipelines. Common integrations:

### Pattern A — Passive→dnsgen→massdns→httpx

1. Collect passive subdomains: `amass -passive`, `subfinder`, `assetfinder`, `crt.sh` output, waybackurls.
2. `cat passive_subs.txt | dnsgen | massdns -r resolvers.txt -t A -o S -w massdns_out.txt`
3. Parse massdns result to canonical host list: `cut -d' ' -f1 massdns_out.txt | sed 's/\.$//' | sort -u > live_hosts.txt`
4. `cat live_hosts.txt | httpx -title -status-code -silent > http_info.txt`

### Pattern B — passive→dnsgen→dnsx→nuclei

```bash
cat passive.txt | dnsgen | dnsx -a -silent | nuclei -t ~/nuclei-templates/ -rate 150
```

Use `dnsx` for lightweight resolution and later scanning.

### Pattern C — brute force style combined

Combine dnsgen candidates with wordlist brute forcing:

```bash
cat passive.txt | dnsgen > candidates.txt
cat wordlist.txt candidates.txt | sort -u | massdns -r resolvers.txt -t A -o S -w massdns_out.txt
```

### Pattern D — continuous monitoring (cron)

Schedule weekly:

* Update passive list
* Generate new candidates with dnsgen
* Resolve and diff previous results to alert on newly discovered hosts

---

## 7. Practical examples (real commands)

### Simple generate + resolve using dnsx (fast)

```bash
cat subs.txt | dnsgen | dnsx -a -resp -silent -retries 2 -timeout 2 > new_resolved.txt
```

* `-a` get A records, `-resp` keeps raw response, tune `-timeout`/`-retries` to environment.

### Using massdns for large volume resolution

```bash
cat subs.txt | dnsgen | massdns -r resolvers.txt -t A -o S -w massdns_output.txt
# extract hosts
awk '{print $1}' massdns_output.txt | sed 's/\.$//' | sort -u > discovered_hosts.txt
```

### Filtering out wildcards and cloud provider placeholders

* Many cloud providers respond for almost any subdomain (wildcards). To mitigate:

  1. Pre-check for wildcard behavior:

     ```bash
     echo "random-subdomain-$(date +%s).example.com" | dnsx -a -silent
     ```
  2. If a wildcard resolves, record its IPs and filter out candidates that resolve to same IP set (or other heuristics such as CNAME to known CDN). Use `jq`/awk scripting to exclude.

---

## 8. Tuning, performance & scaling

* dnsgen itself is lightweight; bottleneck is DNS resolution. Use high-performance resolvers (massdns) or dnsx with tuned concurrency.
* Use a large resolver list (Public resolvers + fast recursive resolvers) but be polite and do not overload third-party resolvers. Use your own resolver infrastructure (recommended) for heavy scans.
* Use batching: generate candidates, chunk them (`split -l 10000`) and resolve in parallel while respecting rate limits.
* Monitor network/target to avoid overloading.

Example: parallel massdns with 10 workers

```bash
cat subs.txt | dnsgen > candidates.txt
split -l 10000 candidates.txt chunk_
for f in chunk_*; do
  massdns -r resolvers.txt -t A -o S -w ${f}.out $f &
done
wait
cat chunk_*.out > all_massdns.out
```

---

## 9. Handling wildcard DNS & noisy responses

Wildcard DNS can create many false positives. Strategies:

1. **Early wildcard detection**: For each zone run a random name check. If random name resolves, take note of wildcard IPs/CNAMEs.
2. **IP set filtering**: If candidate resolves to wildcard IPs, consider it a wildcard and filter.
3. **CNAME analysis**: Some wildcard responses are CNAME to CDN or hosting placeholders; identify known patterns and filter them.
4. **HTTP probing**: After DNS resolution, probe with `httpx` and check HTTP response body/title patterns that indicate generic CDN/parking pages; filter those too.
5. **Rate limit observations**: If many candidates resolve to same IPs quickly, your resolver or upstream target may be applying wildcard; introduce backoff.

---

## 10. Advanced techniques

* **Template customization**: Some dnsgen versions support templates or suffix lists; provide a focused suffix/prefix list (e.g., `-staging`, `-internal`, `-svc`) to bias the generation.
* **Language-specific variations**: For targets in other locales, include local token variations (e.g., `dev`, `devs`, `desarrollo`, `prd`, `prod`, `preprod`).
* **Historic tokens**: Use waybackurls/gau to extract path tokens and feed into dnsgen (e.g., `admin`, `wp`, `login`, `jenkins`).
* **Cross-zone mapping**: If the organization owns multiple TLDs, map tokens across them (a token seen in `example.org` could be used in `example.com`).
* **Entropy filters**: Filter generated candidates that have high entropy or uncommon character sequences (likely garbage).
* **Machine learning heuristics**: Score generated names by plausibility (frequency of tokens combined, length, token semantic relevance) and prioritize by score for resolution.

---

## 11. Safety, legal & ethical considerations

* dnsgen only *generates* candidate names; the act of resolving those names (massdns/dnsx) is the network action that may be rate-limited or logged by the target’s DNS provider or by upstream recursive resolvers.
* Always have **authorization** before performing mass resolution on domains outside your scope.
* For large scans prefer to use **your own resolvers** rather than third-party public resolvers to avoid causing collateral load.
* Respect targets’ Robots/Rules of Engagement where applicable.
* Avoid brute forcing internal corporate domains without explicit permission.

---

## 12. Troubleshooting & common pitfalls

* **Too many false positives**: apply wildcard detection and HTTP probing to reduce noise.
* **Slow resolution**: switch to massdns with binary output and tune concurrency and resolver list.
* **IP rate limiting**: if resolvers throttle queries, reduce concurrency and add sleep/backoff.
* **Huge candidate set**: restrict generation by prefix/suffix lists or sample by highest-priority tokens.
* **Memory/disk issues**: stream pipeline (do not keep large lists in memory), use split/chunk strategy.

---

## 13. Example lab — end-to-end (realistic)

Goal: discover hidden hosts for `target.com` using passive inputs and dnsgen.

1. Gather passive inputs:

```bash
subfinder -d target.com -silent > passive.txt
amass enum -passive -d target.com -o amass_passive.txt
cat passive.txt amass_passive.txt | sort -u > passive_all.txt
```

2. Extract host tokens (domain only):

```bash
cat passive_all.txt | sed 's/:\/\///g' | awk -F/ '{print $1}' | sort -u > hosts.txt
```

3. Generate candidates:

```bash
cat hosts.txt | dnsgen > candidates.txt
```

4. Chunk and resolve with massdns:

```bash
split -l 10000 candidates.txt chunk_
for f in chunk_*; do
  massdns -r resolvers.txt -t A -o S -w ${f}.out $f &
done
wait
cat chunk_*.out > massdns_all.out
```

5. Extract discovered hosts:

```bash
awk '{print $1}' massdns_all.out | sed 's/\.$//' | sort -u > discovered_hosts.txt
```

6. Probe HTTP:

```bash
cat discovered_hosts.txt | httpx -title -status-code -silent -o http_info.txt
```

7. Filter for interesting endpoints and run nuclei:

```bash
cat http_info.txt | awk '{print $1}' | nuclei -t ~/nuclei-templates/ -o nuclei_findings.txt
```

---

## 14. Comparison with other approaches

* **dnsgen vs pure brute force:** dnsgen produces context-aware candidates derived from existing names (higher signal/noise) vs. blindly trying common words.
* **dnsgen vs Amass brute:** Amass can brute force too; dnsgen is complementary — you can feed dnsgen outputs into Amass or vice versa.
* **dnsgen vs permutation tools (e.g., dnsrecon permutations):** dnsgen is specifically designed for token-based mutation from real inputs and has a modern rule set.

---

## 15. Quick reference — commands & flags

* Generate candidates:

```bash
cat subs.txt | dnsgen > candidates.txt
```

* Generate and resolve with dnsx:

```bash
cat subs.txt | dnsgen | dnsx -a -silent > resolved.txt
```

* Generate and resolve with massdns:

```bash
cat subs.txt | dnsgen | massdns -r resolvers.txt -t A -o S -w massdns_out.txt
```

* Split and parallelize:

```bash
cat candidates.txt | split -l 10000 - chunk_
for f in chunk_*; do massdns -r resolvers.txt -t A -o S -w ${f}.out $f & done; wait
```

---

## 16. Final recommendations & best practices

* Always start with **passive enumeration** to build a seed list.
* Feed that seed into **dnsgen** to generate high-value candidates.
* Resolve generated candidates using **massdns** or **dnsx** — tune concurrency and respect rate limits.
* Filter wildcard/parking results early.
* Probe discovered live hosts with **httpx** before deeper scanning.
* Automate and schedule periodic runs to detect newly created assets.
* Store historical results and diff them to detect newly appearing hosts.
