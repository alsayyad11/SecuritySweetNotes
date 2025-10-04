
![n](https://github.com/user-attachments/assets/53ba2ecf-36ed-47d9-84fd-5146d0ed8909)

# What *VirusTotal*  

VirusTotal is a security intelligence platform that aggregates scans, telemetry, and user submissions around files, URLs, domains, and IPs — and models relationships between those objects so you can pivot from one object to related objects (for example, from a malicious file to the domain it contacted). ([VirusTotal Docs][1])

## 1.1 Architecture & data sources (how VT sees the world)

VirusTotal’s dataset is the result of many feeds and sources, including:

* **Antivirus and URL scanning engines** — results from dozens of AV and URL scanners when files/URLs are analyzed.
* **User/submission telemetry and sandboxes** — files and URLs uploaded by researchers and users, and sandbox runs that reveal network callbacks.
* **Partner telemetry & passive DNS** — feeds from partners that report observed DNS resolutions, certificate observations, and network activity.
* These combined sources are indexed and linked so objects become queryable (files ↔ URLs ↔ domains ↔ IPs). The platform exposes this data both through a **web GUI** for interactive pivoting and through a **programmatic API (v3)**. ([VirusTotal Docs][1])

## 1.2 Object model — *Objects* and *Relationships*

* VT models *objects* (file hash, URL object, domain object, IP object) and *relationships* between objects (for example, “this file contacted this domain”, or “this domain has these subdomains”).
* The relationships API is central: you request a relationship of an object (for example `/domains/{domain}/subdomains`) to retrieve related objects. This is how you get subdomains programmatically. ([VirusTotal Docs][2])

## 1.3 Why VirusTotal is useful for reconnaissance

* It’s a **passive intelligence source** — you query their database instead of actively probing the target (less noisy).
* It often contains **observed** (not guessed) subdomains collected from real telemetry (e.g., malware C2 callbacks, sandbox network activity, passive DNS), which makes the entries actionable and contextual.
* But it is **not exhaustive** — combine it with other passive sources (crt.sh, certificate transparency, passive DNS providers) for better coverage.

---

# Subdomain enumeration using VirusTotal 

This section breaks the problem into: **how VT acquires subdomains**, **GUI steps with precise clicks and what each panel shows**, **API usage with concrete examples (curl & Python)**, **pagination, rate limits and backoff**, **workflow to validate & prioritize**, **integration examples**, and **practical gotchas**.

---

## 2.1 How VirusTotal collects subdomain information — briefly, so you understand results

* Subdomains appearing in VT are typically *observed* by one of VT’s telemetry sources: sandbox runs that invoked domain names, passive DNS feeds, certificates seen in the wild, or user-submitted data. That gives VT a list of *observed* subdomains (not guesses produced by brute-force wordlists). This means VT’s subdomains are often evidence-backed (e.g., a malware sample reached `c2.example.com`). ([VirusTotal Docs][1])

---

## 2.2 GUI (web interface) — step-by-step manual workflow

Use this when you want to **pivot visually** and examine context (files, URLs, resolutions) quickly.

1. **Sign in** at `https://www.virustotal.com`. Signing in gives you slightly richer context and full Relations access.
2. **Search**: paste the domain into the top search bar (e.g., `target.com`) and press Enter. You land on the **Domain Overview**. ([VirusTotal Docs][1])
3. **Overview panel**: shows domain reputation, categories, summary stats, and small quick links (last seen, tags). This is a high-level snapshot.
4. **Open the `Relations` tab** (sometimes labeled “Graph” / “Visualizer”) — this is the interactive graph view that shows linked objects. Expand the node for your domain. ([VirusTotal Docs][2])
5. **Find the Subdomains section** inside Relations. It will display “direct” subdomains observed by VT for that domain. Click each subdomain in the list or graph to pivot to:

   * **URLs** observed under that subdomain,
   * **Files/samples** that contacted it,
   * **Resolutions** (historical IPs), and
   * **Graph neighbors** (other domains/files that share the same IPs or samples). ([VirusTotal Docs][3])
6. **Resolutions tab**: shows historical A/AAAA records — useful to spot hosting changes or shared hosting.
7. **Files/URLs** tabs: see malware or suspicious URLs connected to the subdomain (this directly informs prioritization).
8. **Export**: The GUI is not convenient for bulk export; for automation use the API. For a quick manual list you can copy/paste the subdomain list.

**GUI example:** search `example.com` → Relations → Subdomains → you see entries like `dev.example.com`, `api.example.com`. Click `dev.example.com` → view files that contacted it and historical resolutions.

---

## 2.3 API — canonical endpoint and exact usage

### 2.3.1 Canonical subdomains relationship endpoint

To retrieve **direct subdomains**:

```
GET https://www.virustotal.com/api/v3/domains/{domain}/subdomains
```

This relationship **returns direct subdomains only** (it is not recursive). To discover deeper sub-subdomains you must query newly discovered subdomains in turn. ([VirusTotal Docs][3])

### 2.3.2 Authentication & general response format

* Use your API key in header: `x-apikey: YOUR_API_KEY`.
* Responses are JSON; successful responses include a top-level `data` array with object entries. See API responses docs for structure. ([VirusTotal Docs][4])

### 2.3.3 Rate limits, public vs private API

* Public (free/community) API constraints: **≈ 4 requests per minute** and **500 requests per day**. Do not exceed these limits; design your scripts accordingly and add backoff handling for `429` responses. For large-scale or commercial use, consider the private/premium API. ([VirusTotal Docs][5])

---

## 2.4 Practical examples — curl and Python (paginated & rate-limit aware)

### Example A — Quick `curl` one-line (single page)

This prints subdomain IDs (works for small results):

```bash
curl -s -H "x-apikey: $VT_API_KEY" \
 "https://www.virustotal.com/api/v3/domains/example.com/subdomains" \
 | jq -r '.data[].id'
```

If the result is paginated you must follow `links.next` in the response.

---

### Example B — Robust Python script (production-grade, paginated, backoff)

This script:

* follows `links.next` pagination,
* enforces a minimum delay to respect free tier (default 15s),
* implements exponential backoff on 429/5xx,
* optionally does recursive expansion (dangerous for quota — use cautiously),
* writes outputs to files.

> Save as `vt_subdomains_fetcher.py`. Set your API key in the environment `export VT_API_KEY="..."` before running.

```python
#!/usr/bin/env python3
"""
vt_subdomains_fetcher.py
Fetch direct subdomains from VT (handles pagination + rate limits).
Usage: export VT_API_KEY="..." ; python3 vt_subdomains_fetcher.py target.com --outdir out
"""

import os, time, argparse, requests, json

BASE = "https://www.virustotal.com/api/v3"
API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise SystemExit("Set VT_API_KEY in environment")

HEADERS = {"x-apikey": API_KEY, "Accept": "application/json"}

# Politeness/rate-limiting defaults for public API
MIN_DELAY = 15.0    # seconds; roughly 4 requests / min
MAX_RETRIES = 5
BACKOFF_BASE = 2.0

def get_json_with_backoff(url, params=None):
    delay = MIN_DELAY
    for attempt in range(1, MAX_RETRIES+1):
        r = requests.get(url, headers=HEADERS, params=params, timeout=30)
        if r.status_code == 200:
            time.sleep(MIN_DELAY)  # ensure spacing between successful calls
            return r.json()
        if r.status_code == 429:
            wait = delay * BACKOFF_BASE
            print(f"[!] 429 rate limited; sleeping {wait}s (attempt {attempt})")
            time.sleep(wait)
            delay *= BACKOFF_BASE
            continue
        if 500 <= r.status_code < 600:
            wait = delay * BACKOFF_BASE
            print(f"[!] {r.status_code} server error; sleeping {wait}s (attempt {attempt})")
            time.sleep(wait)
            delay *= BACKOFF_BASE
            continue
        # other errors: show and break
        print("[!] HTTP", r.status_code, r.text)
        return None
    return None

def fetch_direct_subdomains(domain):
    url = f"{BASE}/domains/{domain}/subdomains"
    collected = []
    while url:
        j = get_json_with_backoff(url)
        if not j:
            break
        for item in j.get("data", []):
            collected.append(item.get("id"))
        # pagination: follow links.next if present
        links = j.get("links", {})
        url = links.get("next")
    return sorted(set(collected))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--outdir", default=".")
    ap.add_argument("--recursive", action="store_true",
                    help="Query each discovered subdomain for its direct subdomains (careful with quota)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    print(f"[+] fetching direct subdomains of {args.domain}")
    subs = fetch_direct_subdomains(args.domain)
    print(f"[+] found {len(subs)} direct subdomains")
    all_subs = set(subs)

    if args.recursive:
        queue = list(subs)
        while queue:
            s = queue.pop(0)
            print(f"[>] expanding {s}")
            found = fetch_direct_subdomains(s)
            for f in found:
                if f not in all_subs:
                    all_subs.add(f)
                    queue.append(f)

    out_file = os.path.join(args.outdir, f"{args.domain}_subdomains.txt")
    with open(out_file, "w") as fh:
        fh.write("\n".join(sorted(all_subs)))
    print(f"[+] saved {len(all_subs)} entries to {out_file}")

if __name__ == "__main__":
    main()
```

**Explanation of important choices**

* `MIN_DELAY=15s` is conservative to respect the public limit of ~4 requests/minute. Adjust only if you have a higher-quota plan. ([VirusTotal Docs][5])
* **Pagination**: follow `links.next` in the JSON to retrieve all pages (per VT v3 semantics). ([VirusTotal Docs][4])
* **Recursive mode**: multiplies API calls fast — use only with permission/quota.

---

### Example C — vt-py (official Python client)

The official client `vt-py` provides higher-level helpers and manages connections:

```python
import vt

client = vt.Client("YOUR_API_KEY")
# the client has methods to get relationships
it = client.get_iterator("/domains/example.com/subdomains")
for item in it:
    print(item.id)
client.close()
```

Using `vt-py` is recommended for production code because it handles internal details; see the vt-py docs. ([virustotal.github.io][6])

---

## 2.5 Pagination & common response fields — detailed notes

* Most v3 endpoints return JSON with a top-level `data` and optionally a `links` object. When the result set is large, `links.next` provides the next-page URL — call it until absent. This is the standard v3 approach for relationships. ([VirusTotal Docs][4])
* Do NOT try to construct next-page URLs manually; use the `links.next` value returned by VT.

---

## 2.6 Rate-limits & best practices (very important)

* **Public API limits**: ~4 requests/min, 500/day. Exceeding returns `429`. For production/bulk use get a private/premium key or throttle requests heavily. ([VirusTotal Docs][5])
* **Politeness patterns**:

  * Add a fixed minimum delay (15s) between *successful* requests.
  * On `429`, apply exponential backoff (sleep longer and retry).
  * Cache responses locally; avoid repeat queries.
  * Batch work: collect required domains and query them over hours/days rather than in a short loop.
* **Do not** create multiple free accounts to get around limits — VT forbids that.

---

## 2.7 Practical end-to-end recon pipeline (how you actually use VT subdomains)

1. **Harvest passive data**:

   * VirusTotal (Relations → Subdomains / API)
   * Certificate Transparency (`crt.sh`), Passive DNS providers, Search engines (Bing/Dogpile), Shodan, SecurityTrails.

2. **Merge & dedupe**:

   ```bash
   cat vt_subs.txt crt_subs.txt other_sources.txt | sort -u > all_passive.txt
   ```

3. **DNS resolution (to actionable IPs)**:

   * Use `dnsx` or `massdns` to resolve all the names quickly:

   ```
   dnsx -l all_passive.txt -a -o resolved.txt
   ```

   Keep only hosts that resolve.

4. **HTTP probing**:

   * Use `httpx` to check which hosts serve HTTP/HTTPS and gather status codes / titles / techs:

   ```
   httpx -l resolved.txt -status-code -title -o live_http.txt
   ```

5. **Prioritize with VT context**:

   * For hosts that are **live**, check VT again (GUI or API) for files or URLs related to that host. Hosts referenced by malware samples or flagged URLs should be higher priority.

6. **Authorize and scan (only with permission)**:

   * If you have permission, run port/service scans (e.g., `nmap -sV`) on prioritized hosts.

**Reasoning behind this order:** VirusTotal gives observed names (passive) → resolution filters actionable targets → HTTP probing gives surface endpoints → VT associations provide risk context.

---

## 2.8 Integrations with popular recon tools (how to make it automatic)

* **Amass**: configure API key in `~/.config/amass/config.ini` and include the VT source; Amass will query VT along with many passive sources.
* **Subfinder**: add VT as a provider in `provider-config.yaml` so Subfinder queries VT automatically.
* **Custom pipelines**: call the VT API in scripts and pipe outputs to `dnsx`/`httpx`/`nmap`.

---

## 2.9 Limitations, gotchas, and how to avoid mistakes (practical advice)

* **Direct only**: `/domains/{domain}/subdomains` returns direct subdomains only — it will not produce `a.b.example.com` unless it's directly observed as a subdomain of `example.com`. To find deeper levels you must query each result separately — be mindful of quota. ([VirusTotal Docs][3])
* **Incomplete coverage**: VT is not canonical. Complement with CT logs, passive DNS and cert transparency.
* **Stale / ephemeral names**: some entries come from a one-off malware sample; validate with DNS/http before investing time.
* **Quota exhaustion**: do not run recursive expansion across hundreds of domains on a free key — you will hit limits quickly. Use caching and time-spread tasks. ([VirusTotal Docs][5])
* **Privacy & activity logging**: queries are visible in your VT account history — if that matters for your operational security, plan accordingly.

---

## 2.10 Quick troubleshooting & FAQ

* *Q: I got no `links.next` but suspect more results.* → The endpoint returned a single page; confirm `meta` fields if present. For large datasets VT may require different endpoints (enterprise). ([VirusTotal Docs][4])
* *Q: I hit `429` rapidly.* → Back off, wait, and implement exponential backoff; also check you are not calling the endpoint in parallel from multiple processes. ([VirusTotal Docs][5])
* *Q: I want deeper context than subdomains (files/URLs). How?* → Use other relationships (`/domains/{domain}/relationships/urls` or query the domain report) and pivot from returned object IDs. See VT relationships docs. ([VirusTotal Docs][2])

---

# PART 3 — Authoritative citations (most important claims)

1. Canonical **subdomains** relationship and the fact it returns *direct* subdomains only. ([VirusTotal Docs][3])
2. VirusTotal **overview**: it provides domain reports, URL/file analysis and the relationships model. ([VirusTotal Docs][1])
3. **Public API limits**: the public API is constrained (≈ 4 requests/min and 500 requests/day). ([VirusTotal Docs][5])
4. **Relationships** are the way VT links objects (domain → subdomains, file → URLs, etc.). Use the relationships API to pivot. ([VirusTotal Docs][2])
5. **vt-py**: vt-py is the official Python client for VT v3 (recommended helper library). ([virustotal.github.io][6])

---

# PART 4 — Short, copy-paste practical snippets

### curl single-page:

```bash
curl -s -H "x-apikey: $VT_API_KEY" \
 "https://www.virustotal.com/api/v3/domains/target.com/subdomains" \
 | jq -r '.data[].id' > vt_subs.txt
```

### python (quick, not production):

```python
import os, requests
API_KEY = os.getenv("VT_API_KEY")
h = {"x-apikey": API_KEY}
r = requests.get("https://www.virustotal.com/api/v3/domains/target.com/subdomains", headers=h)
for i in r.json().get("data", []):
    print(i["id"])
```

### combine + validate:

```bash
cat vt_subs.txt crt_subs.txt | sort -u > all_passive.txt
dnsx -l all_passive.txt -a -o resolved.txt
httpx -l resolved.txt -status-code -o live_http.txt
```

---


# Reference  : [VTDOC](https://docs.virustotal.com/)
