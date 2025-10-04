
# 1) What is Censys 

**Censys** is an internet-wide search engine / dataset that continuously scans the public Internet and indexes the results so researchers can query hosts, services and TLS/SSL certificates. You can search for services, open ports, certificate Subject Alternative Names (SANs) and more — then pivot from one object (a certificate) to related hosts and names. ([docs.censys.com][1])

---

# 2) How Censys collects its data (why it’s powerful)

* **Internet-wide scanning**: Censys performs regular, large-scale scans of IPv4 (and IPv6 discovery via DNS/redirects), fingerprints services and captures application-layer data. That scan data is what the index is built from. ([docs.censys.com][2])
* **ZMap & ZGrab**: historically (and currently in many parts) Censys uses the ZMap/ZGrab tools (ZMap finds responsive hosts; ZGrab performs application-layer handshakes such as TLS) to collect service banners and certificate data. That’s why Censys has very rich TLS/certificate records. ([Censys][3])

Because Censys *actively scans the Internet*, its certificate dataset often contains many subdomains that appear in real certificates (SANs), and its host dataset contains observed hostnames and open services.

---

# 3) Censys datasets you’ll use for subdomain enumeration

* **Certificates** (best for subdomain harvesting): certificates include `names` (CN and SAN entries). Searching certificate records is a high-signal way to surface subdomains because TLS certs often list real hostnames. ([docs.censys.com][4])
* **Hosts (IPv4/IPv6)**: shows hosts, open ports and the names that were observed during scanning (virtual hosts). Useful when a subdomain resolves and you want IP/service context. ([docs.censys.com][5])
* **Websites / web properties** (platform): higher-level web property views and reports (if you have Platform/ASM access). ([docs.censys.com][6])

---

# 4) Query language basics (how to find subdomains in Censys)

Censys has a query language used both in the GUI and the API. For certificates you’ll commonly use fields such as `parsed.names` (or `cert.parsed.names` depending on the dataset/endpoint). Example simple query:

```
parsed.names: example.com
```

That returns certificate records where `example.com` appears in the certificate names (CN/SAN). Censys tokenizes certificate fields so queries like `cert.parsed.subject.common_name` or `cert.names` and `*.common_name` work and can extract subdomain tokens. See the Censys query docs and certificate field definitions for exact field names (they’re documented and searchable). ([docs.censys.com][7])

**Practical query tips**

* `parsed.names:"example.com"` — returns certs that include exactly `example.com`.
* `parsed.names: *.example.com` or `cert.names: example.com` — useful when you want the analyzer to break out subdomain tokens (Censys applies special tokenization for cert fields). ([docs.censys.com][7])
* Use additional filters to reduce noise: e.g. `parsed.names: example.com AND parsed.issuer.common_name: "Let's Encrypt"` to find recently issued certs from a given CA.

---

# 5) GUI (step-by-step, detailed) — fastest for manual reconnaissance

1. Open **[https://search.censys.io](https://search.censys.io)** (or [https://search.censys.io/](https://search.censys.io/) ). Sign in (free account gives limited credits; paid options give more). ([Censys][8])
2. In the UI choose the **Certificates** dataset (dropdown near the search bar).
3. Type a certificate query, for example:

   ```
   parsed.names: example.com
   ```

   and press **Enter**.
4. Browse results: each certificate record shows `parsed.names` (CN + SAN entries). Click a certificate to expand its parsed fields. ([docs.censys.com][9])
5. **Pivot**: from a certificate you can click “View hosts that serve this cert” (or go to the Hosts dataset with the certificate fingerprint) — this reveals IPs & virtual hostnames.
6. **Export / cURL**: the UI offers “Export as cURL” or an API call link in many places; for bulk work use the API. ([Censys][10])

**GUI example workflow (manual):**

* Search `parsed.names: target.com` → copy `parsed.names` entries (you’ll get `www.target.com`, `api.target.com`, etc.) → paste into `all_passive.txt` → dedupe → resolve.

---

# 6) API access & authentication (summary)

Censys offers multiple API surfaces (Legacy Search / v1/v2, Platform v3, and SDKs). Two practical options:

* **Legacy / Search API (v1/v2)** — endpoints like `https://search.censys.io/api/v2/certificates/search` (basic auth with API ID:API Secret). Many people use this for certificate searches and it supports POST/GET with JSON query bodies. ([docs.censys.com][11])
* **Platform APIs (v3) / ASM** — newer Platform APIs use bearer tokens and an explicit `Accept` header to select asset types (hosts, certificates, etc.). If you use the Platform endpoints, follow the API docs for `Accept` headers and OAuth/Bearer usage. ([docs.censys.com][1])

**Free account behaviour / credits:** free accounts have limited monthly credits for searches (the official docs describe free credits per month). Be mindful of quotas. ([docs.censys.com][12])

---

# 7) Concrete examples — GUI, curl, and Python (copy-pasteable)

> I. **GUI** example (manual)
>
> * In Certificates dataset search bar:
>   `parsed.names: target.com`
> * Click records, expand `parsed.names` and copy hostnames.

---

> II. **curl → v2 certificates search (basic auth)**
> Replace `CENSYS_API_ID` and `CENSYS_API_SECRET` with your credentials (legacy/v2 style). This example uses the v2 certificates search endpoint and requests page 1 with 100 results. The endpoint supports POST JSON payload for larger queries.

```bash
export CENSYS_API_ID="your_id"
export CENSYS_API_SECRET="your_secret"

curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
  -X POST "https://search.censys.io/api/v2/certificates/search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "parsed.names: target.com",
    "per_page": 100
  }' \
| jq '.results[] | .parsed.names'   # prints parsed.names arrays for each certificate
```

If the response includes a `cursor` (or `links.next`), use it to fetch the next page. (See SDK examples below for pagination helpers.) ([docs.censys.com][11])

---

> III. **Python — using the official `censys` Python package (recommended)**
> Install:

```bash
pip install censys
```

Example script — *search certificates for `target.com`, extract names, dedupe and save to `censys_subs.txt`*. This uses the `censys.search` v2 wrapper (the SDK handles auth and pagination helpers).

```python
# censys_certs_extract.py
# Requires: pip install censys
import os
from censys.search import CensysCerts  # v2 search wrapper
from time import sleep

CENSYS_ID = os.getenv("CENSYS_API_ID")
CENSYS_SECRET = os.getenv("CENSYS_API_SECRET")
if not (CENSYS_ID and CENSYS_SECRET):
    raise SystemExit("Set CENSYS_API_ID and CENSYS_API_SECRET in environment")

c = CensysCerts(api_id=CENSYS_ID, api_secret=CENSYS_SECRET)

query = 'parsed.names: target.com'
per_page = 100
cursor = None
seen = set()

while True:
    resp = c.raw_search(query, per_page=per_page, cursor=cursor)  # raw_search returns results + cursor
    results = resp.get("results", [])
    for cert in results:
        # parsed.names is the typical field containing CN + SANs
        names = cert.get("parsed", {}).get("names", []) or cert.get("parsed.names") or []
        for n in names:
            seen.add(n.strip().lower())
    cursor = resp.get("cursor") or resp.get("links", {}).get("next")
    if not cursor:
        break
    sleep(1)  # be polite; respect your quota and SDK guidance

# save final list
with open("censys_subs.txt", "w") as fh:
    for name in sorted(seen):
        fh.write(name + "\n")

print(f"Saved {len(seen)} names to censys_subs.txt")
```

Notes:

* The `censys` SDK abstracts auth and supports `raw_search` / `search_get` / `search_post` / pagination via `cursor`. See SDK docs for exact method names. ([censys-python.readthedocs.io][13])
* Increase `per_page` up to allowed max if your account supports it; watch credits.

---

# 8) Pagination, quotas & polite automation

* **Pagination:** v2/v3 APIs return either a `cursor` token or `links.next`. Use the token exactly as returned — don't try to guess offsets. The official SDKs expose helpers for iterating pages. ([censys-python.readthedocs.io][14])
* **Credits & rate limits:** free accounts have monthly credits (the docs explain the free allotment). Some endpoints rate-limit how fast you can page; back off on `429`. Always check the `account` or `quota` API call to see your remaining credits. ([docs.censys.com][12])
* **Politeness:** If you automate a large job, stagger queries (sleep or use a scheduler), cache results locally, and upgrade to a paid plan if you need bulk extraction.

---

# 9) How to merge Censys results into a full recon pipeline (practical, step-by-step)

1. **Harvest**: use Censys Certificates search → collect `parsed.names` hostnames.
2. **Combine**: combine with other passive sources (crt.sh, VirusTotal, Amass, Subfinder, SecurityTrails).

   ```bash
   cat censys_subs.txt vt_subs.txt crt_subs.txt other.txt | sort -u > all_passive.txt
   ```
3. **Resolve**: find active hosts (`dnsx` / `massdns`):

   ```bash
   dnsx -l all_passive.txt -a -o resolved.txt
   ```
4. **Probe HTTP**: find live web endpoints (`httpx`):

   ```bash
   httpx -l resolved.txt -status-code -o live_http.txt
   ```
5. **Contextualize**: for each live host, check Censys host record (open ports, banners) and cross-reference certificate records to see who issued the cert and when. Prioritize targets that are live and have suspicious associations (unexpected cert issuers, expired certs, service banners that match interesting software, etc.).
6. **Authorize & test**: obtain permission before active scanning (port scans, fuzzing).

Why this order? Censys gives observed names (passive) → DNS resolves turn them actionable → HTTP/Banner probes reveal attack surface → prioritized targets get tested with permission.

---

# 10) Examples of useful Censys queries (starter list)

* Subdomains from certificates:

  ```
  parsed.names: example.com
  ```
* Narrow to a CA (reduce noise):

  ```
  parsed.names: example.com AND parsed.issuer.common_name: "Let's Encrypt"
  ```
* Find certs with wildcard SANs:

  ```
  parsed.names: *.example.com
  ```
* Find hosts serving a cert:

  * Use the certificate fingerprint then pivot to the Hosts dataset (GUI or `/view` endpoint).

(Use the Censys query examples page for many more real queries and patterns.) ([Censys][15])

---

# 11) Common gotchas, limitations & defensive notes

* **Not exhaustive**: Censys is powerful but not all-seeing. Combine other passive sources (CT logs/crt.sh, VirusTotal, PassiveDNS).
* **Wildcard & generic certs**: Many certs (especially from providers or CDNs) cover many hostnames; you’ll see lots of unrelated subdomains. Use filtering (e.g., issuer, validity window) to reduce noise.
* **Ephemeral names**: LetsEncrypt and automated issuance causes a flood of certs; some names appear only briefly. Validate with DNS/http probes.
* **Privacy / legality**: Censys *scans the public internet* and publishes scanned metadata. Don’t use it as an excuse for unauthorized scanning of third-party properties — when you move to active tests, obtain permission.
* **Quotas**: Free tier limits mean large extractions require paid access or careful scheduling. Check `account/quota` endpoints to monitor usage. ([docs.censys.com][12])

---

# 12) Quick “two-minute” actionable checklist

1. Sign up for Censys, get API credentials. ([Censys][10])
2. Run a certificates query: `parsed.names: target.com`. Copy SANs → `censys_subs.txt`. ([docs.censys.com][9])
3. Merge with other passive results and dedupe.
4. Resolve (`dnsx`) → probe (`httpx`) → prioritize.
5. For automation use the `censys` Python package (examples above) or `curl` to the v2 search endpoint. Monitor credits. ([censys-python.readthedocs.io][13])

---

# 13) Want me to generate anything else *right now*?

I can **immediately** (no waiting) paste one of these (pick any and I’ll paste it now):

* A production-ready Python script (using the `censys` SDK) that: authenticates, paginates, caches results to SQLite, and runs `dnsx/httpx` on the final host list.
* A compact **shell pipeline**: curl → jq → dedupe → dnsx → httpx (fully formed ready to run).
* An **amass/subfinder** config snippet and step-by-step to integrate Censys as a passive source.

(You don’t need to answer any setup question — tell me which option number you want and I’ll paste it right away.)

---

# Sources / further reading (official docs & SDKs)

* Get started & Platform API docs — Censys. ([docs.censys.com][1])
* Censys scanning & how data is collected (ZMap/ZGrab). ([Censys][3])
* Certificates parsed fields & definitions (parsed.names etc.). ([docs.censys.com][9])
* Legacy / Search API (v2) and endpoints (certificates search examples). ([docs.censys.com][11])
* `censys` Python SDK usage & pagination (`raw_search`, `cursor`). ([censys-python.readthedocs.io][13])
* Free credits & account quotas documentation. ([docs.censys.com][12])

---
# Reference : [Guide](https://github.com/christophetd/censys-subdomain-finder)
