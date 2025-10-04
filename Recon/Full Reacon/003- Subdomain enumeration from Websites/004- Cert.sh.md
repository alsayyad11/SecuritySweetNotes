
## 1. What is crt.sh?

* **crt.sh** is a **free, open Certificate Transparency (CT) log search engine** operated by [Sectigo (formerly Comodo CA)](https://crt.sh/).
* It allows you to search **digital certificates** issued by Certificate Authorities (CAs).
* Since SSL/TLS certificates often list **domain names and subdomains**, crt.sh becomes an excellent resource for **discovering subdomains** during reconnaissance.

Think of crt.sh as a **search engine for SSL/TLS certificates**.

---

## 2. Why is crt.sh useful for Subdomain Enumeration?

* **Certificates must list domain names** → This exposes subdomains like `mail.target.com`, `vpn.target.com`, or even staging environments.
* **Publicly available** → No login or API key needed (completely free).
* **Updated in near real-time** → New certs are logged within minutes.
* **Large dataset** → Covers most certificates issued by trusted CAs worldwide.

⚠️ Limitation: It only shows subdomains that have certificates. Internal-only or non-HTTPS subdomains may not appear.

---

## 3. How to Use crt.sh (Web GUI)

Go to: [https://crt.sh](https://crt.sh)

### Example: Search for `target.com`

* Input: `target.com`
* Results:

  * Certificates for `www.target.com`
  * Certificates for `mail.target.com`
  * Certificates for `api.dev.target.com`

### Tricks:

1. **Wildcard Search (`%`)**

   * Query: `%target.com`
   * Finds all subdomains like `*.target.com`

2. **Exact Subdomain Search**

   * Query: `mail.target.com`
   * Finds only certificates mentioning that subdomain.

3. **Exclude Expired Certificates**

   * Check “Exclude expired” to see only active certificates.

4. **Output Formats**

   * crt.sh can output JSON, which is great for automation:

     ```
     https://crt.sh/?q=%25.target.com&output=json
     ```

---

## 4. Using crt.sh for Automation (API-like JSON)

Even though crt.sh doesn’t have an official API, it provides a **JSON output option**.

### Example: Fetch JSON with curl

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json"
```

### Example Output

```json
[
  {
    "issuer_ca_id": 1234,
    "issuer_name": "Let's Encrypt",
    "common_name": "www.target.com",
    "name_value": "www.target.com",
    "not_before": "2025-09-01",
    "not_after": "2025-12-01"
  },
  {
    "issuer_name": "DigiCert",
    "common_name": "mail.target.com",
    "name_value": "mail.target.com"
  }
]
```

### Extract just subdomains

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
| jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

Output:

```
mail.target.com
vpn.target.com
staging.target.com
api.dev.target.com
```

---

## 5. Using crt.sh with Python

```python
import requests

domain = "target.com"
url = f"https://crt.sh/?q=%25.{domain}&output=json"

resp = requests.get(url)
data = resp.json()

subdomains = set()
for entry in data:
    names = entry["name_value"].split("\n")
    for n in names:
        subdomains.add(n.replace("*.",""))

print("\n".join(sorted(subdomains)))
```

---

## 6. Recon Workflow with crt.sh

Let’s say your target is `target.com`.

1. **Extract Subdomains with crt.sh**

   ```bash
   curl -s "https://crt.sh/?q=%25.target.com&output=json" \
   | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt_subs.txt
   ```

2. **Combine with other passive sources**

   ```bash
   chaos -d target.com -silent >> crt_subs.txt
   subfinder -d target.com -silent >> crt_subs.txt
   sort -u crt_subs.txt -o all_subs.txt
   ```

3. **Resolve Valid Hosts**

   ```bash
   dnsx -l all_subs.txt -a -o resolved.txt
   ```

4. **Probe HTTP Services**

   ```bash
   httpx -l resolved.txt -title -status-code -o webhosts.txt
   ```

---

## 7. Strengths & Limitations

### Strengths

* Free and public.
* Doesn’t require API keys or sign-up.
* Near real-time certificate data.
* Can be automated with JSON output.

### Limitations

* Only shows **certified subdomains** → if a subdomain never had a certificate, it won’t appear.
* Includes **expired or revoked certificates** (filtering needed).
* Rate-limiting → heavy use may get temporarily blocked.

---

## 8. Example: End-to-End Recon with crt.sh

```bash
# 1. Fetch subdomains from crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
| jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt_subs.txt

# 2. Resolve
dnsx -l crt_subs.txt -a -o resolved.txt

# 3. Probe HTTP
httpx -l resolved.txt -status-code -o live_hosts.txt
```

Result: You now have a **list of live, valid subdomains** for `target.com` discovered via SSL certificates.

---
# Site : [cert.sh](https://crt.sh/)
