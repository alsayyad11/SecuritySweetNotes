
## 1. What is Chaos?

**Chaos** is a **subdomain discovery and enumeration platform** developed by **ProjectDiscovery** (the team behind tools like `subfinder`, `nuclei`, and `httpx`).

* It provides a **centralized, continuously updated dataset** of **DNS records and subdomains** for millions of domains across the internet.
* The main goal: to help **security researchers, penetration testers, and bug bounty hunters** quickly find subdomains of a target **without brute-forcing**.
* Chaos is **passive**: it does not scan the target in real time. Instead, it collects and aggregates data from:

  * **Certificate Transparency logs (CT logs)**
  * **Passive DNS databases**
  * **Contributions from bug bounty programs**
  * **Open internet scans**
  * **ProjectDiscovery’s own crawling infrastructure**

---

## 2. Why is Chaos Useful?

* **Speed** → Instead of waiting for brute-force enumeration, you instantly get a pre-built dataset.
* **Breadth** → Often finds obscure subdomains that traditional brute-force misses (like `staging.target.com` or `sso.dev.target.com`).
* **Automation-friendly** → Has a CLI and an API for scripting.
* **Open to community** → Researchers contribute domains, so the dataset grows continuously.

---

## 3. Access Methods

You can use Chaos in **3 main ways**:

1. **Web GUI (Docs Site)**

   * The official Chaos site: [https://chaos.projectdiscovery.io/#/](https://chaos.projectdiscovery.io/#/)
   * Provides documentation, examples, and API reference.
   * Great for learning how Chaos works, but not for bulk enumeration.

2. **CLI Client (`chaos`)**

   * A Go-based client you install on your system.
   * Lets you run:

     ```bash
     chaos -d target.com -silent
     ```
   * Returns thousands of subdomains in seconds.

3. **Chaos API (REST)**

   * Programmatic interface for automation.
   * Example (pseudo):

     ```bash
     curl -H "Authorization: <API_KEY>" \
     "https://dns.projectdiscovery.io/dns/fetch?domain=target.com"
     ```

---

## 4. Getting Started with Chaos

### Step 1: Get an API Key

* You need to sign up at **ProjectDiscovery Cloud** → generate an API key.
* This key is used with both the **CLI** and **API**.

### Step 2: Install Chaos CLI

```bash
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

### Step 3: Set Your API Key

```bash
export PDCP_API_KEY="your_api_key"
```

---

## 5. Using the Chaos CLI

### Fetch subdomains

```bash
chaos -d example.com -silent
```

Output:

```
mail.example.com
vpn.example.com
staging.example.com
api.dev.example.com
```

### Save to file

```bash
chaos -d example.com -o subs.txt
```

### Combine with other tools

```bash
chaos -d example.com -silent | dnsx -a -resp
```

(Here, `dnsx` resolves the subdomains to IP addresses.)

---

## 6. Using the Chaos API

### Example: cURL

```bash
curl -s -H "Authorization: $PDCP_API_KEY" \
"https://dns.projectdiscovery.io/dns/fetch?domain=example.com"
```

### Example Response (JSON)

```json
{
  "domain": "example.com",
  "subdomains": [
    "www.example.com",
    "mail.example.com",
    "vpn.example.com"
  ]
}
```

### Example: Python Script

```python
import requests

API_KEY = "your_api_key"
domain = "example.com"

url = f"https://dns.projectdiscovery.io/dns/fetch?domain={domain}"
headers = {"Authorization": API_KEY}

resp = requests.get(url, headers=headers)
data = resp.json()

for sub in data.get("subdomains", []):
    print(sub)
```

---

## 7. GUI Overview

On the Chaos web docs page (`chaos.projectdiscovery.io/#/docs`), you’ll find:

* **Documentation** on installation, API, CLI usage.
* **Search bar & examples** to understand how queries work.
* **Code snippets** (curl, Python, Go).

> ⚠️ Note: The GUI is **not an interactive subdomain search engine** like VirusTotal’s UI — it’s more of a **documentation portal**. For real enumeration, use the **CLI** or **API**.

---

## 8. Real Recon Workflow with Chaos

Let’s say you’re doing recon on `target.com`.

### Step 1: Get subdomains from Chaos

```bash
chaos -d target.com -silent > chaos_subs.txt
```

### Step 2: Merge with other passive sources

```bash
subfinder -d target.com -silent >> chaos_subs.txt
sort -u chaos_subs.txt -o chaos_subs.txt
```

### Step 3: Resolve live hosts

```bash
dnsx -l chaos_subs.txt -resp-only -o resolved.txt
```

### Step 4: Probe for web services

```bash
httpx -l resolved.txt -status-code -title -o webhosts.txt
```

Now you have a **validated list of live web assets** from Chaos + other sources.

---

## 9. Strengths and Limitations

### Strengths

* Large dataset (millions of domains, billions of subdomains).
* Updated continuously.
* Easy to automate.

### Limitations

* **Passive only** → may miss some subdomains not yet seen in datasets.
* **API rate-limiting** → heavy automation requires throttling.
* **Not interactive GUI** → unlike VirusTotal, you can’t just “search” domains in a browser.

---

## 10. Example End-to-End Script

Here’s a full pipeline:

```bash
# Get subdomains from Chaos
chaos -d target.com -silent > chaos.txt

# Merge with crt.sh
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
| jq -r '.[].name_value' | sed 's/\*\.//g' >> chaos.txt

# Deduplicate
sort -u chaos.txt -o all_subs.txt

# Resolve
dnsx -l all_subs.txt -a -o resolved.txt

# Find live HTTP services
httpx -l resolved.txt -o live_http.txt
```

---

# Site : [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io/#/)
