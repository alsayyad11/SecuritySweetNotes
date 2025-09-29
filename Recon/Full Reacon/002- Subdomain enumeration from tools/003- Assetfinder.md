
## 1. What Assetfinder Is

* **Assetfinder** is a **subdomain enumeration tool** created by *Tomnomnom* (a well-known security researcher).
* It automates the discovery of subdomains related to a given domain.
* It queries multiple public sources (like crt.sh, certspotter, virustotal, etc.) and aggregates the results.

This is extremely useful in:

* **Bug bounty hunting** → finding attack surface beyond the main domain.
* **Penetration testing** → identifying hidden apps, staging environments, dev/test portals.
* **Reconnaissance** → mapping the target organization’s assets.

---

## 2. How It Works (under the hood)

Assetfinder works by:

1. Taking a **root domain** (e.g., `example.com`).
2. Querying multiple **online sources/APIs** like:

   * **crt.sh** (Certificate Transparency logs)
   * **certspotter**
   * **Virustotal**
   * **Archive.org**
   * **Facebook certificate transparency**
   * **Other passive subdomain sources**
3. Returning a list of **discovered subdomains**.
4. Printing them line by line so you can easily pipe results into other tools (`httprobe`, `httpx`, etc.).

---

## 3. Installation

### On Linux

```bash
sudo apt update
sudo apt install golang-go -y
go install github.com/tomnomnom/assetfinder@latest
```

* The binary will be placed in `~/go/bin/assetfinder`.
* Add it to your PATH:

  ```bash
  export PATH=$PATH:~/go/bin
  ```

### Verify installation

```bash
assetfinder -h
```

You should see help options.

---

## 4. Basic Usage

```bash
assetfinder example.com
```

* This command queries multiple sources and prints discovered subdomains.
* Example output:

  ```
  www.example.com
  mail.example.com
  dev.example.com
  test.example.com
  ```

By default, Assetfinder finds **related domains** too (not just strict subdomains).

---

## 5. Restrict to Subdomains Only

Sometimes Assetfinder gives domains *related* to the target (not only subdomains).
Use `--subs-only` to filter:

```bash
assetfinder --subs-only example.com
```

Output:

```
www.example.com
api.example.com
portal.example.com
```

This is cleaner for bug bounty use.

---

## 6. Practical Examples

### Example 1: Save output to file

```bash
assetfinder --subs-only example.com > subs.txt
```

Now `subs.txt` contains all discovered subdomains.

---

### Example 2: Combine with httprobe (check live hosts)

```bash
assetfinder --subs-only example.com | httprobe
```

This finds subdomains and immediately probes for live HTTP(S) services.

---

### Example 3: Combine with httpx (advanced probing)

```bash
assetfinder --subs-only example.com | httpx -title -status-code -content-length
```

This gives you:

* Status codes (200, 301, 403…)
* Page titles
* Content lengths

---

### Example 4: Filtering with grep

```bash
assetfinder --subs-only example.com | grep "dev"
```

This filters only subdomains containing "dev".

---

### Example 5: Mass recon with multiple domains

```bash
for domain in $(cat domains.txt); do
  assetfinder --subs-only $domain >> all_subs.txt
done
```

This runs Assetfinder against a list of domains.

---

## 7. Strengths and Limitations

### Strengths

* **Very fast** (because it uses passive sources, no brute force).
* **Simple** — one command does the job.
* **Good integration** — works well in pipelines with other tools (`httprobe`, `httpx`, `gf`).
* **Lightweight** — Go binary, no big dependencies.

### Limitations

* **Passive only** → If no sources report the subdomain, Assetfinder won’t find it.
* **No brute force** → Unlike `dnsx` or `subfinder`, it doesn’t try dictionary-based enumeration.
* **No recursive mode** → Won’t enumerate deeper (e.g., sub-subdomains).

That’s why bug hunters usually **combine Assetfinder with Subfinder, Amass, and DNS brute-forcing** for better coverage.

---

## 8. Workflow in Bug Bounty

Typical workflow using Assetfinder:

```bash
# Step 1: Find subdomains
assetfinder --subs-only target.com > subs.txt

# Step 2: Filter unique
sort -u subs.txt -o subs.txt

# Step 3: Probe live hosts
cat subs.txt | httprobe > live.txt

# Step 4: Scan for vulnerabilities
cat live.txt | nuclei -t ~/nuclei-templates/
```

---

## 9. Comparison with Similar Tools

| Tool            | Features                                   | Pros                                | Cons                      |
| --------------- | ------------------------------------------ | ----------------------------------- | ------------------------- |
| **Assetfinder** | Passive sources only                       | Very fast, lightweight, easy to use | Limited coverage          |
| **Subfinder**   | Passive + some brute force                 | More sources, active enumeration    | Slightly slower           |
| **Amass**       | Passive + active + brute force + recursive | Most comprehensive                  | Heavy, resource-intensive |

So:

* Use **Assetfinder** for **quick & lightweight recon**.
* Use **Amass/Subfinder** for **deep recon**.

---

## 10. Best Practices

* Always run Assetfinder with `--subs-only` for bug bounty.
* Deduplicate output (`sort -u`).
* Always follow up with a **live check tool** (`httprobe`, `httpx`).
* Combine with **dnsx** (from ProjectDiscovery) for DNS resolution.
* Run it alongside **Subfinder + Amass** to maximize coverage.

---

## 11. Example One-Liner Recon Pipeline

```bash
assetfinder --subs-only example.com | sort -u | tee subs.txt | httprobe | tee live.txt | httpx -title -status-code -content-length
```

This:

1. Finds subdomains.
2. Removes duplicates.
3. Saves to `subs.txt`.
4. Finds live hosts.
5. Saves to `live.txt`.
6. Runs httpx for titles, status codes, content length.

---

## 12. When to Use Assetfinder vs Others

* **Quick checks** before bounty scope closes.
* **Fast recon** during live hacking events.
* **Initial mapping** before running heavier tools.
* If you’re scripting automation pipelines (because it’s fast and clean).
