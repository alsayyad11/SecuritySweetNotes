## 1. Introduction

**Knockpy** is a Python-based tool used for **subdomain enumeration**. Unlike Sublist3r (which is mainly passive), Knockpy is built to perform **dictionary-based brute force** of subdomains against a target domain.

* **Purpose:** Discover hidden subdomains of a domain by trying possible names from a **wordlist**.
* **Type:** Mostly **active enumeration** (brute-forcing), but can integrate with passive sources.
* **Why important:** Some sensitive subdomains (`admin.example.com`, `dev.example.com`) are never indexed by search engines. Only brute force or certificate transparency will reveal them.
* **Target audience:** Bug bounty hunters, penetration testers, red teamers.

---

## 2. Installation

### Requirements

* Python 3
* `git`, `pip`
* A subdomain wordlist (like `SecLists`)

### Installation steps

```bash
# clone repo
git clone https://github.com/guelfoweb/knock.git
cd knock

# install dependencies
pip install -r requirements.txt

# check help
python3 knockpy.py -h
```

If installed correctly, you’ll see available options.

---

## 3. How Knockpy Works (Internals)

1. Takes a **target domain** (e.g., `example.com`).
2. Loads a **wordlist** of possible subdomains (`www`, `mail`, `dev`, `api`).
3. Iterates through each word and queries DNS records (`A`, `CNAME`) to check if it resolves.
4. If resolution is successful, it means the subdomain exists.
5. Saves results into a file/database for further analysis.

---

## 4. Basic Usage

### Scan a domain

```bash
python3 knockpy.py example.com
```

* Uses the **default wordlist** shipped with Knockpy.
* Discovers subdomains that exist.

### Use a custom wordlist

```bash
python3 knockpy.py example.com -w /path/to/wordlist.txt
```

* Replace `/path/to/wordlist.txt` with something like `SecLists/Discovery/DNS/subdomains-top1million-5000.txt`.

### Save results to a file

```bash
python3 knockpy.py example.com -o results.json
```

* Supports **JSON output** for easy parsing.

---

## 5. Options and Parameters

| Flag | Description                                              | Example           |
| ---- | -------------------------------------------------------- | ----------------- |
| `-d` | Domain (can be omitted if first argument)                | `-d example.com`  |
| `-w` | Path to custom wordlist                                  | `-w wordlist.txt` |
| `-o` | Output results file                                      | `-o results.json` |
| `-r` | Recursive mode (try brute forcing discovered subdomains) | `-r`              |
| `-h` | Help menu                                                | `-h`              |

---

## 6. Workflow (Step by Step)

Let’s say your target is `tesla.com`.

### Step 1 — Run Knockpy with default wordlist

```bash
python3 knockpy.py tesla.com
```

* Discovers `shop.tesla.com`, `energy.tesla.com`, `inventory.tesla.com`.

### Step 2 — Run with a bigger wordlist

```bash
python3 knockpy.py tesla.com -w ~/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
```

* Might reveal hidden gems like `admin.tesla.com`, `vpn.tesla.com`.

### Step 3 — Recursive scan

```bash
python3 knockpy.py dev.tesla.com -r
```

* Brute-forces **nested subdomains** like `test.dev.tesla.com`.

### Step 4 — Save output for later

```bash
python3 knockpy.py tesla.com -o tesla_results.json
```

---

## 7. Example Output

Sample output:

```
[+] Discovered subdomains for tesla.com:
- www.tesla.com        104.18.10.12
- shop.tesla.com       104.18.15.44
- api.tesla.com        104.18.20.19
- vpn.tesla.com        104.18.21.31
```

JSON format:

```json
{
  "domain": "tesla.com",
  "subdomains": [
    {"name": "www.tesla.com", "ip": "104.18.10.12"},
    {"name": "shop.tesla.com", "ip": "104.18.15.44"},
    {"name": "vpn.tesla.com", "ip": "104.18.21.31"}
  ]
}
```

---

## 8. Strengths and Weaknesses

**Strengths**

* Brute force capability (finds hidden/unindexed subs).
* Recursive enumeration.
* JSON output (easy automation).
* Simple and straightforward.

**Weaknesses**

* Slower than passive tools (because DNS brute force = many queries).
* Requires good wordlists.
* May cause **DNS rate-limiting** if scanning big scopes.

---

## 9. Best Practices

* Always use **good curated wordlists** (like SecLists).
* Combine with **Sublist3r/Subfinder** to catch passive sources.
* Use DNS resolvers (`--dns` option in other tools) to avoid ISP blocking.
* Automate filtering of live subdomains with `dnsx` after Knockpy.

---

## 10. Real Recon Workflow with Knockpy

1. Run passive tools first (Subfinder, Assetfinder, Amass passive).
2. Run Knockpy with a **focused wordlist** for hidden subdomains.

   ```bash
   python3 knockpy.py example.com -w ~/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt -o knockpy.json
   ```
3. Combine results with passive ones.

   ```bash
   cat subs_passive.txt <(jq -r '.subdomains[].name' knockpy.json) | sort -u > all_subs.txt
   ```
4. Resolve & probe:

   ```bash
   cat all_subs.txt | dnsx -silent -a -resp > resolved.txt
   cat resolved.txt | httpx -status-code -title -silent > live_hosts.txt
   ```

Now you have a clean list of **live, resolved subdomains**.

---

## 11. Comparison with Other Tools

| Tool          | Style       | Speed     | Unique Advantage                   |
| ------------- | ----------- | --------- | ---------------------------------- |
| **Knockpy**   | Brute force | Medium    | Recursive brute force, JSON output |
| **Sublist3r** | Passive     | Fast      | Aggregates public sources          |
| **Subfinder** | Passive     | Very fast | API-rich, modern                   |
| **Amass**     | Hybrid      | Slower    | Deep, advanced recon               |
| **massdns**   | Brute force | Very fast | DNS resolution at scale            |

---

## 12. Example Lab

Target: `insecure.com`

1. Run Knockpy:

```bash
python3 knockpy.py insecure.com -w subdomains.txt -o insecure.json
```

2. Found:

```
mail.insecure.com → 10.0.0.5
vpn.insecure.com  → 10.0.0.6
```

3. Resolve:

```bash
cat insecure.json | jq -r '.subdomains[].name' | dnsx -silent -a
```

4. Probe HTTP:

```bash
httpx -l insecure.json -status-code -title
```

Output:

```
https://mail.insecure.com [200] [title: Horde Webmail]
https://vpn.insecure.com [302] [title: Cisco VPN Portal]
```

**Result:** You now have two juicy targets (`webmail` and `VPN portal`) to test further.
