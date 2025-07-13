<img width="1025" height="307" alt="image" src="https://github.com/user-attachments/assets/034f1766-b351-48ee-9a2f-a7600c37a205" />

#  What is Subdomain Enumeration?

When you visit a website like:

```
example.com
```

you’re seeing the main domain. But many websites also have **subdomains** — smaller parts of the same domain that serve different purposes. Examples:

* `login.example.com` → login page
* `api.example.com` → backend for apps
* `admin.example.com` → admin dashboard
* `dev.example.com` → development server
* `test.example.com` → testing version of the site

Some of these subdomains are **forgotten**, **not secured properly**, or even **publicly exposed by mistake**.

**Subdomain Enumeration** means trying to **discover all the subdomains** of a target domain. This is an important first step in hacking or bug bounty work — because many vulnerabilities exist **outside** the main website.

---

#  Why Is Subdomain Enumeration Important?

Most companies don’t host everything under just `www.example.com`.

They spread their infrastructure across many subdomains. Some of these may be:

* Misconfigured
* Not updated
* Protected with weak security
* Or even **abandoned** but still online

As a bug hunter or pentester, these subdomains often contain the **easiest and most valuable bugs**.

By skipping subdomain enumeration, you’re ignoring large parts of your potential attack surface.

---

#  Two Main Methods of Finding Subdomains

There are two common techniques to discover subdomains:

---

## 1. **Passive Enumeration**

This method collects subdomains using **public information** available on the internet. It doesn’t talk directly to the target website, so it’s quiet and safe.

### Where passive tools get data from:

* DNS databases
* SSL certificates
* OSINT sources
* Search engines
* Public APIs

### Pros:

* Silent (no direct contact with the target)
* Fast
* No risk of being blocked

### Cons:

* Can miss hidden or private subdomains

---

## 2. **Active Enumeration**

This method tries to **guess or test** subdomains by sending real requests (DNS queries) to the target domain.

### How active tools work:

* Try thousands of common subdomain names using wordlists (like `admin.`, `api.`, `test.`)
* Check which ones respond
* Validate which subdomains are active or alive

### Pros:

* Can find hidden or forgotten subdomains
* More accurate and up-to-date

### Cons:

* Slower
* Noisy (can be logged or blocked)

---

#  Tools for Subdomain Enumeration

Here’s a list of the most useful tools — and how you can use them, even as a beginner.

---

### 1. **subfinder**

**Type:** Passive
**Use:** Collects subdomains from public sources
**Created by:** ProjectDiscovery

```bash
subfinder -d example.com
```

Subfinder is fast and pulls data from services like VirusTotal, Shodan, Censys, and others.

---

### 2. **assetfinder**

**Type:** Passive
**Use:** Finds subdomains from OSINT
**Created by:** TomNomNom

```bash
assetfinder example.com
```

Very beginner-friendly and simple to use.

---

### 3. **amass**

**Type:** Passive + Active
**Use:** Advanced tool for deep subdomain enumeration
**Created by:** OWASP

Passive scan:

```bash
amass enum -passive -d example.com
```

Active brute-force:

```bash
amass enum -active -brute -d example.com
```

Amass can also map relationships between subdomains and export graphs.

---

### 4. **gobuster**

**Type:** Active (Brute-force)
**Use:** Tries to guess subdomains using a wordlist

```bash
gobuster dns -d example.com -w wordlist.txt
```

Used when you want to try thousands of possible subdomains.

---

### 5. **ffuf**

**Type:** Active (Brute-force)
**Use:** Similar to Gobuster, but faster and supports more options

```bash
ffuf -w wordlist.txt -u http://FUZZ.example.com
```

Often used for both subdomain and directory brute-forcing.

---

### 6. **crt.sh**

**Type:** Passive (Manual)
**Use:** Finds subdomains from SSL certificates

Go to: [https://crt.sh](https://crt.sh)
Search for: `%.example.com`

crt.sh shows certificates that include subdomains — which companies often forget are public.

---

### 7. **dnsx**

**Type:** DNS Resolver
**Use:** Checks which subdomains are real and active

After collecting subdomains using other tools, use dnsx to validate them.

```bash
cat subdomains.txt | dnsx -silent
```

---

### 8. **httprobe**

**Type:** HTTP Probing
**Use:** Checks which subdomains have a web server running

```bash
cat live-subdomains.txt | httprobe
```

Helps you find which subdomains are hosting websites.

---

## 9. **Sublist3r**

**Type:** Passive
**Use:** Finds subdomains using search engines and public sources
**Language:** Python
**Created by:** AbdelRahman Mohamed

### What Sublist3r does:

Sublist3r collects subdomains from many **public search engines** and websites like:

* Google
* Bing
* Yahoo
* Netcraft
* VirusTotal
* ThreatCrowd
* crt.sh
* DNSDumpster
* Baidu
* Ask

Sublist3r is a **very beginner-friendly tool** and doesn’t require deep knowledge to use. It’s especially useful in **manual recon** or when you want quick results.

---

### How to install Sublist3r:

```bash
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
pip install -r requirements.txt
```

---

### How to use Sublist3r:

```bash
python sublist3r.py -d example.com
```

To save output:

```bash
python sublist3r.py -d example.com -o sublist3r.txt
```

Sublist3r will quickly return a list of subdomains found using its sources.

---

### When to use Sublist3r:

* When you want a **quick scan** without setting up API keys
* When you’re doing **manual recon**
* When you want to compare results from different tools
* As part of a **passive enumeration phase**

---

# Workflow

Here’s how you can combine all these tools in a simple  recon process.

### Step 1: Collect subdomains using passive tools

```bash
subfinder -d example.com -o sub1.txt
assetfinder example.com >> sub1.txt
amass enum -passive -d example.com >> sub1.txt
```

### Step 2: Use brute-force to find more subdomains

```bash
gobuster dns -d example.com -w wordlist.txt -o sub2.txt
```

### Step 3: Combine all results and remove duplicates

```bash
cat sub1.txt sub2.txt | sort -u > all_subdomains.txt
```

### Step 4: Check which subdomains are real

```bash
cat all_subdomains.txt | dnsx -silent > valid_subdomains.txt
```

### Step 5: Check which ones are running websites

```bash
cat valid_subdomains.txt | httprobe > live_websites.txt
```

You now have a full list of subdomains and can start looking for vulnerabilities.

---

#  Subdomain Enumeration Tools – Summary 

| # | Tool Name       | Type             | Main Purpose                                           | Notes for Beginners                                       |
| - | --------------- | ---------------- | ------------------------------------------------------ | --------------------------------------------------------- |
| 1 | **Subfinder**   | Passive          | Gathers subdomains from public APIs & sources          | Fast, supports automation, widely used in recon pipelines |
| 2 | **Sublist3r**   | Passive          | Finds subdomains using search engines & public sources | Easy to use, no API needed, great for quick scans         |
| 3 | **Assetfinder** | Passive          | Finds subdomains using OSINT                           | Very simple and lightweight                               |
| 4 | **Amass**       | Passive + Active | Advanced subdomain enumeration + mapping               | More complex, but powerful for deep recon                 |
| 5 | **Gobuster**    | Active           | Brute-forces subdomains using wordlists                | Requires a wordlist, slower but effective                 |
| 6 | **Ffuf**        | Active           | High-speed brute-forcing (subdomains or directories)   | Flexible and fast                                         |
| 7 | **crt.sh**      | Passive          | Discovers subdomains from SSL certificate data         | Manual or scriptable (certificate transparency)           |
| 8 | **Dnsx**        | Resolver         | Validates and resolves subdomains                      | Filters out dead or invalid subdomains                    |
| 9 | **Httprobe**    | Web Probing      | Checks which subdomains are serving HTTP/S             | Good for focusing on targets with active websites         |


---
