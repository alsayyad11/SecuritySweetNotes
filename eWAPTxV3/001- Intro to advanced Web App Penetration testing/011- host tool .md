
# What is `host`

`host` is a simple command-line DNS lookup tool (part of BIND tools) that resolves domain names to IPs and vice-versa. It’s lightweight and great for quick lookups in scripts or on the terminal.

---

# Why use `host`

* Very quick and terse output for simple lookups.
* Good for automation / piping in scripts.
* Handy for recon tasks: enumerate mail servers (MX), name servers (NS), TXT records, basic zone transfer tests, reverse lookups.
* Available on most Linux distros (via `bind9-host` or `bind-utils` package).

---

# Install

* **Debian/Ubuntu/Parrot**:

  ```bash
  sudo apt update
  sudo apt install -y dnsutils bind9-host
  ```

  (`dnsutils` typically provides `dig` & `nslookup`; `bind9-host` provides `host`.)
* **CentOS/RHEL/Fedora**:

  ```bash
  sudo dnf install -y bind-utils
  ```
* **Windows**: use `nslookup` (native) or install BIND tools through WSL / Cygwin.

---

# Syntax

```
host [options] name [server]
```

* `name` is the domain, IP, or hostname you want to query.
* `server` (optional) is a specific DNS server to query (e.g., `8.8.8.8`).

---

# Common useful options

* `-t type` — query a specific record type (A, AAAA, MX, NS, TXT, SOA, PTR, SRV).
* `-a` — equivalent to `-t ANY` (query all).
* `-v` — verbose.
* `-l` — perform a zone transfer (AXFR) against the domain’s authoritative servers (requires the server to allow it — usually blocked).
* `-R` — reverse lookup? (Most common is `host ip` for reverse; `-R` not standard on all builds.)
* `-W` — set timeout (seconds).
* `-4` / `-6` — force IPv4 / IPv6 (not in every `host` build).

---

# Examples (copy-pasteable)

### 1) Simple A record (IPv4)

```bash
host example.com
# Output:
# example.com has address 93.184.216.34
```

### 2) AAAA record (IPv6)

```bash
host -t AAAA example.com
# If none, no result for AAAA.
```

### 3) MX (mail servers)

```bash
host -t MX example.com
# example.com mail is handled by 10 mx1.example.net.
# example.com mail is handled by 20 mx2.example.net.
```

### 4) NS (name servers)

```bash
host -t NS example.com
# example.com name server ns1.example.net.
# example.com name server ns2.example.net.
```

### 5) TXT (SPF, DKIM, verification strings)

```bash
host -t TXT example.com
# example.com descriptive text "v=spf1 include:_spf.example.net ~all"
```

### 6) SOA (Start of Authority)

```bash
host -t SOA example.com
# example.com domain name pointer ns1.example.net
```

### 7) Reverse DNS (PTR) — lookup IP to domain

```bash
host 8.8.8.8
# 8.8.8.8.in-addr.arpa domain name pointer dns.google.
```

### 8) Query a specific DNS server

```bash
host example.com 8.8.8.8
# Ask Google DNS for the answer.
```

### 9) ANY query (all records)

```bash
host -a example.com
# returns many record types (note: many servers limit ANY responses)
```

### 10) Try a zone transfer (AXFR) — often blocked but useful to test

```bash
# find authoritative NS
host -t NS target.com

# suppose ns1.target.com is authoritative:
host -l target.com ns1.target.com
# If misconfigured, you'll get full zone listing (files), otherwise "Transfer failed" or "permission denied".
```

**Note:** Only perform AXFR on domains you are authorized to test.

---

# Using `host` in recon workflows

### Enumerate subdomains from brute force results

If you have `subdomains.txt` (wordlist), you can script `host` to check which resolve:

```bash
while read -r s; do host "$s.example.com" | grep "has address" && echo "$s.example.com"; done < subdomains.txt
```

### Batch queries (parallel)

Use `xargs` to parallelize:

```bash
cat hosts.txt | xargs -P20 -I {} sh -c 'host {} 8.8.8.8 | grep "has address" && echo {}' 
```

### Extract MX hosts to test mail servers

```bash
host -t MX example.com | awk '{print $7}' | sed 's/\.$//'
# then test each mail host with telnet or nmap
```

### Discover name servers and try AXFR automatically

```bash
for ns in $(host -t NS example.com | awk '{print $4}'); do
  echo "Trying AXFR against $ns..."
  host -l example.com $ns
done
```

---

# `host` vs `dig` vs `nslookup`

* **`host`** — simple and concise, good for scripting and quick lookups.
* **`dig`** — more powerful, flexible output formatting, good for advanced DNS debugging (SOA, recursion tests, query times, +short option). Preferred for in-depth DNS work.
* **`nslookup`** — older; interactive mode useful but `dig`/`host` are preferred these days.

Example `dig` equivalent:

```bash
dig +short example.com A
dig example.com MX +short
```

---

# Practical pentesting notes & ethics

* DNS queries are generally low-risk, but **zone transfers (AXFR)** and automated mass scanning should only be performed with authorization.
* Excessive querying can alert monitoring systems or trigger rate-limiting / temporary DNS blacklisting.
* Use caching nameservers or respected public resolvers (8.8.8.8, 1.1.1.1) for repeat queries to avoid hitting authoritative servers repeatedly.

---

# Troubleshooting common issues

* **No response / timeout**: Try a different DNS server (`host example.com 1.1.1.1`).
* **No PTR for IP**: Many IP ranges don’t have reverse DNS configured.
* **ANY returns limited results**: Modern DNS responds minimally to ANY queries — use specific types.
* **Zone transfer denied**: Expected; most servers disallow AXFR.

---

# Handy one-liners

List all MX target IPs:

```bash
host -t MX example.com | awk '{print $7}' | sed 's/\.$//' | xargs -I{} host {}
```

Get authoritative name servers:

```bash
host -t NS example.com
```

Check SPF (TXT) quickly:

```bash
host -t TXT example.com | grep spf
```

Reverse lookup of many IPs (parallel):

```bash
cat ips.txt | xargs -P20 -I{} host {}
```
