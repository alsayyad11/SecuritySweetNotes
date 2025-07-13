# What is DNS Zone Transfer?

A **DNS Zone Transfer** (also called **AXFR**) is a mechanism used to replicate DNS databases from a **primary (master)** DNS server to **secondary (slave)** DNS servers. This is a normal part of DNS operations, meant for redundancy and consistency.

However, if the DNS server is misconfigured and allows **unauthenticated zone transfers**, attackers can request and download the entire DNS zone — which is a **serious security risk**.

---

## Why is Zone Transfer Dangerous?

If zone transfers are publicly allowed, an attacker can:

* Discover all **subdomains**, including staging, test, internal
* Identify **internal servers** like databases, mail, dev environments
* Leak **internal/private IP addresses**
* Expose **mail servers**, VPN endpoints, and more

This results in an attacker having a **complete internal map** of the target's infrastructure.

---

## Manual Zone Transfer using `dig`

### Step 1: Get the Nameservers (NS Records)

You need to know which DNS servers are responsible for the domain.

```bash
dig example.com NS +short
```

Example output:

```
ns1.example.com
ns2.example.com
```

These are the servers you will test.

---

### Step 2: Try Zone Transfer

Use the AXFR query type against each nameserver:

```bash
dig @ns1.example.com example.com AXFR
```

If the server is vulnerable, you’ll get a list of DNS records:

```
example.com.     86400 IN A 192.168.1.5
mail.example.com. 86400 IN A 192.168.1.10
db.example.com.   86400 IN A 192.168.1.15
...
```

If zone transfer is disabled, you’ll see an error like:

```
; Transfer failed.
```

---

### Step 3: Repeat for Each NS

Test each nameserver one by one — sometimes only one of them is misconfigured.

---

## Automated Zone Transfer using `dnsenum`

### What is `dnsenum`?

`dnsenum` is a Perl-based DNS enumeration tool. It automates many tasks, including:

* Enumerating NS records
* Attempting zone transfers
* Brute-forcing subdomains
* Collecting additional DNS data

---

### Basic Usage

```bash
dnsenum example.com
```

This command will:

* Find the nameservers
* Attempt zone transfers on each one
* Print the results if successful

Example output if vulnerable:

```
Trying zone transfer on ns1.example.com... SUCCESS!
Records found:
- www.example.com -> 192.168.1.2
- mail.example.com -> 192.168.1.10
- internal-db.example.com -> 192.168.1.20
```

---

### Advanced Usage

```bash
dnsenum --dnsserver 8.8.8.8 --threads 10 --enum example.com
```

This allows you to:

* Use a custom DNS server
* Increase threading for speed
* Perform full enumeration (subdomains + zone transfer + more)

---

## Real-World Scenario (Bug Bounty)

Assume your target is:

```
targetcompany.com
```

You run:

```bash
dig targetcompany.com NS +short
```

You get:

```
ns1.targetcompany.com
ns2.targetcompany.com
```

Try:

```bash
dig @ns1.targetcompany.com targetcompany.com AXFR
```

And you see:

```
staging.targetcompany.com.   IN A 10.0.0.5
vpn.targetcompany.com.       IN A 10.0.0.7
mail.targetcompany.com.      IN A 10.0.0.10
```

This means zone transfer was successful, and you now have:

* Internal environment records
* Private IPs
* More targets for attack

In a bug bounty program, this is reported as **Unrestricted DNS Zone Transfer**, usually with a **high severity rating**.

---

## Summary 

| Feature         | `dig`                        | `dnsenum`               |
| --------------- | ---------------------------- | ----------------------- |
| Type            | Manual                       | Automated               |
| Control         | Full – you execute each step | Fully automated         |
| Output Format   | Raw, requires interpretation | Clean, organized output |
| Subdomain Brute | No                           | Yes                     |
| Zone Transfer   | Yes (manual)                 | Yes (automated)         |

---

