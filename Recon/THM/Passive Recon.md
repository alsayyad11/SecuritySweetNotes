<img width="1050" height="130" alt="image" src="https://github.com/user-attachments/assets/03268dc0-a7fb-4fcf-b262-56dbdbd8f891" />


[Access The Lab](https://tryhackme.com/room/passiverecon)

## Task 1: Introduction
<img width="322" height="58" alt="image" src="https://github.com/user-attachments/assets/c6754333-34ca-4b28-a9c3-cb8f31ba4f1f" />

This room introduces some essential **command-line tools** and **online services** used in Passive Reconnaissance:

###  Command-line Tools:

1. `whois` – to query WHOIS records for domains.
2. `nslookup` – to query DNS servers.
3. `dig` – to query DNS records with more detail.

###  Online Services:

1. [dnsdumpster.com](https://dnsdumpster.com) – used to enumerate DNS records and subdomains.
2. [shodan.io](https://shodan.io) – used to discover exposed systems and services on the internet.

---

## Task 2: Passive Versus Active Recon

<img width="498" height="68" alt="image" src="https://github.com/user-attachments/assets/583f200c-5b75-4085-ab7f-70142e851783" />

###  Quote:

> “If you know the enemy and know yourself, your victory will not stand in doubt.” — Sun Tzu

###  Reconnaissance Overview:

* **Reconnaissance (Recon)**: The first phase of the kill chain. It involves gathering information about a target before launching an attack.

<p align="center">
  <img src="https://github.com/user-attachments/assets/42b80a25-0ba9-4c29-a11d-0a8c9dc396b8" width="512" height="512" alt="image" />
</p>

###  Passive Recon:

* No direct interaction with the target.
* Uses publicly available information (news, DNS records, job postings, etc).

###  Active Recon:

* Involves direct engagement with the target.
* Can trigger alerts or be considered illegal without permission.

<p align="center">
  <img src="https://github.com/user-attachments/assets/f1ddbfdc-fe6f-49ae-9bb0-a45ef8affb52" width="300" />
</p>

###  Questions:

* **Q2.1:** Visiting a Facebook page to gather employee names → **P**
* **Q2.2:** Pinging a web server to test ICMP → **A**
* **Q2.3:** Social engineering at a party → **A**

---

## Task 3: WHOIS

<img width="272" height="70" alt="image" src="https://github.com/user-attachments/assets/10d5a42f-d0b7-4830-84e6-39123a23466d" />

###  Protocol Info:

* WHOIS works over TCP port **43**.
* It gives metadata about a domain: registrar, creation/update/expiration dates, registrant contact (unless hidden), and nameservers.

###  Syntax:

```bash
whois <domain_name>
```

###  Example Output (whois tryhackme.com):

<img width="730" height="377" alt="image" src="https://github.com/user-attachments/assets/db792917-e192-4531-a7bc-ac67ff4ed335" />

* **Registrar:** Namecheap.com
* **Creation Date:** 2018-07-05
* **Expiration Date:** 2027-07-05
* **Name Servers:** Cloudflare (e.g., `ns1.cloudflare.com`)

WHOIS data can be used to:

* Craft social engineering attacks
* Target DNS or mail servers

###  Questions:

* **Q3.1:** When was TryHackMe.com registered? → `20180705`
* **Q3.2:** What is the registrar of TryHackMe.com? → `namecheap.com`
* **Q3.3:** Which company is TryHackMe.com using for name servers? → `cloudflare.com`

---

## Task 4: Nslookup and Dig

<img width="374" height="66" alt="image" src="https://github.com/user-attachments/assets/6b0874d0-3d4a-4e25-b60f-acc2041a739f" />

###  `nslookup` Usage:

```bash
nslookup -type=<record_type> <domain> <dns_server>
```

* Common Types:

<img width="1100" height="261" alt="image" src="https://github.com/user-attachments/assets/2fcfc411-db62-4049-b0fe-b2ac42b89d9c" />

### Example 

<img width="1100" height="286" alt="image" src="https://github.com/user-attachments/assets/db73f8ec-888a-4a65-a515-1b5e19fd5d74" />

###  Email Configuration Lookup:

```bash
nslookup -type=MX tryhackme.com
```

* Result: Google’s mail servers handle THM’s email (e.g., `aspmx.l.google.com`)

###  `dig` Usage:

```bash
dig <domain> <record_type>
dig @<dns_server> <domain> <record_type>
```

* More verbose and customizable than nslookup.

<img width="557" height="410" alt="image" src="https://github.com/user-attachments/assets/58bdfcd0-018a-49b4-bbb5-4ccd2b8e41f0" />

###  Question:

* **Q4.1:** Check TXT records of `thmlabs.com`. What is the flag? → `THM{a5b83929888ed36acb0272971e438d78}`
  
### `nslookup` method
<img width="511" height="123" alt="image" src="https://github.com/user-attachments/assets/817a02bd-c8ca-4823-82b9-5e72757520e9" />

### `dig` method
<img width="712" height="405" alt="image" src="https://github.com/user-attachments/assets/12ae5842-fe3a-4a54-83e4-cc42ce3835b5" />

---

## Task 5: DNSDumpster

<img width="356" height="62" alt="image" src="https://github.com/user-attachments/assets/225f6547-226c-4c3f-9297-e5404ca5b973" />

###  Purpose:

`nslookup` and `dig` **can’t discover subdomains** by themselves.

**DNSDumpster** is a web-based recon tool that can:

* Identify subdomains (e.g., `remote.tryhackme.com`)
* Resolve IPs
* Show MX, TXT, and NS records
* Generate visual maps of the DNS infrastructure

## How to use it ?

### 1st — Access into DNSDumpster
```
www.dnsdumpster.com
```

### 2nd — Search “tryhackme.com”

<img width="704" height="174" alt="image" src="https://github.com/user-attachments/assets/7f8379b3-ee85-4236-b3ff-90e5af63e461" />

### 3rd — Examine the information that has been extracted

<img width="631" height="536" alt="image" src="https://github.com/user-attachments/assets/d6b0b1db-ae42-44ea-b2f8-74cceb508993" />

<img width="573" height="375" alt="image" src="https://github.com/user-attachments/assets/a5fbec21-4406-4967-bbe3-81576a51682c" />

<img width="1420" height="1080" alt="image" src="https://github.com/user-attachments/assets/f6853178-ec05-44e1-b339-d4722ec00f6a" />

<img width="937" height="294" alt="image" src="https://github.com/user-attachments/assets/4b126efa-c25e-4e32-a2ce-83ef61677ea7" />

<img width="1100" height="1419" alt="image" src="https://github.com/user-attachments/assets/aabb74da-1277-47f6-9df4-24b2d16b3853" />

###  Question:

* **Q5.1:** Interesting subdomain besides `www` and `blog` → `remote`

---

## Task 6: Shodan.io
<img width="340" height="68" alt="image" src="https://github.com/user-attachments/assets/80410c76-9fa8-43f8-9bcf-40c4349a1379" />

###  What is Shodan?

A search engine for internet-connected devices, not websites.

###  Info you can gather from Shodan:

* IP Address
* Open Ports
* Location
* Hosting Provider
* Server type/version

###  Examples:

* Search `tryhackme.com` or its IPs from previous DNS lookups.
* Discover open ports, exposed services, or outdated software.

  <img width="762" height="328" alt="image" src="https://github.com/user-attachments/assets/f352fafa-fd63-4704-bd8c-e45d8fdb04bf" />


###  Questions:

* **Q6.1:** 2nd country with most Apache servers? → `Germany`
  
  <img width="192" height="554" alt="image" src="https://github.com/user-attachments/assets/e6bec9a7-495b-458c-9f16-a0fe2e8b52be" />

* **Q6.2:** 3rd most common port for Apache? → `8080`
  
  <img width="177" height="165" alt="image" src="https://github.com/user-attachments/assets/d82c5386-1e2c-435a-8419-fc6a0fb74728" />

* **Q6.3:** 3rd most common port for nginx? → `5001`
  
<img width="190" height="551" alt="image" src="https://github.com/user-attachments/assets/dc34c336-9fa6-4edb-bbeb-53b3fec7a5ff" />

---

## Task 7: Summary
<img width="294" height="68" alt="image" src="https://github.com/user-attachments/assets/42e6505a-a5a9-4f1d-823b-2826df8528cb" />

<img width="762" height="378" alt="image" src="https://github.com/user-attachments/assets/e8d6fef1-0b1d-4ee2-a191-1ba1cf636e9d" />


* Passive Recon helps gather critical information **without touching the target**.
* Tools like `whois`, `nslookup`, and `dig` are foundational.
* Services like DNSDumpster and Shodan give **huge value** with minimal risk.

> Passive Recon is the "silent preparation" before active engagement — helping us map the environment and understand the target better without revealing ourselves.

###  Question:

* **Q7.1:** Make sure you note all the points discussed in this room, especially the syntax for the command-line tools.

Answer: No answer is needed.
---

##  Conclusion

All of the tools covered in this room — including `whois`, `nslookup`, `dig`, **DNSDumpster**, and **Shodan.io** — are designed to help us gather information about a target without directly interacting with it. This is what makes passive reconnaissance so powerful: it's a stealthy approach that doesn’t alert the target or reveal our intentions.

It's essentially the “silence before the storm,” where we quietly collect as much intelligence as possible in preparation for further actions. In penetration testing, information is the foundation of everything — the more we know, the better we can plan and execute our next steps.

Passive recon allows us to map out potential vulnerabilities, exposed services, and system details — all without ever “knocking on the door.” It’s the first and most critical step in understanding the landscape and gaining a strategic advantage.

---

<img width="1917" height="870" alt="Screenshot 2025-07-12 121224" src="https://github.com/user-attachments/assets/ba5a9e70-e0b1-46e9-b958-0804b20868be" />


<img width="1919" height="747" alt="Screenshot 2025-07-12 113601" src="https://github.com/user-attachments/assets/b7de98e3-5487-4153-9c3b-117a02927c63" />
