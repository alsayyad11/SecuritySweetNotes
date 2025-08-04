
## 1. Authentication, Authorization & Accounting (AAA)

**What it means**

* **Authentication** (“Who are you?”) checks your identity—like logging in with a username/password or a code on your phone.
* **Authorization** (“What can you do?”) decides which files or tools you’re allowed to use once you’re logged in.
* **Accounting** (“What did you do?”) keeps a log of your actions—when you logged in, what you opened, and when you logged out.

**. example**

* You enter your email and password (authentication).
* You can view your own inbox but not someone else’s (authorization).
* The system logs that you read three messages at 10:00 AM (accounting).

---

## 2. The CIA Triad

**What it means**

* **Confidentiality** = keeping data secret so only the right people see it (like locking your diary).
* **Integrity** = making sure data isn’t changed by mistake or on purpose (like checking a receipt hasn’t been tampered with).
* **Availability** = making sure data and systems are up and running when you need them (like having backup power so the lights don’t go out).

**. example**

* **Confidentiality:** Your messaging app encrypts chats so only you and your friend can read them.
* **Integrity:** A downloaded photo has a small “checksum” that proves it hasn’t been altered.
* **Availability:** A website has two servers; if one crashes, the other keeps it online.

---

## 3. Public & Private Keys (Asymmetric Encryption)

**What it means**

* You have a **public key** you can share with everyone, and a **private key** you keep secret.
* If someone encrypts a message with your public key, only your private key can decrypt it.

**. example**

* You post your public key on your profile. A friend uses it to lock (encrypt) a secret note to you. Only you, with your private key, can read that note.

---

## 4. Encryption Types

**What it means**

* **Symmetric encryption** uses one secret key for both locking and unlocking data. It’s fast for large files.
* **Asymmetric encryption** uses a public/private key pair. It’s slower but solves the problem of how to share the secret key safely.
* In practice, we often use both together: first use asymmetric to share a secret key, then symmetric to lock the real data.

**. example**

* Your bank’s website (HTTPS) uses asymmetric keys to set up a secure session, then uses a fast symmetric key to encrypt all the pages you see.

---

## 5. Hashing & Hashing Algorithms

**What it means**

* A **hash** is like a digital fingerprint for any file or message. It always gives you the same fingerprint for the same input but you can’t go backwards from fingerprint to original.
* Used to check data integrity and to store passwords safely (with an extra “salt” so two people with the same password have different hashes).

**. example**

* When you download a program, the website shows a small code (hash). After download, you generate the hash on your machine. If they match, the file wasn’t damaged or changed.

---

## 6. OSI Model

**What it means**
The OSI model is a way to think about networking in **seven layers**. From bottom to top they are:

1. **Physical** – the cables and signals
2. **Data Link** – local addresses (MAC), switches, error checking
3. **Network** – logical addresses (IP), routers, routing
4. **Transport** – moving data reliably (TCP) or quickly (UDP)
5. **Session** – keeping communications going or closing them
6. **Presentation** – formatting data, encrypting/decrypting, compressing
7. **Application** – the programs you use (web browser, email client)

**. example**

* When you type a web address, your browser (Layer 7) makes a request. That request travels down through each layer, gets wrapped in headers, goes over the wire, then unwraps on the server and back again.

---

## 7. TCP & UDP

**What it means**

* **TCP** is like sending a letter with tracking: it confirms each piece arrived and puts them in order.
* **UDP** is like tossing postcards: fast, but if one gets lost, you don’t know.

**. example**

* **TCP:** Loading a web page – you need every bit of the page in the right order.
* **UDP:** Live video chat – you’d rather see the latest frames quickly, even if a few frames drop.

---

## 8. TCP Three-Way Handshake

**What it means**
To start a TCP connection, the client and server exchange three messages:

1. **SYN** – client says “Let’s talk.”
2. **SYN-ACK** – server says “Okay, I hear you.”
3. **ACK** – client says “Great, let’s start.”

**. example**

* When you click a link, your browser and the website do this quick handshake before any real data flows.

---

## 9. IP Addressing

**What it means**

* **IP address** is a unique number for each device on a network (like a house address).
* **IPv4** uses four groups of numbers (e.g., 192.168.1.10).
* **IPv6** uses longer hexadecimal groups because we ran out of IPv4 addresses.

**. example**

* Your home router might give your phone the IP `192.168.0.5` so it knows where to send internet packets.

---

## 10. IP Classes & Public vs. Private

**What it means**

* **Private IPs** are for inside your home or office (e.g., 10.x.x.x, 192.168.x.x).
* **Public IPs** are on the internet.
* (Old “classes” A, B, C divided addresses differently before today’s flexible “CIDR” system.)

**. example**

* Your laptop might be `192.168.1.100` (private), and your Internet Service Provider gives your router `203.0.113.45` (public).

---

## 11. MAC Address & ARP

**What it means**

* **MAC address** is a built-in hardware address on each network card (like a factory-printed serial number).
* **ARP** is how your computer finds the MAC for a known IP on the same local network.

**. example**

* To send to `192.168.1.20`, your PC asks “Who has 192.168.1.20?” on the local network. The right device replies “It’s me, MAC AA\:BB\:CC\:DD\:EE\:FF.”

---

## 12. Subnetting & Subnet Masks

**What it means**

* **Subnet mask** divides an IP network into smaller groups (subnets). Written as `255.255.255.0` or `/24`.
* Helps organize and limit network size.

**. example**

* A small office might use `192.168.1.0/24` for up to 254 devices. A larger company could split that into `192.168.1.0/26` and `192.168.1.64/26` to keep departments separate.

---

## 13. Network Devices & Traffic Flow

**What it means**

* **Hub**: repeats every signal to all ports (old, now rare).
* **Switch**: sends data only to the correct device using MAC addresses.
* **Router**: sends data between different networks using IP addresses.
* **Active Directory (AD)**: in Windows networks, AD centrally manages user accounts and permissions.

**. example**

* Your office switch learns that MAC AA → port 3, so when data arrives for AA, it only sends it out port 3, not everywhere.

---

## 14. VLANs (Virtual LANs)

**What it means**

* Create separate “virtual” networks on one physical switch to keep traffic isolated, like having separate floors in a building.

**. example**

* Finance computers on VLAN 10 can’t talk directly to Engineering on VLAN 20 unless a router lets them.

---

## 15. Common Protocols

| Protocol |  Port | What it does                             |
| :------- | :---: | :--------------------------------------- |
| HTTP     |   80  | Web pages (no encryption)                |
| HTTPS    |  443  | Secure web pages (encrypted)             |
| SMTP     |   25  | Sending email                            |
| IMAP     |  143  | Reading email while leaving it on server |
| POP3     |  110  | Downloading email (often deletes it)     |
| DNS      |   53  | Turning names (example.com) into IPs     |
| DHCP     | 67/68 | Automatically giving IP addresses        |
| SSH      |   22  | Secure remote command line               |
| Telnet   |   23  | Unsecure remote command line             |
| FTP      |   21  | Transferring files (no encryption)       |

---

## 16. NAT (Network Address Translation)

**What it means**

* Lets many private devices share one public IP by rewriting addresses as traffic flows through your router.

**. example**

* All your home devices (192.168.1.x) appear on the internet as one IP (e.g., 203.0.113.5).

---

## 17. Proxies, VPNs & Firewalls

**What it means**

* **Proxy**: goes between you and the internet to cache or filter traffic.
* **VPN**: makes a secure “tunnel” so you appear as if you’re somewhere else.
* **Firewall**: decides which traffic is allowed or blocked based on rules.

**. example**

* Using a company VPN lets you access internal files as if you were in the office.
* A firewall rule might block all incoming traffic except for web (port 80/443).

---

## 18. Network Intrusion Detection & Baseline Configuration

**What it means**

* **NIDS** watches network traffic and alerts on suspicious patterns (like an alarm system).
* **Baseline Configuration** means you start with a known “good” setup; if settings change unexpectedly, you get warned.

**. example**

* If a new open port appears on your server out of nowhere, the baseline-check alerts you to investigate.

---

## 19. Broadcast vs. Unicast

**What it means**

* **Unicast**: one-to-one message.
* **Broadcast**: one-to-all on the local network.

**. example**

* Your phone sends a unicast request to your router for a website.
* Your device sends a broadcast ARP request when it first comes online.

---
