<img width="1100" height="126" alt="image" src="https://github.com/user-attachments/assets/8bf4baa9-e618-47eb-8629-4990df9e9320" />

 [Access The Lab](https://tryhackme.com/room/activerecon)

# **Active Reconnaissance**

<img width="326" height="70" alt="image" src="https://github.com/user-attachments/assets/f16b6c9a-0612-45af-98a6-3ac08980e4d5" />

Active reconnaissance is the **polar opposite of passive recon**; it requires direct interaction or “contact” with the target system or organization.

### Examples:

1. **Social Engineering** — such as making a phone call or visiting the organization in disguise to gather more information.
2. **Technical Contact** — like visiting a website or checking if their firewall exposes a service like SSH.

Think of active recon like **closely examining door locks and windows**—you’re probing for entry points. That’s why it’s **crucial to obtain legal authorization from the client before performing any active recon**.

---

### **Footprints Left by Active Recon**

Active techniques may leave behind:

* IP address logs
* Connection time
* Duration of the connection

Still, not all traffic appears suspicious. For example, if you blend in with normal web traffic, it’s **harder to detect**. This stealth is often used in red team operations to avoid alerting defenders (blue team).

---

## **Active Recon Tools (Terminal-Based)**

* `ping`
* `traceroute`
* `telnet`

> **\[Question 1.1]** Ensure that you understand why these tools fall under active reconnaissance. Launch your AttackBox and make sure it's ready.
> **Answer:** No answer is needed.

---

## **Using a Web Browser for Recon**

<img width="360" height="66" alt="image" src="https://github.com/user-attachments/assets/77020736-30dd-41fa-b115-584a1cf87f51" />

When browsing a website, your browser communicates on:

* **TCP Port 80** → for HTTP
* **TCP Port 443** → for HTTPS

Browsers **hide default ports**, but if a website uses a **custom port**, it must be specified in the address.
Example: `https://127.0.0.1:8834/` connects to **port 8834** on `127.0.0.1`.

---

### **Built-in Browser Tools**

Most modern browsers like Firefox/Chrome offer useful inspection features:

* **Right click → Inspect**

### **Useful Add-ons for Recon**

* **FoxyProxy** — Easily switch proxy servers (e.g., to route traffic through Burp Suite).

* <img width="362" height="202" alt="image" src="https://github.com/user-attachments/assets/e82bbdbd-4123-45cb-ae94-9f9d0e1a8968" />

* **User-Agent Switcher** — Masquerade as a different browser or OS (e.g., simulate iPhone access).

* <img width="607" height="283" alt="image" src="https://github.com/user-attachments/assets/1050e6dd-598c-46a9-80a2-d52fd8d6c271" />

* **Wappalyzer** — Identify technologies used by websites (e.g., frameworks, CMS, libraries).

* <img width="978" height="1082" alt="image" src="https://github.com/user-attachments/assets/a5756c7f-ae5b-4fbb-89c0-fc3d7b2eb76e" />


> **\[Question 2.1]** Open Developer Tools and browse the specified site.
>
> <img width="598" height="295" alt="image" src="https://github.com/user-attachments/assets/d98725ff-7972-4d29-b5c1-2718e2789351" />

> **Answer:** 8

---

## **Ping — Network Reachability Test**

<img width="314" height="72" alt="image" src="https://github.com/user-attachments/assets/600ad070-1545-4cba-b9cd-9a55978c32b4" />


`ping` checks if a system is online and reachable using **ICMP Echo requests**.

### **Command Syntax:**

<img width="615" height="377" alt="image" src="https://github.com/user-attachments/assets/454f8e25-0a72-4a82-bb77-27f5227b7356" />

* Basic: `ping tryhackme.com`
* With packet count:

<img width="542" height="138" alt="image" src="https://github.com/user-attachments/assets/00444425-d8a3-4b97-aac8-989e0317e246" />

  * Linux/macOS: `ping -c 10 <domain>`
  * Windows: `ping -n 10 <domain>`

> **\[Question 3.1]** Option to set data size in ICMP request?

<img width="532" height="16" alt="image" src="https://github.com/user-attachments/assets/f0365e93-6d7a-48b7-b505-c67175a6ca0a" />

> **Answer:** `-s`

> **\[Question 3.2]** Size of ICMP header in bytes?

<img width="761" height="652" alt="image" src="https://github.com/user-attachments/assets/8b4ed3df-56c9-40cd-ac8a-0e71b9978075" />

> **Answer:** `8`

> **\[Question 3.3]** Does Windows firewall block ping by default?
> **Answer:** `Y`

> **\[Question 3.4]** Ping with `-c 10` — number of responses received?
> **Answer:** `10`

---

## **Traceroute — Track the Packet Path**

<img width="320" height="62" alt="image" src="https://github.com/user-attachments/assets/ed691d57-e411-43fb-bbb2-9d180aa3c05b" />

`traceroute` identifies the **path (hops/routers)** taken by packets from your machine to a target.

### **Command Syntax:**

* Linux/macOS: `traceroute <domain>`
* Windows: `tracert <domain>`

<img width="1100" height="589" alt="image" src="https://github.com/user-attachments/assets/0cace430-eaab-4844-81cd-13c23792d76d" />

### **How It Works:**

Uses **TTL (Time To Live)** values to force routers to send back an **ICMP Time Exceeded** message, revealing their IPs.

Each router decreases the TTL by 1. If TTL = 0 → router discards the packet and replies.

> **\[Question 4.1]** Last router in Traceroute A before reaching tryhackme.com?

<img width="1100" height="143" alt="image" src="https://github.com/user-attachments/assets/6207a8cd-737b-44f4-8aed-fda4424c86a4" />

> **Answer:** `172.67.69.208`

> **\[Question 4.2]** Last router in Traceroute B before reaching tryhackme.com?

<img width="1056" height="50" alt="image" src="https://github.com/user-attachments/assets/268adfa3-a088-4aa9-9281-735ea42a708a" />

> **Answer:** `104.26.11.229`

> **\[Question 4.3]** How many routers in Traceroute B?
> **Answer:** `26`

> **\[Question 4.4]** Run `traceroute MACHINE_IP`

<img width="584" height="116" alt="image" src="https://github.com/user-attachments/assets/a25260ba-876f-493d-9ecb-6f45d5816a02" />

> **Answer:** No answer is needed (expect result: 2)

---

## **Telnet — Old-School CLI Communication**

<img width="294" height="72" alt="image" src="https://github.com/user-attachments/assets/3544592c-97e4-429b-8b11-0e86a88e2d5e" />

Telnet lets you connect to remote systems using the **Telnet protocol** (default port: `23`).
 Sends all data, including credentials, in **cleartext** → insecure.

### **Command to Interact with Web Server:**

```bash
telnet <IP> 80
GET / HTTP/1.1
Host: example.com
[press Enter twice]
```

This retrieves the index page or any other requested file.

> **\[Question 5.1]** Name of running server on port 80?

<img width="623" height="447" alt="image" src="https://github.com/user-attachments/assets/fcaa7adb-654c-40fb-bc0f-93fe79bd8017" />

> **Answer:** `Apache`

> **\[Question 5.2]** Version of running server?
> **Answer:** `2.4.10`

---

## **Netcat (nc) — Versatile Network Tool**

<img width="284" height="66" alt="image" src="https://github.com/user-attachments/assets/9d071de0-fb10-4b3d-b935-b34bef954363" />

Netcat can act as a **client or server** using either **TCP or UDP**.

### **Client Mode:**

```bash
nc <IP> <port>
```

### **Server Mode:**

```bash
nc -lvnp <port>
```

#### Example:

1. On server: `nc -lvnp 1234`
2. On client: `nc <server_ip> 1234`
3. Any message typed gets echoed on both ends.

> **\[Question 6.1]** Use Netcat to connect to port 21. What is the version of the server?


<img width="617" height="73" alt="image" src="https://github.com/user-attachments/assets/4e1a5d8b-3808-46de-9635-236de1359c0d" />

> **Answer:** `0.17`

---

## **Recap of Tools Used for Active Recon**

<img width="448" height="70" alt="image" src="https://github.com/user-attachments/assets/0f27a582-0d1a-4638-a538-d417fad406a6" />


<img width="1100" height="415" alt="image" src="https://github.com/user-attachments/assets/521b4c3c-f5e8-4bf9-8c0f-7a1af0ad401f" />

<img width="1100" height="163" alt="image" src="https://github.com/user-attachments/assets/fb01cf54-3ed5-4025-af9e-4bc188f77efa" />

> **\[Question 7.1]** Ensure you’ve practiced with these tools.
> **Answer:** No answer is needed.

---

## **Conclusion**

Active reconnaissance is about **intentional interaction** with the target. While it can leave detectable footprints (logs, IPs, etc.), blending in with normal behavior (like browsing) can help remain stealthy.

The tools covered here give practical ways to:

* Check **availability** (`ping`)
* Map **network paths** (`traceroute`)
* Interact with **services** (`telnet`, `netcat`)
* Gather **tech stack info** (browser + extensions)

---

<img width="1917" height="867" alt="Screenshot 2025-07-12 213439" src="https://github.com/user-attachments/assets/5d038839-3b81-46eb-bd74-9bf61b6443a8" />

<img width="1919" height="752" alt="Screenshot 2025-07-12 174714" src="https://github.com/user-attachments/assets/7f882c87-de9f-43dc-a486-deb4c0f2d5ac" />
