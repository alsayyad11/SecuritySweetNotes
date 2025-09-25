
## 1. Introduction

**Nmap (Network Mapper)** is an open-source network exploration and security auditing tool. It is used to:

* Discover live hosts on a network.
* Enumerate open ports.
* Detect services, versions, and operating systems.
* Run vulnerability and discovery scripts with the **Nmap Scripting Engine (NSE)**.
* Provide detailed outputs for reporting and automation.

It works by sending crafted packets and analyzing the responses (or lack thereof). Because of this, Nmap is both powerful and sensitive to the network environment.

---

## 2. How Nmap Works

When you run Nmap, it performs the following phases (not always all of them, depending on your flags):

1. **Host discovery** — check which hosts are alive.
2. **Port scanning** — probe ports for their state.
3. **Service detection** — fingerprint services running on open ports.
4. **OS detection** — guess the operating system using packet signatures.
5. **Scripting (NSE)** — run scripts for additional data gathering or vulnerability scanning.
6. **Output generation** — present results in multiple formats.

---

## 3. Port States in Nmap

Nmap classifies ports into several states:

* **open**: An application is actively accepting connections.
* **closed**: No application is listening, but the port is reachable.
* **filtered**: Nmap cannot determine if open/closed due to firewall or filtering.
* **unfiltered**: Accessible, but Nmap cannot determine if open/closed (rare).
* **open|filtered**: No response; could be open or filtered (common in UDP scans).
* **closed|filtered**: Ambiguous state (rare).

---

## 4. Host Discovery

Before scanning ports, Nmap often checks if the host is alive.

* **Ping Scan** (no ports):

  ```bash
  nmap -sn 192.168.1.0/24
  ```

  * Uses ICMP Echo requests, TCP ACKs, or ARP (on LAN).
  * Quickly identifies live hosts without scanning ports.

* **Disabling host discovery**:

  ```bash
  nmap -Pn target
  ```

  * Skips host discovery; assumes host is up.

---

## 5. Port Scanning Techniques

### 5.1 TCP Connect Scan (`-sT`)

* Default when not run as root.
* Completes the full 3-way TCP handshake.
* Reliable but noisier (easily logged).

```bash
nmap -sT 192.168.1.10
```

### 5.2 SYN (Stealth) Scan (`-sS`)

* Default when run as root.
* Sends SYN and waits for SYN/ACK.
* Does not complete handshake (stealthier, faster).

```bash
sudo nmap -sS 192.168.1.10
```

### 5.3 UDP Scan (`-sU`)

* Probes UDP ports.
* Slower and less reliable (due to lack of responses).
* Often returns `open|filtered`.

```bash
sudo nmap -sU -p 53,161 192.168.1.10
```

### 5.4 Other TCP Scans

* **FIN Scan (`-sF`)**, **Xmas Scan (`-sX`)**, **Null Scan (`-sN`)**:

  * Send unusual TCP flags.
  * Useful for bypassing weak firewalls.
  * Not reliable on modern systems.

```bash
sudo nmap -sF 192.168.1.10
```

* **ACK Scan (`-sA`)**:

  * Used to map firewalls and differentiate between `filtered` and `unfiltered`.

```bash
sudo nmap -sA 192.168.1.10
```

* **Window Scan (`-sW`)**:

  * Similar to ACK but examines TCP window size.

* **Maimon Scan (`-sM`)**:

  * Obscure; sends FIN/ACK probes.

### 5.5 SCTP Scans

* For SCTP (Stream Control Transmission Protocol).
* Rarely used except in telecom/VoIP contexts.

---

## 6. Service and Version Detection

```bash
nmap -sV 192.168.1.10
```

* Sends probes to open ports to determine:

  * Service type (e.g., HTTP, FTP, SSH).
  * Version (e.g., Apache httpd 2.4.49).
* Can be tuned with:

  * `--version-intensity 0–9`
  * `--version-light` (less probing).
  * `--version-all` (all probes).

---

## 7. OS Detection

```bash
sudo nmap -O 192.168.1.10
```

* Uses TCP/IP fingerprinting.
* Provides **probable OS matches** with accuracy percentage.
* More reliable with multiple open ports.

---

## 8. Aggressive Scan (`-A`)

```bash
sudo nmap -A 192.168.1.10
```

* Combines:

  * SYN scan
  * Version detection
  * OS detection
  * Traceroute
  * Default NSE scripts

* Provides maximum information, but:

  * Very noisy.
  * Takes longer.
  * More likely to trigger defenses.

---

## 9. Timing and Performance

Nmap has timing templates (`-T0` to `-T5`):

* `-T0`: Paranoid (very slow, IDS evasion).
* `-T1`: Sneaky.
* `-T2`: Polite (slower, less intrusive).
* `-T3`: Normal (default).
* `-T4`: Aggressive (fast, used in practice).
* `-T5`: Insane (very fast, unreliable, easily detected).

Example:

```bash
nmap -sS -T4 target
```

You can also fine-tune:

* `--min-rate` / `--max-rate`: control packet send rate.
* `--host-timeout`: stop scanning a host after set time.
* `--max-retries`: limit retransmissions.

---

## 10. NSE (Nmap Scripting Engine)

Scripts extend Nmap for tasks like brute-force, vulnerability detection, and discovery.

* Run a category:

  ```bash
  nmap --script vuln target
  ```
* Run a specific script:

  ```bash
  nmap --script http-title -p 80 target
  ```
* Multiple scripts:

  ```bash
  nmap --script "http-enum,ssl-heartbleed" target
  ```

### NSE Script Categories

* `auth` — authentication bypass/bruteforce.
* `broadcast` — discovery via broadcasts.
* `brute` — brute force logins.
* `default` — scripts run with `-A`.
* `discovery` — host/service enumeration.
* `exploit` — active exploitation.
* `fuzzer` — fuzzing services.
* `intrusive` — heavy scanning, risky.
* `malware` — malware detection.
* `safe` — safe, no risk.
* `vuln` — vulnerability detection.

---

## 11. Output Options

Nmap supports multiple formats:

* Normal (human-readable):

  ```bash
  nmap -oN output.txt target
  ```
* Grepable:

  ```bash
  nmap -oG output.gnmap target
  ```
* XML:

  ```bash
  nmap -oX output.xml target
  ```
* All formats:

  ```bash
  nmap -oA prefix target
  ```

---

## 12. Target Specification

* Single host:

  ```bash
  nmap 192.168.1.10
  ```
* Multiple:

  ```bash
  nmap 192.168.1.10 192.168.1.20
  ```
* CIDR notation:

  ```bash
  nmap 192.168.1.0/24
  ```
* Input list:

  ```bash
  nmap -iL targets.txt
  ```

---

## 13. Firewall Evasion and Spoofing

* **Fragment packets**:

  ```bash
  nmap -f target
  ```
* **Decoy scans**:

  ```bash
  nmap -D RND:10 target
  ```
* **Source port manipulation**:

  ```bash
  nmap --source-port 53 target
  ```
* **Randomize scan order**:

  ```bash
  nmap --randomize-hosts -p- -T4 target
  ```

Caution: Evasion techniques are often detectable and may be illegal without authorization.

---

## 14. Real-World Practical Examples

* Quick host discovery:

  ```bash
  nmap -sn 10.0.0.0/24
  ```
* Full TCP + Service detection:

  ```bash
  sudo nmap -sS -sV -T4 target
  ```
* All ports:

  ```bash
  sudo nmap -p- target
  ```
* Aggressive recon:

  ```bash
  sudo nmap -A -p- target
  ```
* UDP + specific scripts:

  ```bash
  sudo nmap -sU -p 53 --script dns-recursion target
  ```

---

## 15. Limitations and Caveats

* **False positives/negatives**: Filters, IDS, or flaky networks can cause inaccuracies.
* **OS detection**: Probabilistic, not guaranteed.
* **UDP scans**: Unreliable without tuning.
* **Legal concerns**: Unauthorized scanning can be illegal.

---

## 16. Integrating with Other Tools

* Combine with **Masscan** for fast discovery, then feed results into Nmap for detailed scans.
* Parse XML outputs into tools like:

  * `xsltproc` (reporting).
  * `ndiff` (scan comparison).
  * Security dashboards.

---

## 17. Summary (Cheatsheet)

* Live hosts on LAN:

  ```bash
  nmap -sn 192.168.1.0/24
  ```
* Quick TCP service scan:

  ```bash
  sudo nmap -sS -sV -T4 target
  ```
* Aggressive full recon:

  ```bash
  sudo nmap -A -p- target
  ```
* UDP discovery:

  ```bash
  sudo nmap -sU -p 53,161 target
  ```
* NSE vuln scan:

  ```bash
  sudo nmap --script vuln target
  ```

