
![1](https://github.com/user-attachments/assets/351ad0bc-11f9-4e3a-a660-526d0a304a14)


## 1. Introduction

Nmap (short for Network Mapper) is a free and open-source tool used for **network discovery** and **security auditing**. It allows security professionals, system administrators, and penetration testers to identify live hosts, open ports, running services, operating systems, and potential vulnerabilities within a network.

Nmap works by sending carefully crafted packets to target hosts and then analyzing the responses. Depending on how a target responds, Nmap can determine whether ports are open, closed, or filtered, and what services may be running.

---

## 2. Importance of Nmap

* **Reconnaissance**: The first and most crucial step in penetration testing is mapping the target environment. Nmap provides this reconnaissance capability.
* **Attack Surface Identification**: Nmap reveals which ports and services are exposed, helping testers identify the entry points.
* **Vulnerability Identification**: Through scripting, Nmap can help identify common vulnerabilities.
* **Network Defense**: System administrators use it to verify which services are running and to detect unauthorized systems or services.

---

## 3. Core Capabilities of Nmap

* **Host Discovery**: Identifies live systems within a network.
* **Port Scanning**: Determines which ports are open, closed, or filtered.
* **Service Detection**: Identifies the specific application or service running on a port.
* **Version Detection**: Determines the version of the detected service.
* **Operating System Detection**: Attempts to identify the target’s operating system through fingerprinting.
* **Script Scanning**: Uses the Nmap Scripting Engine (NSE) to run automated tasks, including vulnerability detection and brute force attacks.
* **Firewall and IDS Evasion**: Includes options to bypass detection and filtering mechanisms.

---

## 4. Scan Types

### 4.1 Host Discovery

Used to check which hosts are active in a network.

```bash
nmap -sn 192.168.1.0/24
```

This command performs a "ping sweep" to discover live hosts in a subnet.

---

### 4.2 Port Scanning

#### TCP Scans

* **SYN Scan (Stealth Scan)**

```bash
nmap -sS target.com
```

Sends a SYN packet. If a SYN/ACK is returned, the port is open. It does not complete the TCP handshake, making it stealthier.

* **Connect Scan**

```bash
nmap -sT target.com
```

Completes the TCP handshake. This scan is more reliable but easier to detect in logs.

* **ACK Scan**

```bash
nmap -sA target.com
```

Checks if ports are filtered by a firewall. It does not determine open/closed states.

#### UDP Scans

```bash
nmap -sU target.com
```

Used to identify open UDP services such as DNS, SNMP, or DHCP. UDP scans are slower because UDP is connectionless and responses may not always be received.

---

### 4.3 Service and Version Detection

```bash
nmap -sV target.com
```

Detects the specific service and version running on open ports, for example Apache 2.4.41 or OpenSSH 8.2.

---

### 4.4 Operating System Detection

```bash
nmap -O target.com
```

Attempts to identify the operating system by analyzing TCP/IP packet responses.

---

### 4.5 Aggressive Scan

```bash
nmap -A target.com
```

Performs a comprehensive scan including service detection, version detection, OS detection, script scanning, and traceroute. Provides detailed results but is more intrusive and easier to detect.

---

## 5. Nmap Scripting Engine (NSE)

NSE allows automation of advanced scanning using scripts written in Lua. It is one of Nmap’s most powerful features.

Examples:

* **Vulnerability detection**

```bash
nmap --script vuln target.com
```

Scans the target for common known vulnerabilities.

* **Brute force attacks**

```bash
nmap --script ftp-brute target.com
```

Attempts brute force logins against FTP.

* **Service enumeration**

```bash
nmap --script smb-enum-shares target.com
```

Enumerates shared folders on an SMB service.

---

## 6. Output Options

Nmap supports multiple output formats for documentation and further analysis.

* **Normal output** (default):
  Displayed directly in the terminal.

* **Save results to a file**:

```bash
nmap -oN result.txt target.com
```

* **Grepable output**:

```bash
nmap -oG result.gnmap target.com
```

* **XML output** (useful for importing into other tools):

```bash
nmap -oX result.xml target.com
```

---

## 7. Firewall and IDS Evasion Techniques

* **Decoy Scan**

```bash
nmap -D RND:10 target.com
```

Sends traffic using multiple spoofed IP addresses to obscure the attacker’s real location.

* **Fragmented Packets**

```bash
nmap -f target.com
```

Splits packets into smaller fragments to evade intrusion detection systems.

* **Timing Options**

```bash
nmap -T4 target.com
```

Controls scan speed. Options range from T0 (very slow, stealthy) to T5 (very fast, noisy).

---

## 8. Real-World Examples

* **Example 1: Internal Network Discovery**

```bash
nmap -sn 10.0.0.0/24
```

Used in corporate environments to find active devices.

* **Example 2: Web Server Enumeration**

```bash
nmap -sS -sV -p 1-1000 -A target.com
```

Scans ports 1–1000, detects services, versions, runs scripts, and traceroute.

* **Example 3: Vulnerability Scanning**

```bash
nmap -p 80,443 --script http-vuln* target.com
```

Runs vulnerability scripts against HTTP/HTTPS services.

---

## 9. Advantages and Limitations

### Advantages

* Free and open source.
* Supports multiple advanced scanning techniques.
* Highly customizable with scripting.
* Works across platforms (Linux, Windows, macOS).

### Limitations

* Intrusive scans can be easily detected by IDS/IPS.
* Results may vary depending on firewall configurations.
* Does not exploit vulnerabilities (requires additional tools for exploitation).

---

## 10. Commonly Used Commands Cheat Sheet

| Command                          | Description                   |
| -------------------------------- | ----------------------------- |
| `nmap -sn 192.168.1.0/24`        | Ping sweep to find live hosts |
| `nmap -sS target.com`            | TCP SYN (stealth) scan        |
| `nmap -sT target.com`            | TCP connect scan              |
| `nmap -sU target.com`            | UDP scan                      |
| `nmap -sV target.com`            | Service and version detection |
| `nmap -O target.com`             | OS detection                  |
| `nmap -A target.com`             | Aggressive scan               |
| `nmap --script vuln target.com`  | Vulnerability scan using NSE  |
| `nmap -D RND:10 target.com`      | Decoy scan for evasion        |
| `nmap -oX result.xml target.com` | Save output in XML format     |

