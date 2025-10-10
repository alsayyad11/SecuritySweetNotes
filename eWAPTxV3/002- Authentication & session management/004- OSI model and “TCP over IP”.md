

# 1  — Two models: OSI vs TCP/IP

## 1.1 OSI Reference Model (7 layers)

The **OSI model** is a conceptual layering that helps understand network functions. It is a theoretical model; real-world stacks map approximately to it.

Layers (top → bottom):

1. **Application (Layer 7)**

   * What it does: provides network services to user applications. Examples: HTTP, SMTP, FTP, DNS, SSH.
   * Data unit: *data* (or *message*).

2. **Presentation (Layer 6)**

   * What it does: data representation, encryption/decryption, compression, character encoding (UTF‑8), serialization formats (JSON, ASN.1).
   * Examples: TLS/SSL sits partly here (encryption) and in the session layer in some models.

3. **Session (Layer 5)**

   * What it does: session management (establish, maintain, terminate sessions), synchronization, checkpoints. Example usages: RPC sessions, SMB session management.
   * Not always distinct in practical stacks — OSI separates it for clarity.

4. **Transport (Layer 4)**

   * What it does: end-to-end communication, segmentation/reassembly, reliability, flow control, multiplexing (ports).
   * Protocols: **TCP** (reliable, connection-oriented), **UDP** (unreliable, connectionless), **DCCP**, **SCTP**.
   * Data unit: *segment* (TCP) or *datagram* (UDP).

5. **Network (Layer 3)**

   * What it does: logical addressing, routing between networks, fragmentation/reassembly.
   * Protocols: **IPv4**, **IPv6**, **ICMP**, **IGMP**.
   * Data unit: *packet*.

6. **Data Link (Layer 2)**

   * What it does: node-to-node data transfer on same link, MAC addressing, error detection (frame check sequence), flow control on link, framing.
   * Protocols/technologies: **Ethernet (IEEE 802.3)**, **802.11 (Wi‑Fi)**, **PPP**, **VLAN (802.1Q)**, **ARP** (often described here).
   * Data unit: *frame*.

7. **Physical (Layer 1)**

   * What it does: bits over physical medium — electrical/optical/wireless signaling, pinouts, cabling, connectors, modulation.
   * Technologies: copper (Ethernet), fiber, radio frequencies (Wi‑Fi), modulation standards.

## 1.2 TCP/IP (Internet) model — practical stack

The Internet is commonly described by a 4-layer model:

1. **Application layer** — application protocols (HTTP, SMTP, DNS)
2. **Transport layer** — TCP/UDP/SCTP
3. **Internet layer** — IP (IPv4/IPv6), ICMP
4. **Network Access / Link layer** — Ethernet, Wi‑Fi, ARP

Mapping to OSI:

* Internet/Application model’s *Application* ≈ OSI Application + Presentation + Session.
* *Internet* layer ≈ OSI Network.
* *Network Access* ≈ OSI Data Link + Physical.

Conclusion: OSI is conceptual; TCP/IP stack describes practical protocols.

---

# 2 — Encapsulation and data units

When an application sends data (e.g., an HTTP GET), information is **encapsulated** as it moves down the layers:

```
Application data
   → Transport header + segment
       → Network header + packet
           → Link header + frame
               → Physical medium (bits)
```

Data unit names:

* L7: data/message
* L4: segment (TCP) / datagram (UDP)
* L3: packet
* L2: frame
* L1: bits

Example pipeline for HTTP GET:

* HTTP GET (text)
  encapsulated in TCP segment (with ports, seq/ack)
  encapsulated in IPv4 packet (with source/dest IP, TTL, protocol)
  encapsulated in Ethernet frame (with source/dest MAC, Ethertype)
  put on wire as bits (voltage/waveform).

---

# 3 — Link and Physical layers (L1–L2) — Ethernet example

## Ethernet frame (IEEE 802.3) — typical fields

```
| Preamble (7B) | SFD (1B) | Destination MAC (6B) | Source MAC (6B) |
| Ethertype/Length (2B) | Payload (46–1500B) | FCS (4B) |
```

* Preamble/SFD: used for sync on wire. Not always visible in captures.
* Destination/Source MAC: 48‑bit addresses.
* Ethertype: e.g., 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP.
* FCS: CRC32 for frame integrity.

### ARP (Address Resolution Protocol)

* Purpose: map IPv4 addresses to MAC addresses on a local network.
* Operation: broadcast ARP Request → target ARP Reply unicast.
* ARP packet sits at L2 but logically part of L3 addressing.

### MTU and fragmentation at L2

* Typical Ethernet MTU = 1500 bytes payload. Jumbo frames may be larger.
* If an L3 packet exceeds MTU and cannot be fragmented at L2, IP fragmentation may occur (IPv4) or packet is dropped (IPv6 requires Path MTU Discovery).

---

# 4 — Network layer (L3) — IPv4/IPv6, routing, fragmentation

## IPv4 header (minimum 20 bytes) — key fields

```
Version (4) | IHL (4) | DSCP/ECN (8) | Total Length (16)
Identification (16) | Flags (3) | Fragment Offset (13)
TTL (8) | Protocol (8) | Header Checksum (16)
Source IP (32) | Destination IP (32)
[Options — variable length]
```

Important:

* **Total Length** = header + data (bytes). Max 65535.
* **Identification/Flags/Fragment Offset**: fragmentation control.

  * Flags: DF (Don't Fragment), MF (More Fragments).
* **TTL**: time-to-live decremented at each router; avoid infinite loops.
* **Protocol**: indicates L4 protocol (6 = TCP, 17 = UDP, 1 = ICMP).
* **Header checksum**: protects only header (not payload).

## IPv6 header (fixed 40 bytes)

```
Version (4) | Traffic Class (8) | Flow Label (20)
Payload Length (16) | Next Header (8) | Hop Limit (8)
Source Address (128) | Destination Address (128)
```

* No checksum in header — lower layers or upper layers handle integrity.
* Extension headers may follow; fragmentation handled differently (fragment header).

## Routing

* Routers use destination IP and routing tables (longest-prefix match) to forward packets.
* Routing protocols: OSPF, BGP, RIP — operate between routers to share routes (outside scope for deep BGP).

## Fragmentation

* **IPv4**: routers or sender can fragment; fragments carry same Identification; reassembly at destination.
* **IPv6**: routers do NOT fragment; sender must perform fragmentation or use Path MTU Discovery (ICMPv6 needed).

Fragmentation pitfalls:

* Reassembly consumes memory; overlapping fragments can be exploited.
* Firewall rules often block fragments or drop unexpected fragments.

---

# 5 — Transport layer (L4) — TCP and UDP fundamentals

## 5.1 UDP (User Datagram Protocol)

* Lightweight, connectionless, no reliability, no ordering, no flow control.
* Header (8 bytes):

  ```
  Source Port (16) | Dest Port (16)
  Length (16) | Checksum (16)
  ```
* Use cases: DNS, DHCP, SNMP, RTP (media), simple queries where low latency > reliability.

## 5.2 TCP (Transmission Control Protocol) — key responsibilities

* Reliable, connection-oriented, byte-stream oriented, flow control, congestion control, in-order delivery.
* Header (minimum 20 bytes, usually with options):

  ```
  Source Port (16) | Dest Port (16)
  Sequence Number (32)
  Acknowledgment Number (32)
  Data Offset (4) | Reserved (3) | Flags (9) | Window Size (16)
  Checksum (16) | Urgent Pointer (16)
  [Options ...] (e.g., MSS, Window Scale, SACK, Timestamps)
  ```
* Flags (control bits):

  * **SYN** (synchronize) — initiate connection
  * **ACK** — acknowledgment field is significant
  * **FIN** — finish (close) connection
  * **RST** — reset connection
  * **PSH** — push data to application
  * **URG** — urgent pointer valid
  * **ECE/ CWR** — ECN flags
* Sequence and acknowledgment numbers: 32-bit counters used for byte-stream tracking.
* Window size: receiver’s advertised buffer space; controls flow.

## 5.3 TCP three-way handshake

To open a connection:

1. **Client → Server**: `SYN` (Seq = x)
2. **Server → Client**: `SYN, ACK` (Seq = y, Ack = x+1)
3. **Client → Server**: `ACK` (Ack = y+1)

After handshake, data flows with Seq/Ack numbering.

## 5.4 Connection termination

* Four-step (normal):

  1. Endpoint A: `FIN, ACK`
  2. Endpoint B: `ACK` (acknowledge FIN)
  3. Endpoint B: `FIN, ACK`
  4. Endpoint A: `ACK` — connection closed.
* `RST` can abort immediately.
* TIME_WAIT state exists on the side that performs the active close (to handle delayed segments, avoid old duplicate connection confusion).

## 5.5 TCP options (common)

* **MSS (Maximum Segment Size)**: negotiation of max payload per TCP segment.
* **Window Scale**: allows windows > 65535 by shifting.
* **Selective Acknowledgment (SACK)**: allow acknowledgment of non-contiguous blocks (improves recovery).
* **Timestamps (PAWS)**: aid RTT calculation and avoid old packets.

## 5.6 Flow control vs congestion control

* **Flow control** (receiver-side): using advertised window, prevents sender from overflowing receiver buffer.
* **Congestion control** (network): algorithms to avoid network congestion: slow start, congestion avoidance, fast retransmit, fast recovery. Common algorithms: Reno, Cubic, BBR.

Brief TCP congestion phases:

* **Slow start**: cwnd starts small (e.g., 1 MSS) and doubles each RTT until threshold.
* **Congestion avoidance**: cwnd increases linearly.
* **Fast retransmit/fast recovery**: on triple duplicate ACKs, retransmit lost segment and reduce cwnd.

## 5.7 Retransmissions and timers

* Retransmit when ACK not received within RTO (retransmission timeout), computed by RTT estimates (smoothed RTT + variance).
* Retransmission strategies: exponential backoff on repeated failures.

---

# 6 — Ports, sockets, and multiplexing

* **Port**: 16-bit number identifying an endpoint on a host (0–65535).

  * Well-known ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 53 (DNS).
  * Ephemeral ports: typically high-numbered ephemeral range used by clients.
* **Socket**: tuple (source IP, source port, dest IP, dest port, protocol). Identifies unique connection in TCP.
* Multiplexing: many application sessions can use same IP, distinct ports.

---

# 7 — Example trace: HTTP GET encapsulation and TCP/IP flow

We’ll walk a simple HTTP GET over IPv4, Ethernet, TCP.

1. Application (browser) issues: `GET /index.html HTTP/1.1\r\nHost: example.com\r\n...\r\n\r\n`

2. Transport (TCP) breaks data into segment(s). Suppose:

   * Client port: 49152 (ephemeral)
   * Server port: 80

3. TCP handshake:

   * Client → Server: `SYN` (Seq=x)
   * Server → Client: `SYN,ACK` (Seq=y, Ack=x+1)
   * Client → Server: `ACK` (Ack=y+1)

4. Client sends TCP segment with HTTP GET (Seq=x+1). IP header source/dest IP, TTL, protocol=6 (TCP). Ethernet frame with MAC addresses.

5. Server replies with `200 OK` in TCP segments. Each segment has Seq/Ack updated.

6. Connection close: FIN/ACK exchange.

### ASCII encapsulation summary

```
Ethernet frame:
  [Dst MAC][Src MAC][0x0800 IPv4][IP packet]
IP packet:
  [IPv4 hdr][TCP segment]
TCP segment:
  [TCP hdr][HTTP payload: "GET /index.html ..."]
```

### Example Wireshark/TCP dump view (conceptual)

* `1 0.000000 10.0.0.2 → 93.184.216.34 TCP 74 49152 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`
* `2 0.020000 93.184.216.34 → 10.0.0.2 TCP 74 80 → 49152 [SYN,ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460`
* `3 0.020007 10.0.0.2 → 93.184.216.34 TCP 66 49152 → 80 [ACK] Seq=1 Ack=1 Win=65535 Len=0`
* `4 0.020100 10.0.0.2 → 93.184.216.34 TCP 152 49152 → 80 [PSH,ACK] Seq=1 Ack=1 Len=86 "GET / HTTP/1.1\r\nHost: example.com\r\n..."`
* `5 0.050000 93.184.216.34 → 10.0.0.2 TCP 600 [PSH,ACK] ... "HTTP/1.1 200 OK\r\n..."`

Fields: Seq numbers, Ack numbers, Window, Length, Flags.

---

# 8 — ICMP and control plane

* **ICMP** (Internet Control Message Protocol) used for control messages: `echo request/reply` (ping), destination unreachable, TTL exceeded, fragmentation needed.
* ICMP useful for diagnostics and Path MTU Discovery (PMTUD uses ICMP "Fragmentation Needed" messages).
* Note: ICMP can be abused (ping flood) and is often rate-limited or filtered.

---

# 9 — TCP/IP nuances & advanced topics

## 9.1 TCP segmentation offload (TSO), checksum offload

* NICs can offload segmentation and checksum calculation; tool captures may show incorrect checksums (because OS expects NIC to compute later).

## 9.2 Middleboxes

* Firewalls, NAT, load balancers, proxies modify traffic (NAT rewrites IP/port, load balancers alter source IPs, HTTP proxies terminate TLS).
* NAT breaks end-to-end transparency; requires stateful translation.

## 9.3 NAT and private addressing

* RFC1918 private addresses: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
* NAT maps internal IP:port to external public socket; complicates incoming connections.

## 9.4 TLS (encryption) and its interaction

* TLS sits on top of TCP (L7) and encrypts application data. After TLS handshake, payloads in TCP are encrypted.
* TLS handshake uses client/server certificates (server-side always; client certs optional).
* TLS handshake uses multiple TLS records and application data records. Once TLS is established, Wireshark shows `Application Data` rather than HTTP content unless decrypted.

## 9.5 IPv6 differences summary

* Larger address space (128-bit).
* No header checksum.
* Extension headers replace options.
* Fragmentation only at source node.
* ICMPv6 includes neighbor discovery (replaces ARP) and requires certain ICMPv6 messages for PMTUD.

---

# 10 — Security considerations

* **Unencrypted HTTP** leaks data and credentials; always use HTTPS (TLS).
* **TCP attacks**: SYN flood (resource exhaustion), session hijacking (if sequence numbers predictable), RST attacks (reset).
* **IP attacks**: IP spoofing (if not validated), fragmentation attacks (evil overlapping fragments).
* **Application-level**: injection attacks over HTTP (XSS, SQLi) — TCP/IP provides transport only.
* **Defense**: firewalls, IDS/IPS, rate-limiting, SYN cookies, TLS, strong randomness for sequence numbers, proper authentication, and session management.

---

# 11 — Practical debugging & tools

## 11.1 tcpdump examples

* Capture packets for interface `eth0` and port 80:

  ```bash
  sudo tcpdump -i eth0 port 80 -w http.pcap
  ```
* Show packets live (human readable):

  ```bash
  sudo tcpdump -i eth0 -nn -A tcp port 80
  ```

  * `-nn` numeric addresses/ports, `-A` to print ASCII payload.

## 11.2 tshark/Wireshark filters

* Display TCP handshake:

  ```
  tcp.flags.syn==1 && tcp.flags.ack==0
  ```
* Filter HTTP GETs:

  ```
  http.request.method == "GET"
  ```
* Show TCP retransmissions:

  ```
  tcp.analysis.retransmission
  ```

## 11.3 netstat/ss

* Show TCP sockets and states:

  ```bash
  ss -tna   # shows TCP sockets, numeric
  netstat -ant
  ```

## 11.4 traceroute / ping

* `ping` uses ICMP echo to test reachability.
* `traceroute` uses UDP or ICMP with increasing TTL to map path.
* `tracepath` may use MTU discovery.

---

# 12 — Example: TCP state machine (common states)

Important TCP states:

* **CLOSED** — initial state
* **LISTEN** — server waiting for connection
* **SYN-SENT** — client sent SYN, waiting SYN-ACK
* **SYN-RECEIVED** — server sent SYN-ACK, waiting ACK
* **ESTABLISHED** — data can be exchanged
* **FIN-WAIT-1**, **FIN-WAIT-2**, **CLOSING**, **TIME-WAIT**, **CLOSE-WAIT**, **LAST-ACK** — various closing states

Transitions are triggered by sending/receiving SYN/ACK/FIN/RST.

---

# 13 — Example packet header fields and sizes (concise)

* Ethernet header: 14 bytes (Dst MAC 6 + Src MAC 6 + Ethertype 2) + FCS 4 bytes at end (not always shown).
* IPv4 header: min 20 bytes, + options.
* TCP header: min 20 bytes, typical with options 20–40 bytes.
* So minimum total L2+L3+L4 overhead: ~54 bytes (Ethernet 14 + IPv4 20 + TCP 20) + frame FCS.

---

# 14 — Typical problems and how to diagnose them

| Symptom                        | Likely cause                               | Diagnostic                                                      |
| ------------------------------ | ------------------------------------------ | --------------------------------------------------------------- |
| No response to TCP SYN         | Firewall drop, routing issue, service down | `tcpdump` show SYN leaving but no SYN-ACK; `traceroute`, `nmap` |
| HTTP body missing or garbled   | Middlebox or TLS terminated, MTU issue     | `tcpdump`/Wireshark: check `Content-Encoding`, TLS handshake    |
| High retransmissions           | Packet loss or too small RTO               | Wireshark `tcp.analysis.retransmission`; check interface errors |
| Intermittent connection resets | Application crash, RST from firewall       | Capture RST packets, examine source IP/port                     |
| Large latency                  | Route congested or long RTT                | `ping`, `traceroute`, measure RTT, tcp RTT in capture           |

---

# 15 — Short cheat-sheet (key commands, numbers)

* TCP ports: 0–65535 (well-known 0–1023, registered 1024–49151, ephemeral >49151 typical)
* Common protocols: TCP=6, UDP=17, ICMP=1 (IPv4)
* Max IPv4 packet size: 65,535 bytes (Total Length)
* Ethernet MTU default: 1500 bytes
* Typical TCP handshake: SYN → SYN+ACK → ACK
* Common tcpdump: `sudo tcpdump -i eth0 -nn tcp and host 1.2.3.4 and port 80 -w capture.pcap`

---

# 16 — Summary 

* **OSI model** is a conceptual 7-layer reference; **TCP/IP** model is a practical 4-layer mapping used on the Internet.
* **Encapsulation**: application data is wrapped by transport headers (TCP/UDP), then by IP headers, then by link-layer frames, then sent as bits.
* **TCP** provides reliability, ordering, flow and congestion control. **IP** provides addressing and routing. **Ethernet/Wi‑Fi** provide link-layer delivery on local networks.
* Understanding sequence numbers, ACKs, windows, TTL, fragmentation, and port/socket semantics is essential to debug network behavior.
* Tools: `tcpdump`, `Wireshark`, `ss`, `netstat`, `traceroute`, `ping`, `httpx` are essential for diagnosis.
