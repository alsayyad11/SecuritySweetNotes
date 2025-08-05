<img width="2000" height="1573" alt="67358729ecfada2f78a958d6_663395d3790b636e6eefcc14_CIA-Triad" src="https://github.com/user-attachments/assets/f0a33f86-2154-43f2-9a52-813d27618cc4" />

## 1. The CIA Triad

The **CIA Triad** is the foundational model for information security. It defines three primary objectives that security controls must achieve in order to protect data and systems.

1. **Confidentiality**
2. **Integrity**
3. **Availability**

Each of these is explained in turn below.

### 1.1 Confidentiality

**Definition**
Confidentiality ensures that sensitive information is accessed only by authorized parties. It prevents unauthorized disclosure of data.

**Why It Matters**
If confidentiality is broken, confidential data—such as personal records, trade secrets or financial details—can be exposed, leading to privacy violations, identity theft, legal penalties and loss of trust.

**Mechanisms to Enforce Confidentiality**

* **Encryption in transit and at rest**
  • TLS/SSL for data in transit (e.g., HTTPS).
  • AES or RSA encryption for stored data (e.g., disk encryption).
* **Strong authentication**
  • Multi-factor authentication (combining something you know, have, or are).
* **Access control**
  • Role-Based Access Control (RBAC) to grant permissions only to those who need them.
  • Access Control Lists (ACLs) on files and directories.
* **Network segmentation and firewalls** to limit where data can flow.

**➟ Example**
A healthcare provider stores patient medical records in an encrypted database. Even if an attacker obtains a database dump, without the decryption key they cannot read diagnoses, prescriptions or personal identifiers.

---

### 1.2 Integrity

**Definition**
Integrity assures that data remains accurate, complete and unaltered, whether in storage, in transit or during processing.

**Why It Matters**
Without integrity, an attacker or system malfunction could modify records (e.g., financial transactions, logs or critical software binaries), leading to incorrect decisions, fraud or system failures.

**Mechanisms to Enforce Integrity**

* **Hash functions and checksums**
  • Use algorithms such as SHA-256 to produce a fixed-length fingerprint of data.
  • Verify that the fingerprint matches before and after transfer or storage.
* **Digital signatures**
  • Sign data with a private key; recipients verify with the corresponding public key.
* **Version control systems**
  • Tools like Git maintain the history and can detect unauthorized changes.
* **Database constraints and ACID transactions**
  • Enforce referential integrity, unique keys, and transaction rollbacks on failure.

**➟ Example**
When downloading an operating system ISO, the vendor publishes its SHA-256 hash. After download, users run a checksum utility. If the calculated hash differs, the ISO has been tampered with or corrupted.

---

### 1.3 Availability

**Definition**
Availability ensures that systems, applications and data are accessible to authorized users whenever needed.

**Why It Matters**
Loss of availability can disrupt business operations, prevent emergency services, halt e-commerce transactions or impede critical communications.

**Mechanisms to Enforce Availability**

* **Redundancy and failover**
  • Multiple servers in different geographic locations.
  • Automatic failover clusters for databases and applications.
* **Load balancing**
  • Distribute incoming traffic across multiple nodes to prevent any single node overload.
* **Regular backups and disaster recovery planning**
  • Frequent backups with tested restoration procedures.
* **Denial-of-Service (DoS) and Distributed DoS (DDoS) protection**
  • Rate limiting, traffic scrubbing services, web application firewalls (WAFs).

**➟ Example**
An online retailer deploys its website across several data centers with automatic failover. If one data center suffers an outage, traffic is seamlessly redirected to another, preventing downtime during peak shopping seasons.

---

## 2. The AAA Model

While the CIA Triad focuses on protecting data, the **AAA model** governs how users interact with systems. It is composed of:

1. **Authentication**
2. **Authorization**
3. **Accounting**

Each element builds on the previous to ensure secure, controlled access and traceability of user actions.

### 2.1 Authentication

**Definition**
Authentication is the process of verifying the identity of a user, device or system. It answers the question “Who are you?”

**Common Methods**

* **Something you know**: password or PIN
* **Something you have**: security token, smart card, or mobile device for one-time passwords
* **Something you are**: biometric factors such as fingerprint, facial recognition or iris scan
* **Multi-Factor Authentication (MFA)**: combinations of the above

**➟ Example**
A corporate VPN requires employees to enter their username and password (knowledge) and then confirm a push notification on their registered smartphone (possession) before granting network access.

---

### 2.2 Authorization

**Definition**
Authorization determines what actions an authenticated user is permitted to perform. It answers the question “What are you allowed to do?”

**Mechanisms**

* **Role-Based Access Control (RBAC)**
  • Assign users to roles (e.g., “manager,” “engineer,” “intern”) and grant each role specific permissions.
* **Attribute-Based Access Control (ABAC)**
  • Use attributes (e.g., department, time of day, device type) in policy decisions.
* **Access Control Lists (ACLs)** for files, directories, network resources and APIs.

**➟ Example**
At a university, students can view their own grades but cannot view or modify other students’ records. Faculty members have additional privileges to update grade entries.

---

### 2.3 Accounting (Auditing)

**Definition**
Accounting, also known as auditing or logging, records and tracks user activities. It answers the question “What did you do, and when?”

**Components**

* **Event logging** of successful and failed logins, file access, configuration changes and administrative actions.
* **Audit trails** that record who performed each action, on which resource, and at what time.
* **Log retention and secure storage** to ensure logs cannot be tampered with.

**➟ Example**
A financial services firm retains logs of every transaction, including the user ID, timestamp, amount and account numbers involved. In the event of fraud, investigators can reconstruct the sequence of events to identify the perpetrator.

---

## Summary 

| Model   | Component       | Purpose                                | Example Mechanism           |
| ------- | --------------- | -------------------------------------- | --------------------------- |
| **CIA** | Confidentiality | Prevent unauthorized data disclosure   | Encryption, RBAC            |
|         | Integrity       | Ensure data accuracy and consistency   | Hashing, digital signatures |
|         | Availability    | Ensure reliable access to systems/data | Redundancy, load balancing  |
| **AAA** | Authentication  | Verify user identity                   | Passwords, MFA              |
|         | Authorization   | Grant or deny access/permissions       | ACLs, RBAC                  |
|         | Accounting      | Log and audit user actions             | SIEM systems, audit trails  |

---

