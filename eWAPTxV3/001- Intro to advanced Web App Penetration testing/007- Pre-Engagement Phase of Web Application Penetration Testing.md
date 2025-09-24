## What is Pre-Engagement Phase

The **Pre-Engagement Phase** is the most critical stage of a web application penetration test. It lays the foundation for a controlled, safe, and legally authorized security assessment. The success of the engagement depends on how well this phase is executed. Skipping or mishandling pre-engagement activities can result in legal liability, broken trust, wasted effort, or even accidental outages.

This phase typically results in **one or more formal documents** (Statement of Work, Rules of Engagement, Authorization Letter, Scope Document) that define the rules, boundaries, and expectations of the assessment.

---

## **Core Objectives of the Pre-Engagement Phase**

1. Define **objectives**: what the client expects from the penetration test (compliance, risk discovery, secure coding verification, etc.).
2. Define **scope**: what is in-scope and out-of-scope (apps, APIs, environments, URLs, functionalities).
3. Clarify **timeline & milestones**: testing start/end dates, blackout windows, reporting deadlines.
4. Establish **responsibilities & liabilities**: who owns the risks, who fixes issues, and what happens if something breaks.
5. Agree on **authorized actions**: which techniques are permitted and which are explicitly prohibited.
6. Document **expectations & deliverables**: interim updates, draft/final reports, executive summary, raw artifacts.
7. Create a **Statement of Work (SOW)**: the contractual document that binds both parties to the agreed rules.

---


### 1. Understanding Project Objectives

* **Why it matters**: Different clients have different goals — regulatory compliance, internal security assurance, or customer confidence. Misaligned objectives can make the test useless.
* **Actions**:

  * Interview stakeholders to determine their goals.
  * Identify business drivers (e.g., PCI-DSS, GDPR, ISO 27001, SOC 2, customer audit).
  * Determine type of test: **black box**, **grey box**, or **white box**.
* **Example**:

  * A bank may want **regulatory compliance (PCI-DSS)** and assurance that online banking is secure.
  * A SaaS company may want to **identify OWASP Top 10 vulnerabilities** before a product launch.

---

### 2. Scope Definition

* **Why it matters**: Scope prevents accidental testing of systems not owned by the client or critical systems that could break business operations.
* **Actions**:

  * Identify web applications, subdomains, APIs, and IP ranges that are in-scope.
  * Explicitly list out-of-scope systems (e.g., third-party payment processors, legacy servers).
  * Clarify environments: production, staging, UAT.
  * Define scope depth: surface testing only, or full exploit attempts.
* **Example Scope Table**:

| Asset                          | In-Scope? | Notes                                    |
| ------------------------------ | --------- | ---------------------------------------- |
| `https://app.example.com`      | ✅         | Full testing, including authentication   |
| `https://api.example.com/v1/`  | ✅         | Test API endpoints with provided API key |
| `https://payments.example.com` | ❌         | Out-of-scope, owned by third-party       |
| Internal admin portal          | ✅         | Test with provided admin credentials     |

---

### 3. Authorization and Legal Requirements

* **Why it matters**: Without explicit authorization, penetration testing may be considered **illegal hacking**.
* **Actions**:

  * Obtain written authorization from the client (signed by an executive with authority).
  * Verify client owns/controls all in-scope assets.
  * Check regulatory restrictions (some countries require government notification).
* **Deliverable**: Authorization Letter.
* **Example Clause**:
  *“This letter authorizes \[Tester] to perform security testing against the systems listed in Appendix A between Oct 1–Oct 5, 2025.”*

---

### 4. Rules of Engagement (RoE)

* **Why it matters**: RoE prevents misunderstandings by specifying what testers can and cannot do.
* **Actions**:

  * Define testing window and hours.
  * Specify disallowed techniques (DoS, social engineering, phishing, physical access).
  * Clarify exploitation depth (proof-of-concept only vs. full compromise).
  * Define communication & escalation process (e.g., call ops manager if critical vuln found).
* **Example Rule**:

  * Scanning limited to **150 requests/sec**.
  * No intrusive testing during **business hours (9am–5pm UTC+3)**.

---

### 5. Communication and Coordination

* **Why it matters**: Good communication prevents disruptions and ensures quick action on critical findings.
* **Actions**:

  * Identify primary, secondary, and emergency contacts.
  * Decide on communication channels (encrypted email, phone, Slack).
  * Agree on response time for emergencies (e.g., 30 minutes).
* **Example Contact Block**:

  ```
  Primary Contact: John Doe (CISO) – john.doe@example.com – +1 555-123-4567  
  Emergency Contact: Jane Smith (Ops Manager) – +1 555-987-6543 – 24/7
  ```

---

### 6. Contracts and Non-Disclosure Agreements (NDAs)

* **Why it matters**: NDAs ensure sensitive data uncovered during testing remains confidential.
* **Actions**:

  * Sign NDAs before testing begins.
  * Include confidentiality clauses in the Statement of Work.
  * Define data retention and destruction policies.

---

### 7. Scoping Meeting

* **Why it matters**: A live discussion ensures no misunderstandings remain about scope, objectives, or risks.
* **Actions**:

  * Walk through objectives, scope, and exclusions with stakeholders.
  * Confirm test accounts will be provided.
  * Discuss expected deliverables and report format.
* **Example Agenda**:

  1. Objectives and compliance requirements.
  2. Scope (apps, APIs, exclusions).
  3. Rules of Engagement (allowed vs. prohibited techniques).
  4. Communication protocol.
  5. Reporting expectations.

---

### 8. Preparation of Tools and Resources

* **Why it matters**: Testing requires preconfigured environments and licenses. Delays can occur if preparation is skipped.
* **Actions**:

  * Verify Burp Suite Pro, Nessus, or other licensed tools are active.
  * Prepare dedicated testing machines or VMs.
  * Configure VPN access if required.
  * Generate test accounts (user, manager, admin roles).

---

### 9. Risk Assessment and Acceptance

* **Why it matters**: Testing can cause outages or data exposure. Risks must be formally acknowledged.
* **Actions**:

  * Identify risks (service crash, data corruption, alerts in monitoring systems).
  * Assess impact and likelihood.
  * Get written acceptance of these risks from management.
* **Example**:

  * *Risk*: Fuzzing the API may cause slowdowns.
  * *Mitigation*: Conduct fuzzing after 11pm UTC when traffic is low.
  * *Acceptance*: CISO signs off acknowledging possible downtime.

---

### 10. Engagement Kick-off

* **Why it matters**: Marks the official start of testing with all stakeholders aligned.
* **Actions**:

  * Confirm start date and time.
  * Share final Rules of Engagement with both teams.
  * Provide test accounts and VPN credentials.
  * Test communication channels (PGP keys, Slack invite, emergency numbers).
* **Deliverable**: Kick-off email / meeting minutes confirming readiness.

---

## **Example Deliverables of Pre-Engagement Phase**

1. **Authorization Letter** – signed by executive, granting permission.
2. **Rules of Engagement (RoE)** – document with scope, exclusions, testing rules.
3. **Scope Document** – table of in-scope and out-of-scope assets.
4. **Contact & Escalation List** – who to call in case of critical findings.
5. **NDA / Contract** – legal agreement protecting confidentiality.
6. **Testing Preparation Checklist** – tools, accounts, resources ready.

