## 1. Purpose / Objective

Confirm whether the target application, device, or service exposes accounts protected by **default, factory, or well-known credentials** (that ship with the software/hardware or are widely published). Default credentials allow trivial account takeover and privilege escalation. This test validates whether such credentials still work and whether the system permits access using easily guessable vendor defaults.

---

## 2. Threat model / Why it matters

* Vendors ship devices and software with administrative accounts and default passwords for initial setup. If these defaults are not changed, an attacker can take control.
* Default credentials are often documented publicly (manuals, vendor docs, online lists), so any attacker can try them.
* Common targets: network devices (routers, switches), IoT devices, admin panels (web UI), databases, application frameworks, development/test instances, cloud orchestration consoles, embedded devices.
* Impact: full compromise of device/app, pivot to internal network, data theft, persistent backdoors.

---

## 3. Scope — what to test

* Web admin panels (e.g., `/admin`, `/manage`, `/phpmyadmin`).
* SSH / Telnet on network devices or servers.
* Database admin interfaces (MySQL root, MongoDB admin).
* Application default accounts (e.g., `admin`, `administrator`, `root`).
* Embedded device web UIs (printers, cameras, NAS).
* Cloud management consoles and orchestration endpoints.
* Any service with initial setup user/password prompts (FTP, SMB, RDP, SNMP community strings).

---

## 4. Pass / Fail criteria (expected secure behavior)

* Fail: Any default or well-known credential grants access to an account with privileges (admin or other).
* Pass: Default accounts disabled, default credentials changed, or system forces password change on first use and enforces complexity/store policy.
* Note: Some products require default credentials for initial provisioning; in such cases, the product should require immediate change and prevent remote access with default creds.

---

## 5. Tools & resources

* **Manual**: browser, SSH/Telnet client, database clients (mysql, psql), RDP client.
* **Proxy/intercept**: Burp Suite / OWASP ZAP (for web UI).
* **Online enumeration tools**: `nmap` with service scripts, `nikto`, `wfuzz`, `ffuf`.
* **Brute/credential attack tools**: `Hydra`, `Medusa`, `Patator`, `Crowbar` (use responsibly and only when authorized).
* **Record lists**: vendor manuals, published default credentials lists (local copies for tests).
* **Device discovery**: `nmap`, `masscan`.
* **Scripting**: Python / Bash for automated checks (with rate-limiting and logging).

---

## 6. Pretest considerations and ethics

* Ensure authorization for active testing—trying many credentials can trigger lockouts, alarms, or disrupt services.
* Start with passive discovery and manual checks before automated bruting.
* Avoid noisy brute force on production without permission; prefer manual checks or use low-rate automated tests.
* Respect rate limits and lockout behavior; document and avoid causing denial of service.

---

## 7. Step-by-step testing methodology

### 7.1 Reconnaissance and identification

1. Discover services and endpoints using `nmap`/`masscan`.

   ```bash
   nmap -sV -p- -T4 target.example.com
   ```

   Note common admin ports: 22 (SSH), 23 (Telnet), 80/443 (HTTP/HTTPS), 8080/8443 (admin web), 3306 (MySQL), 5432 (Postgres), 5984 (CouchDB), 27017 (MongoDB), 161 (SNMP), 3389 (RDP).

2. Enumerate web admin pages by crawling (Burp spider or ffuf/gobuster).

   ```bash
   ffuf -u https://target.example.com/FUZZ -w /path/to/common-admin-uris.txt
   ```

3. Identify login forms and authentication mechanisms (form fields, Basic auth, digest, API tokens).

### 7.2 Manual checks with common default credentials

Start with manual attempts for high-value accounts (admin, root, administrator) using a curated list of common defaults. Examples (do not rely on these only; maintain updated list locally):

* `admin:admin`
* `admin:password`
* `root:root`
* `administrator:administrator`
* `admin:1234` / `admin:12345`

**Web form example (curl):**

```bash
curl -i -X POST 'https://target.example.com/admin/login' \
  -d 'username=admin&password=admin' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -k
```

Inspect response codes, Set-Cookie, redirect behavior to detect success.

**HTTP Basic Auth example:**

```bash
curl -u admin:admin -i 'https://target.example.com/admin/'
```

If HTTP 200 + expected admin page, login succeeded.

**SSH example:**

```bash
ssh admin@target.example.com
# when prompted, try password 'admin'
```

**Database example:**

```bash
mysql -u root -p -h target.example.com
# try pressing Enter or default password 'root'
```

Record successes and the level of privilege obtained.

### 7.3 Automated credential checks (safe approach)

If authorized and permitted:

* Use targeted Hydra/Medusa/Patator with small lists and low parallelism.
* Limit attempts, use delays, and monitor for account lockout.

**Hydra example (HTTP form)**

```bash
hydra -s 443 -S -L users.txt -P default-passwords.txt https-post-form \
 'target.example.com:/admin/login:username=^USER^&password=^PASS^:F=invalid'
```

`-S` for SSL; craft the failure match (`F=`) based on the site’s invalid-login message. Use very low `-t` (threads) and `-w` (wait) to avoid locks.

**Patator example (ssh bruteforce)**

```bash
patator ssh_login host=target.example.com user=FILE0 password=FILE1 0=users.txt 1=passwords.txt -x delay=2
```

**Important:** Always include rate-limiting and logging, and stop if you detect lockout behavior.

### 7.4 Service-specific checks

* **SNMP:** check default community strings `public`/`private`:

  ```bash
  snmpwalk -v1 -c public target.example.com
  ```
* **SMB/Windows shares:** test `guest` / blank credentials.
* **Telnet:** try `admin`/`admin`.
* **IoT webcams / printers / NAS:** web UI default creds often `admin/admin`.

### 7.5 Check for first-time setup flows

Some devices require changing default password at first boot or disallow remote admin until password changed. Verify that:

* The system enforces password change on first use.
* Remote interfaces are disabled until provisioning.

### 7.6 Check password reuse and account metadata

* If default account exists, check whether it is reused across services (same username/password on different ports).
* Check for discovery pages that reveal default user names or serial numbers (may help guess default passwords).

---

## 8. Evidence to collect

* Exact request/response (curl, Burp) showing successful authentication with default creds.
* Screenshots of admin console after login.
* SSH session transcript or database shell prompt demonstrating access.
* `nmap`/`masscan` output showing service and port discovered.
* Logs showing timestamps and account used (if accessible).
* Notes on account privileges (admin, root, operator).

Always redact sensitive production data from reports if shared.

---

## 9. Severity and impact reasoning

* **Critical/High**: Default credentials allow admin/root access to production systems, network devices, or cloud consoles — immediate full compromise potential.
* **Medium**: Default creds grant low-privilege access but can be used for lateral movement or information disclosure.
* **Low**: Non-critical test systems found with default creds, or devices isolated from sensitive networks.

Assess risk by: account privilege, network segmentation, accessible attack surface (internet vs internal), and potential for pivoting.

---

## 10. Remediation and recommendations

1. **Immediate actions**

   * Change default passwords on all devices/services.
   * Disable default accounts if not used; rename admin accounts where supported.
   * Force password change on first use (enforce on provisioning).
2. **Policy & procedure**

   * Maintain an inventory of devices and their provisioning state.
   * Enforce secure onboarding procedures: mandatory password change, password complexity, and MFA where possible.
3. **Technical controls**

   * Disable remote admin interfaces or restrict access via firewall/VPN/ACLs.
   * Implement centralized authentication (LDAP/AD) with controlled credentials.
   * Monitor for authentication attempts using default credentials and alert on successful logins with known defaults.
4. **Operational**

   * Train ops to rotate credentials and remove hard-coded defaults in firmware or config templates.
   * For cloud/dev environments: remove/rotate test credentials before production.

---

## 11. Detection and monitoring suggestions

* Create IDS/IPS signatures for common default-login patterns and alert on authentication using `admin:admin`, `root:root`, etc. (be careful with false positives).
* Log and alert on first-time login attempts to admin accounts.
* Periodically scan inventory for default credentials as part of configuration management checks.

---

## 12. Reporting — sample finding write-up

**Title:** Default administrative credentials present and active
**WSTG:** WSTG-ATHN-02
**Severity:** High (administrative access)
**Affected:** `target.example.com` — web admin page `/admin` and SSH on port 22
**Proof:**

* Web login succeeded with `admin:admin` (see Burp capture).
* Curl request:

  ```
  curl -i -X POST 'https://target.example.com/admin/login' -d 'username=admin&password=admin'
  HTTP/1.1 302 Found
  Location: /admin/dashboard
  Set-Cookie: session=...
  ```
* SSH login:

  ```
  ssh admin@target.example.com
  Password: admin
  Welcome to Example Appliance - Admin Shell
  ```

**Impact:** An attacker can access administrative interface and modify configuration, install backdoors, or pivot to internal network.
**Recommendation:** Immediately change default credentials, disable default admin accounts, require password change on first boot, restrict management interfaces to trusted networks, and implement MFA for admin access. Provide steps and commands to change passwords and to audit other devices.

---

## 13. Automation recipes & safe scanning policy

* Maintain a curated list of default credential pairs (internal only). Use script to attempt only small, targeted checks.
* Example safe Python script (pseudocode) pattern:

  * Read list of targets and credential pairs.
  * For each target, attempt each credential with `max_attempts_per_target=3`.
  * Sleep between attempts (e.g., 5 seconds).
  * Stop on success; log evidence.
* Add `--dry-run` and `--limit` flags to prevent accidental mass scanning.

---

## 14. Example commands & snippets

### Check HTTP basic auth with curl:

```bash
curl -I -s -k -u admin:admin 'https://target.example.com/admin' | head -n 20
```

If `200 OK` and content is admin page → success.

### Check form auth with curl (example site expects JSON):

```bash
curl -s -k -X POST 'https://target.example.com/api/login' \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' -D - | sed -n '1,40p'
```

### Simple Hydra (use with written authorization):

```bash
hydra -s 443 -S -L single_user.txt -P default_passwords.txt \
  https-post-form 'target.example.com:/admin/login:username=^USER^&password=^PASS^:F=Invalid'
```

Adjust failure condition `F=` string to the application's response.

### SNMP default community:

```bash
snmpwalk -v1 -c public target.example.com
```

---

## 15. Common default credentials examples 

* `admin:admin`
* `admin:password`
* `root:root`
* `administrator:administrator`
* `admin:1234` / `admin:12345`
* SNMP community: `public` (read), `private` (write)

**Note:** Maintain a private, up-to-date list derived from vendor manuals and internal asset inventory; do not rely on public internet lists during an assessment without validation.

---

## 16. Checklist

* [ ] Discover admin interfaces and services (nmap/ffuf).
* [ ] Manually test obvious defaults for web forms (admin/admin, etc.).
* [ ] Test Basic/Digest auth endpoints with curl.
* [ ] Check SSH/Telnet, database, SNMP, SMB for default creds.
* [ ] Verify first-time setup forces password change.
* [ ] If authorized and safe, run low-rate automated checks (Hydra/Patator) with logging and rate limits.
* [ ] Collect proof (request/response, screenshots, session tokens).
* [ ] Assess impact and recommend immediate remediation.
* [ ] Add remediation steps: change defaults, disable unused accounts, restrict remote access.
* [ ] Recommend periodic scans for default credentials in inventory.

---

## 17. notes

* Default credential checks should be part of baseline configuration audits and continuous compliance scanning.
* Vendors must eliminate hardcoded defaults in firmware and require secure provisioning workflows.
* For pentesters: include safe guards to avoid disrupting devices (e.g., avoid telnet brute force on routers that might crash under load).
