

### Tool 1: Sublist3r

**Description:**
Sublist3r is a Python-based tool for passive subdomain enumeration using various OSINT sources.

**Command Structure:**

```bash
sublist3r -d <target_domain> [options]
```

**Common Parameters:**

| Parameter | Description                                |
| --------- | ------------------------------------------ |
| `-d`      | Target domain name (required)              |
| `-b`      | Enable brute-force using built-in wordlist |
| `-t`      | Number of threads (default is 10)          |
| `-v`      | Verbose output                             |
| `-o`      | Output file name                           |
| `-h`      | Show help message                          |

**Example:**

```bash
sublist3r -d google.com -b -t 50 -v -o google_sublist3r.txt
```

---

### Tool 2: Subfinder

**Description:**
Subfinder is a fast and modern subdomain enumerator written in Go. It supports passive and recursive modes.

**Command Structure:**

```bash
subfinder -d <target_domain> [options]
```

**Common Parameters:**

| Parameter  | Description                            |
| ---------- | -------------------------------------- |
| `-d`       | Target domain                          |
| `-dL`      | File containing a list of domains      |
| `-r`       | Enable recursive subdomain enumeration |
| `-all`     | Use all available passive sources      |
| `-silent`  | Print subdomains only (no logs)        |
| `-o`       | Output file                            |
| `-oJ`      | Output in JSON format                  |
| `-nW`      | Disable wildcard filtering             |
| `-timeout` | Set timeout for sources (in seconds)   |
| `-h`       | Show help message                      |

**Example:**

```bash
subfinder -d google.com -r -all -o google_subfinder.txt
```

---

### Tool 3: Subextreme

**Description:**
Subextreme is a Go-based subdomain enumeration tool focused on passive and recursive discovery using APIs and online services.

**Command Structure:**

```bash
subextreme -d <target_domain> [options]
```

**Common Parameters:**

| Parameter    | Description                      |
| ------------ | -------------------------------- |
| `-d`         | Target domain                    |
| `-dL`        | File containing multiple domains |
| `-o`         | Output file                      |
| `-r`         | Enable recursive mode            |
| `-silent`    | Suppress extra output            |
| `--no-color` | Disable colored output           |
| `-h`         | Show help message                |

**Example:**

```bash
subextreme -d google.com -r -o google_subextreme.txt
```

---
