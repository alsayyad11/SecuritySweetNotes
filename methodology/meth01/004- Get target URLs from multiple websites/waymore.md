<img width="823" height="160" alt="467401231-aac2d7cb-ef28-4ec1-a389-25d76287d47d" src="https://github.com/user-attachments/assets/984d31e8-4609-46e1-93bc-e191770e8424" />

## Overview

`waymore` is an open‑source command‑line tool for collecting both historical and live URLs across one or more domains. It aggregates data from multiple public sources to reveal forgotten, hidden, or deprecated endpoints—ideal for bug bounty hunting, penetration testing, and recon workflows.

## Why Use Waymore?

* **Uncover forgotten endpoints**: Find old panels, upload forms or APIs no longer linked from the main site.
* **Broader visibility**: Combine signals from ten-plus archives and services.
* **Efficient workflow**: Integrates with tools like `httpx`, `gf`, `ffuf`, and `nuclei`.

## Data Sources

Waymore pulls URLs from:

1. Wayback Machine (archive.org)
2. Common Crawl
3. AlienVault OTX
4. URLScan.io
5. Web Archive APIs (CDX, etc.)
6. Other passive OSINT archives

## Features

| Feature              | Description                                                |
| -------------------- | ---------------------------------------------------------- |
| Multiple archives    | Aggregates URLs from 10+ public sources                    |
| Single or bulk input | Accepts one domain (`-i`) or a list of domains (`-l`)      |
| URL filtering        | Filter by HTTP status code, content length, file extension |
| Output formats       | Raw URLs (`-oU`), JSON (`-oJ`), categorized (`-oC`)        |
| Threaded performance | Fast, multi‑threaded enumeration                           |
| CLI entry point      | Simple commands and flags                                  |

## Installation

### Option A: Virtual Environment with Global Command

1. Clone the repository

   ```bash
   git clone https://github.com/xnl-h4ck3r/waymore.git
   ```

2. Create and activate a Python virtual environment

   ```bash
   python3 -m venv waymore-env
   source waymore-env/bin/activate
   ```

3. Install waymore and dependencies

   ```bash
   cd waymore
   pip install .
   pip install -r requirements.txt
   ```

4. Copy the executable to a system path

   ```bash
   sudo cp ~/waymore-env/bin/waymore /usr/local/bin/
   ```

5. Deactivate the virtual environment

   ```bash
   deactivate
   ```

After this, you can run `waymore` from any directory:

```bash
waymore -h
```

### Option B: Direct Python Invocation

If you prefer not to set up a global command:

```bash
git clone https://github.com/xnl-h4ck3r/waymore.git
cd waymore
pip install -r requirements.txt
python3 waymore.py -i example.com
```

## Basic Usage Examples

1. **Single-domain enumeration**

   ```bash
   waymore -i example.com
   ```

2. **Bulk domains from file**

   ```bash
   waymore -l domains.txt
   ```

3. **Raw URLs output**

   ```bash
   waymore -i example.com -oU urls.txt
   ```

4. **Broad recon mode**

   ```bash
   waymore -i example.com -mode B
   ```

5. **Filter by HTTP status (e.g., 200 OK)**

   ```bash
   waymore -i example.com -mode B -mc 200
   ```

6. **Pipe domains or URLs**

   ```bash
   cat valid-subdomains.txt | waymore -mode B -oU waymoreUrls.txt -mc 200
   ```

## Output Options

| Flag  | Type        | Description                      |
| ----- | ----------- | -------------------------------- |
| `-oU` | Raw URLs    | One URL per line                 |
| `-oJ` | JSON        | Structured JSON output           |
| `-oC` | Categorized | Grouped by source or status code |

## Typical Recon Workflow

```bash
# 1. Enumerate all archived URLs
waymore -i target.com -mode B -oU waymore-urls.txt

# 2. Filter for live endpoints
cat waymore-urls.txt | httpx -mc 200 > alive-urls.txt

# 3. Search for interesting patterns
grep -Ei "upload|admin|panel|debug" alive-urls.txt

# 4. Fuzz or scan the results
#    e.g. ffuf, nuclei, or custom scripts
```

## Uninstallation

To remove the global command and environment:

```bash
sudo rm /usr/local/bin/waymore
rm -rf waymore-env
```

## Quick Reference

| Command                  | Purpose                                |                         |
| ------------------------ | -------------------------------------- | ----------------------- |
| `waymore -i domain.com`  | Single-domain URL enumeration          |                         |
| `waymore -l domains.txt` | Bulk domains enumeration               |                         |
| `waymore -mode B`        | Broad, all-source enumeration          |                         |
| `-oU file.txt`           | Output raw URLs to `file.txt`          |                         |
| `-mc 200`                | Filter results to status code 200 only |                         |
| \`cat list               | waymore\`                              | Read domains from stdin |
| `waymore -h`             | Display help                           |                         |

## References

* GitHub Repository: [https://github.com/xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore)
* Author: xnl-h4ck3r
* License: MIT
