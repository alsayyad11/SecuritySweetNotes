
**What is dirsearch?**
`dirsearch` is an open‑source Python tool for brute‑forcing web server directories and files. It systematically requests common paths and filenames—using wordlists—to reveal hidden, forgotten, or unlinked endpoints. It’s multi‑threaded, supports custom headers and HTTP methods, and can recurse into discovered directories.

**Key Features**

* Wordlist‑based enumeration of directories and files
* Support for multiple file extensions in one run
* Multi‑threaded for high performance
* HTTP method choice (`GET` or `HEAD`)
* Status‑code filtering (include or exclude specific codes)
* Recursive scanning of discovered directories
* Custom headers (cookies, tokens, User‑Agent)
* Output in text or JSON formats

**Why use dirsearch?**

* To uncover admin panels, backup or config files, test pages, or other hidden resources.
* To validate an application’s security posture by finding unlinked endpoints.
* To feed discovered paths into further scanning tools or manual review.

---

## Installation

### Option A: Virtual Environment with Global Command

1. `git clone https://github.com/maurosoria/dirsearch.git --depth 1`
2. `python3 -m venv dirsearch-env`
3. `source dirsearch-env/bin/activate`
4. `cd dirsearch`
5. `pip3 install .`
6. `pip3 install -r requirements.txt`
7. `sudo cp ~/dirsearch-env/bin/dirsearch /usr/local/bin/`
8. `deactivate`
9. `cd ../`
10. `dirsearch -h`

After this, `dirsearch` runs from any directory.

### Option B: Direct Python Invocation

```bash
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
pip install -r requirements.txt
python3 dirsearch.py -u https://example.com
```

---

## General Command Structure

```
dirsearch -u <target_url> [options]
```

* `-u, --url`: Target URL (e.g. `https://example.com`)
* `-w, --wordlist`: Path to wordlist file
* `-e, --extensions`: Comma‑separated file extensions (e.g. `php,html,js`)
* `-t, --threads`: Number of concurrent threads
* `-x, --exclude-status`: Status codes to ignore (e.g. `400,403,404`)
* `-H, --header`: Custom HTTP header (`"Header: Value"`)
* `--method`: HTTP method (`GET` or `HEAD`)
* `--recursive`: Scan discovered directories recursively
* `-o, --output`: Save results to a file

---

## Basic Examples

1. Single‑domain scan:

   ```bash
   dirsearch -u https://target.com -w common-wordlist.txt
   ```

2. Include extensions and use HEAD for speed:

   ```bash
   dirsearch -u https://target.com -w common.txt -e php,html,js --method HEAD
   ```

3. Ignore 404 and 500 errors, run 50 threads:

   ```bash
   dirsearch -u https://target.com -w common.txt -t 50 -x 400-499,500-599
   ```

---

## Extended Example: Comprehensive File/Directory Scan

```bash
dirsearch -u https://<target.com>/ \
  -e 'conf,config,bak,backup,smp,old,db,sql,asp,aspx,py,rb,php,bhp,cache,cgi,csv,html,inc,jar,js,json,jsp,lock,log,rar,sql.gz,sql.zip,tar,tar.bz2,txt,wad,zip,xml,swp,x~,asp~,py~,rb~,php~,bkp,jsp~,rar,gz,sql~,swp~,wdl,env,ini' \
  --full-url \
  --delay 10 \
  --timeout 30 \
  --proxy 127.0.0.1:8080 \
  --random-agent \
  -t 100 \
  -w ~/SecLists/Discovery/web-Content/combined_words.txt \
  -o hidden-files.txt
```

* `--full-url`: Output full URLs instead of relative paths
* `--delay 10`: 10 ms delay between requests
* `--timeout 30`: 30 s timeout per request
* `--proxy 127.0.0.1:8080`: Route through a local proxy (e.g., Burp)
* `--random-agent`: Rotate User‑Agent header
* `-t 100`: Use 100 concurrent threads
* `-o hidden-files.txt`: Save positive results to `hidden-files.txt`

This command exhaustively tests for nearly all common, backup, config, log, and script file types, with controlled rate, timeouts, proxying, and stealth options.
