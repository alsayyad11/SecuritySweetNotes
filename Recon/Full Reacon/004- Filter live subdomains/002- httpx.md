# What `httpx` :

`httpx` (by ProjectDiscovery) is a fast, multi-purpose HTTP probing tool used to check hosts/URLs for live HTTP services and gather response metadata (status code, title, headers, TLS info, technologies, etc.). It’s designed for recon pipelines: after you collect hostnames (crt.sh, Chaos, VirusTotal, subfinder, Amass), you feed them to `httpx` to find *which ones are actually serving HTTP(S)* and gather useful surface information for follow-up testing.

---

# 1. What `httpx` does 

* Accepts hostnames or URLs and probes HTTP/HTTPS endpoints.
* Detects live web servers and returns: status code, response title, content-length, response time, server headers, TLS certificate info, supported protocols (HTTP/2), and technologies (via simple heuristics).
* Supports concurrency, retries, custom headers, proxy support, IPv4/IPv6, and many output formats (plain, JSON, CSV).
* Integrates well in recon chains (e.g., `chaos | httpx | nuclei`) and with `dnsx`, `subfinder`, `ffuf`, etc.

---

# 2. Installation

## From binary (recommended)

Download release for your OS from ProjectDiscovery GitHub releases and place the binary in your PATH.

## With Go

```bash
GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## With Homebrew (macOS)

```bash
brew tap projectdiscovery/tap
brew install httpx
```

After install, confirm:

```bash
httpx -version
```

---

# 3. Basic usage examples

### Probe a single host

```bash
httpx -u https://example.com
```

### Probe a list of hostnames (stdin)

```bash
cat hosts.txt | httpx -silent -status-code -title -o results.txt
```

### Read from file with `-l`

```bash
httpx -l hosts.txt -o out.txt
```

### Common output fields (common flags)

* `-status-code` : include HTTP status codes.
* `-title` : include HTML `<title>` content.
* `-tech-detect` : attempt to detect tech via headers/HTML.
* `-server` : include `Server` header.
* `-content-length` : include response body length.
* `-tls` / `-tls-probe` : include TLS certificate metadata.

Example:

```bash
cat hosts.txt | httpx -status-code -title -server -content-length -o out.txt
```

---

# 4. Core flags — complete, explained

Use these to control behavior precisely.

* `-l <file>` — read a list of URLs/hosts from file.
* `-u <url>` — probe a single URL.
* `-silent` — minimal output (useful for piping).
* `-status-code` — print HTTP status code.
* `-title` — extract `<title>` from HTML.
* `-server` — print `Server` header (webserver info).
* `-content-length` — print response size.
* `-body` — include response body (careful: large/slow).
* `-timeout <seconds>` — timeout for requests (default ~5s).
* `-threads <n>` — concurrency; number of workers (controls speed).
* `-rate-limit <r>` — throttle requests per second globally.
* `-retries <n>` — number of retries on failure.
* `-follow-redirects` — follow 3xx redirects.
* `-max-redirects <n>` — maximum redirect hops to follow.
* `-paths <file>` — brute-force paths on each host (useful for quick endpoint discovery).
* `-probe` / `-probe-protocols` — control protocol probing behavior (http, https).
* `-http2` / `-h2` — attempt HTTP/2.
* `-ip` — treat input as IPs rather than hostnames (useful if you resolved hosts first).
* `-o, -oJ, -oC` — output to file (plain, JSON, CSV).
* `-json` — print JSON per result (machine-friendly).
* `-silent` — only results (no banner).
* `-proxy <url>` — use HTTP/SOCKS proxy (e.g., Burp: `http://127.0.0.1:8080`).
* `-proxy-socks` — use SOCKS proxy.
* `-headers` — supply custom headers (e.g., `-H 'User-Agent: custom'`).
* `-random-agent` — use random user agents for each request.
* `-no-color` — remove color codes.
* `-v` or `-verbose` — verbose logging for debugging.

---

# 5. Real-world example workflows

### 5.1 Fast “which hosts are alive” (minimal)

```bash
cat all_passive.txt | httpx -silent -status-code -o live.txt
```

`live.txt` will contain lines like:

```
https://api.target.com [200]
http://old.target.com [404]
```

### 5.2 Probe + title + tech detection + JSON output

```bash
cat all_passive.txt | httpx -status-code -title -tech-detect -json -o out.json
```

Each JSON line is a structured record; feed directly to other tools or a parser.

### 5.3 Use with dnsx and nuclei (common PD pipeline)

```bash
cat all_passive.txt \
  | dnsx -a -resp -o resolved.txt \
  | httpx -status-code -title -tech-detect -o http_results.txt

# then run templates
cat http_results.txt | nuclei -t /path/to/templates -o findings.txt
```

### 5.4 Use with `chaos` (ProjectDiscovery pipeline)

```bash
chaos -d target.com -silent \
  | httpx -silent -status-code -title -threads 150 -o target_http.txt
```

### 5.5 Bruteforce common paths on live hosts

```bash
cat live_hosts.txt | httpx -paths /common_paths.txt -status-code -o paths_found.txt
```

This tries each path on each host and reports responses.

---

# 6. Performance & tuning

* **Threads/Concurrency (`-threads`)**: primary speed control. Default safe value is low; for fast networks increase to 100–500 depending on your bandwidth and target tolerance.
* **Rate limiting (`-rate-limit`)**: use this to avoid overwhelming targets or hitting middleboxes. Example `-rate-limit 200` (req/s).
* **Timeouts (`-timeout`)**: reduce to speed up slow hosts; increase if probing slow networks or many TLS handshakes.
* **Retries (`-retries`)**: useful when network is flaky; default is small.
* **HTTP/2**: enabling can speed up some hosts but may affect behavior; test on sample targets.
* **Use `dnsx` first**: resolving via `dnsx` and feeding IPs to `httpx` avoids repeated DNS lookups and can be faster.

Tuning advice:

* Start conservative (threads 50, timeout 10s) then raise threads gradually.
* Always respect rate limits in bug bounty rules and company policy.

---

# 7. Advanced flags & features (detailed)

### Proxy support (use Burp)

```bash
httpx -l hosts.txt -proxy http://127.0.0.1:8080
```

Useful for funneling traffic to Burp or a logging proxy.

### SNI / Host header control

* `-H` or `-headers` allows custom Host header; use when probing virtual hosts or IPs with specific SNI:

```bash
httpx -u https://93.184.216.34 -H "Host: example.com"
```

### Force HTTPS or HTTP only

* `-probe` controls which protocols to try. Use `-probe http` or `-probe https` to restrict.

### Path probing (simple fuzzing)

* `-paths` accepts a file of paths to append to each host; fast way to find common endpoints without full ffuf:

```bash
httpx -l hosts.txt -paths /wordlist/common-paths.txt -status-code -o paths.txt
```

### Include response body

* `-body` will print response body — only use carefully (can be huge, leak sensitive data).

### Capture TLS certificate info

* `-tls` or `-tls-probe` flags show certificate CN, SANs, issuer, validity. Useful to spot wildcard certs or misissued certs:

```bash
httpx -l hosts.txt -tls -o tls_info.json
```

### HTTP/2 & ALPN

* `-http2` tries HTTP/2. Some servers respond differently; useful for performance and feature detection.

### IPv6 & IP binding

* Use `-ip` or allow IPv6 by resolving first with `dnsx -aaaa`.

---

# 8. Output formats & processing

* **Plain text** — default; easy to read and pipe.
* **JSON (`-json`)** — one JSON object per line, great for further automation.
* **CSV (`-oC`)** — tabular export for reports/spreadsheets.
* **Custom parsing:** use `jq` on JSON output, or `awk`/`cut` on plain output.

Example (JSON to jq):

```bash
httpx -l hosts.txt -json | jq -r '.url + " " + (.status_code|tostring) + " " + .title'
```

---

# 9. Integration patterns

* `subfinder | anew | httpx | nuclei` — collect, dedupe, probe, then run vulnerability templates.
* `dnsx` before `httpx` to resolve quickly and parallelize DNS & HTTP tasks.
* Use `httpx` as a health-check in CI pipelines (monitor infra changes): run `httpx` daily against assets and alert if status codes change.

Example CI snippet

```bash
curl -s https://raw.githubusercontent.com/org/hosts/main/list.txt | httpx -status-code -json > status.json
# parse status.json and fail CI if unexpected 5xx found
```

---

# 10. Security, ethics & polite operation

* **Do not** use `httpx` to perform intrusive tests without permission. It is a reconnaissance tool; active scanning and exploitation require authorization.
* Rate-limit and respect robots/policies for targets you do not own.
* Use proxies for logging and safe review (Burp), and redact any captured sensitive data.

---

# 11. Troubleshooting & common pitfalls

* **DNS latency**: many slow results are DNS-bound. Pre-resolve with `dnsx` to speed up.
* **TLS handshake slow**: TLS increases latency; increase timeout or lower threads if you see many TLS failures.
* **False negatives**: some servers block automated clients or return different content. Use `-headers` to set `User-Agent` and `Accept` to mimic browsers: `-H "User-Agent: Mozilla/5.0"`
* **Large body responses**: avoid `-body` unless you filter paths, or stream to disk to avoid consuming memory.
* **Redirect loops**: use `-max-redirects` to limit following.
* **Rate-limited by target**: use `-rate-limit` to keep requests reasonable.

---

# 12. Practical examples you can copy-paste

1. Quick live host check and save URLs:

```bash
cat subs.txt | httpx -silent -status-code -o live_urls.txt
```

2. JSON output with TLS and tech detection:

```bash
cat subs.txt | httpx -json -tls -tech-detect -o scan.json
```

3. Probe with Burp proxy:

```bash
cat subs.txt | httpx -threads 200 -proxy http://127.0.0.1:8080 -o proxied.txt
```

4. Path probing with concurrency and rate-limit:

```bash
cat live_urls.txt | httpx -paths ./common_paths.txt -threads 200 -rate-limit 100 -status-code -o paths_found.txt
```

5. Full PD pipeline:

```bash
chaos -d target.com -silent \
  | anew subs.tmp \
  | dnsx -a -resp -o resolved.txt \
  | httpx -status-code -title -tech-detect -threads 300 -o http_results.json
```

---

### Usage 

```bash
httpx -h
```
This will display help for the tool. Here are all the switches it supports.

```
httpx is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.

Usage:
  httpx [flags]

Flags:
INPUT:
   -l, -list string      input file containing list of hosts to process
   -rr, -request string  file containing raw request
   -u, -target string[]  input target host(s) to probe

PROBES:
   -sc, -status-code                      display response status-code
   -cl, -content-length                   display response content-length
   -ct, -content-type                     display response content-type
   -location                              display response redirect location
   -favicon                               display mmh3 hash for '/favicon.ico' file
   -hash string                           display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)
   -jarm                                  display jarm fingerprint hash
   -rt, -response-time                    display response time
   -lc, -line-count                       display response body line count
   -wc, -word-count                       display response body word count
   -title                                 display page title
   -bp, -body-preview                     display first N characters of response body (default 100)
   -server, -web-server                   display server name
   -td, -tech-detect                      display technology in use based on wappalyzer dataset
   -cff, -custom-fingerprint-file string  path to a custom fingerprint file for technology detection
   -method                                display http request method
   -websocket                             display server using websocket
   -ip                                    display host ip
   -cname                                 display host cname
   -extract-fqdn, -efqdn                  get domain and subdomains from response body and header in jsonl/csv output
   -asn                                   display host asn information
   -cdn                                   display cdn/waf in use (default true)
   -probe                                 display probe status

HEADLESS:
   -ss, -screenshot                 enable saving screenshot of the page using headless browser
   -system-chrome                   enable using local installed chrome for screenshot
   -ho, -headless-options string[]  start headless chrome with additional options
   -esb, -exclude-screenshot-bytes  enable excluding screenshot bytes from json output
   -ehb, -exclude-headless-body     enable excluding headless header from json output
   -no-screenshot-full-page         disable saving full page screenshot
   -st, -screenshot-timeout value   set timeout for screenshot in seconds (default 10s)
   -sid, -screenshot-idle value     set idle time before taking screenshot in seconds (default 1s)

MATCHERS:
   -mc, -match-code string            match response with specified status code (-mc 200,302)
   -ml, -match-length string          match response with specified content length (-ml 100,102)
   -mlc, -match-line-count string     match response body with specified line count (-mlc 423,532)
   -mwc, -match-word-count string     match response body with specified word count (-mwc 43,55)
   -mfc, -match-favicon string[]      match response with specified favicon hash (-mfc 1494302000)
   -ms, -match-string string[]        match response with specified string (-ms admin)
   -mr, -match-regex string[]         match response with specified regex (-mr admin)
   -mcdn, -match-cdn string[]         match host with specified cdn provider (cloudfront, fastly, gcore, gocache, google)
   -mrt, -match-response-time string  match response with specified response time in seconds (-mrt '< 1')
   -mdc, -match-condition string      match response with dsl expression condition

EXTRACTOR:
   -er, -extract-regex string[]   display response content with matched regex
   -ep, -extract-preset string[]  display response content matched by a pre-defined regex (url,ipv4,mail)

FILTERS:
   -fc, -filter-code string               filter response with specified status code (-fc 403,401)
   -fep, -filter-error-page               filter response with ML based error page detection
   -fd, -filter-duplicates                filter out near-duplicate responses (only first response is retained)
   -fl, -filter-length string             filter response with specified content length (-fl 23,33)
   -flc, -filter-line-count string        filter response body with specified line count (-flc 423,532)
   -fwc, -filter-word-count string        filter response body with specified word count (-fwc 423,532)
   -ffc, -filter-favicon string[]         filter response with specified favicon hash (-ffc 1494302000)
   -fs, -filter-string string[]           filter response with specified string (-fs admin)
   -fe, -filter-regex string[]            filter response with specified regex (-fe admin)
   -fcdn, -filter-cdn string[]            filter host with specified cdn provider (cloudfront, fastly, gcore, gocache, google)
   -frt, -filter-response-time string     filter response with specified response time in seconds (-frt '> 1')
   -fdc, -filter-condition string         filter response with dsl expression condition
   -strip                                 strips all tags in response. supported formats: html,xml (default html)
   -lof, -list-output-fields              list of fields to output (comma separated)
   -eof, -exclude-output-fields string[]  exclude output fields output based on a condition

RATE-LIMIT:
   -t, -threads int              number of threads to use (default 50)
   -rl, -rate-limit int          maximum requests to send per second (default 150)
   -rlm, -rate-limit-minute int  maximum number of requests to send per minute

MISCELLANEOUS:
   -pa, -probe-all-ips        probe all the ips associated with same host
   -p, -ports string[]        ports to probe (nmap syntax: eg http:1,2-10,11,https:80)
   -path string               path or list of paths to probe (comma-separated, file)
   -tls-probe                 send http probes on the extracted TLS domains (dns_name)
   -csp-probe                 send http probes on the extracted CSP domains
   -tls-grab                  perform TLS(SSL) data grabbing
   -pipeline                  probe and display server supporting HTTP1.1 pipeline
   -http2                     probe and display server supporting HTTP2
   -vhost                     probe and display server supporting VHOST
   -ldv, -list-dsl-variables  list json output field keys name that support dsl matcher/filter

UPDATE:
   -up, -update                 update httpx to latest version
   -duc, -disable-update-check  disable automatic httpx update check

OUTPUT:
   -o, -output string                     file to write output results
   -oa, -output-all                       filename to write output results in all formats
   -sr, -store-response                   store http response to output directory
   -srd, -store-response-dir string       store http response to custom directory
   -ob, -omit-body                        omit response body in output
   -csv                                   store output in csv format
   -csvo, -csv-output-encoding string     define output encoding
   -j, -json                              store output in JSONL(ines) format
   -irh, -include-response-header         include http response (headers) in JSON output (-json only)
   -irr, -include-response                include http request/response (headers + body) in JSON output (-json only)
   -irrb, -include-response-base64        include base64 encoded http request/response in JSON output (-json only)
   -include-chain                         include redirect http chain in JSON output (-json only)
   -store-chain                           include http redirect chain in responses (-sr only)
   -svrc, -store-vision-recon-cluster     include visual recon clusters (-ss and -sr only)
   -pr, -protocol string                  protocol to use (unknown, http11, http2 [experimental], http3 [experimental])
   -fepp, -filter-error-page-path string  path to store filtered error pages (default "filtered_error_page.json")

CONFIGURATIONS:
   -config string                   path to the httpx configuration file (default $HOME/.config/httpx/config.yaml)
   -r, -resolvers string[]          list of custom resolver (file or comma separated)
   -allow string[]                  allowed list of IP/CIDR's to process (file or comma separated)
   -deny string[]                   denied list of IP/CIDR's to process (file or comma separated)
   -sni, -sni-name string           custom TLS SNI name
   -random-agent                    enable Random User-Agent to use (default true)
   -auto-referer                    set the Referer header to the current URL
   -H, -header string[]             custom http headers to send with request
   -http-proxy, -proxy string       proxy (http|socks) to use (eg http://127.0.0.1:8080)
   -unsafe                          send raw requests skipping golang normalization
   -resume                          resume scan using resume.cfg
   -fr, -follow-redirects           follow http redirects
   -maxr, -max-redirects int        max number of redirects to follow per host (default 10)
   -fhr, -follow-host-redirects     follow redirects on the same host
   -rhsts, -respect-hsts            respect HSTS response headers for redirect requests
   -vhost-input                     get a list of vhosts as input
   -x string                        request methods to probe, use 'all' to probe all HTTP methods
   -body string                     post body to include in http request
   -s, -stream                      stream mode - start elaborating input targets without sorting
   -sd, -skip-dedupe                disable dedupe input items (only used with stream mode)
   -ldp, -leave-default-ports       leave default http/https ports in host header (eg. http://host:80 - https://host:443
   -ztls                            use ztls library with autofallback to standard one for tls13
   -no-decode                       avoid decoding body
   -tlsi, -tls-impersonate          enable experimental client hello (ja3) tls randomization
   -no-stdin                        Disable Stdin processing
   -hae, -http-api-endpoint string  experimental http api endpoint

DEBUG:
   -health-check, -hc        run diagnostic check up
   -debug                    display request/response content in cli
   -debug-req                display request content in cli
   -debug-resp               display response content in cli
   -version                  display httpx version
   -stats                    display scan statistic
   -profile-mem string       optional httpx memory profile dump file
   -silent                   silent mode
   -v, -verbose              verbose mode
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default: 5)
   -nc, -no-color            disable colors in cli output
   -tr, -trace               trace

OPTIMIZATIONS:
   -nf, -no-fallback                  display both probed protocol (HTTPS and HTTP)
   -nfs, -no-fallback-scheme          probe with protocol scheme specified in input 
   -maxhr, -max-host-error int        max error count per host before skipping remaining path/s (default 30)
   -e, -exclude string[]              exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)
   -retries int                       number of retries
   -timeout int                       timeout in seconds (default 10)
   -delay value                       duration between each http request (eg: 200ms, 1s) (default -1ns)
   -rsts, -response-size-to-save int  max response size to save in bytes (default 2147483647)
   -rstr, -response-size-to-read int  max response size to read in bytes (default 2147483647)

CLOUD:
   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)
   -ac, -auth-config string        configure projectdiscovery cloud (pdcp) api key credential file
   -pd, -dashboard                 upload / view output in projectdiscovery cloud (pdcp) UI dashboard
   -tid, -team-id string           upload asset results to given team id (optional)
   -aid, -asset-id string          upload new assets to existing asset id (optional)
   -aname, -asset-name string      assets group name to set (optional)
   -pdu, -dashboard-upload string  upload httpx output file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard

                                                                                                                         
```


## Guide : [Httpx by Projectdiscovery](https://docs.projectdiscovery.io/opensource/httpx/overview)
