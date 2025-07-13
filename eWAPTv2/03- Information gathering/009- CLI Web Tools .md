<img width="867" height="195" alt="image" src="https://github.com/user-attachments/assets/f902b669-9653-46e1-b0e4-31d16e128e89" />

## 1. `wget`

### What is `wget`?

`wget` (short for “Web Get”) is a **command-line utility** for **downloading content from the internet** using protocols like HTTP, HTTPS, and FTP.

* It's **non-interactive**, meaning it runs in the background without user input.
* Very useful for **automation, downloading large files**, or **mirroring websites**.
* Pre-installed on many Linux distributions.

### How it works:

`wget` sends an HTTP GET request to the target server. It supports features like **resuming broken downloads**, **recursive fetching**, and **following redirections**.

### Key Features:

* Resume downloads (`-c`)
* Recursive website downloads (`-r`)
* Mirror entire websites (`--mirror`)
* Set custom headers and User-Agents
* Supports cookies and basic authentication

### Real-World Examples:

#### Example 1: Download a file

```bash
wget https://example.com/file.zip
```

#### Example 2: Resume a partial download

```bash
wget -c https://example.com/large.iso
```

#### Example 3: Mirror an entire website

```bash
wget --mirror --convert-links --page-requisites --no-parent https://example.com
```

#### Example 4: Set a fake User-Agent to avoid bot detection

```bash
wget --user-agent="Mozilla/5.0" https://example.com
```

---

## 2. `curl`

### What is `curl`?

`curl` (short for “Client URL”) is a **command-line tool for sending data to or from a server** using a wide variety of supported protocols like HTTP, HTTPS, FTP, SMTP, etc.

* It excels at **interacting with APIs**, **custom HTTP requests**, and **debugging web services**.
* It is very flexible and scriptable.

### How it works:

`curl` lets you define the method (GET, POST, PUT, etc.), headers, body, and more. It's often used to simulate browser requests or API calls.

### Real-World Examples:

#### Example 1: Fetch the HTML of a website

```bash
curl https://example.com
```

#### Example 2: Download a file and save it with the same name

```bash
curl -O https://example.com/file.txt
```

#### Example 3: Send a POST request with login data

```bash
curl -X POST -d "username=admin&password=1234" https://example.com/login
```

#### Example 4: Use custom HTTP headers (e.g., Authorization)

```bash
curl -H "Authorization: Bearer TOKEN123" https://api.example.com/data
```

#### Example 5: Send JSON data with a PUT request

```bash
curl -X PUT -H "Content-Type: application/json" \
     -d '{"email":"user@example.com"}' https://api.example.com/users/1
```

---

## 3. `browsh`

### What is `browsh`?

`browsh` is a **text-based browser** that uses a **headless Firefox engine** to render full websites, including those that require JavaScript. It then translates the page into a format viewable in a terminal.

### How it works:

* Starts a headless Firefox session.
* Loads the page, executes JavaScript, and renders the layout.
* Converts visual output into text that can be viewed in the terminal.

### Real-World Examples:

#### Example 1: Browse Twitter from a remote server

```bash
browsh https://twitter.com
```

#### Example 2: Access Gmail or any JS-heavy page over SSH

```bash
ssh user@vps
browsh https://mail.google.com
```

#### Example 3: Low-bandwidth browsing on servers or embedded systems

You can use browsh in TTY sessions without needing a GUI.

---

## 4. `lynx`

### What is `lynx`?

`lynx` is a **fast, lightweight, text-only browser** for terminals. It doesn't support JavaScript or modern CSS, but it is excellent for reading static content and navigating HTML links via keyboard.

### How it works:

* Fetches the raw HTML.
* Parses and displays only the text and hyperlinks.
* User navigates using arrow keys and numbered links.

### Real-World Examples:

#### Example 1: View man pages or documentation from the terminal

```bash
lynx https://linux.die.net/man/1/grep
```

#### Example 2: Perform reconnaissance on a target website

```bash
lynx https://target.com
```

You can see all links, forms, and page structure with zero JavaScript interference.

#### Example 3: Debug redirection behavior or hidden inputs

```bash
lynx https://target.com/login
```

Useful in CTFs, recon, or server-side behavior inspection.

---

## 5. `drip`

### What is `drip`?

`drip` is a command-line tool used to **simulate slow HTTP requests**. This is especially valuable for testing how servers respond to **slowloris-style** attacks, **connection timeouts**, or **slow clients**.

### How it works:

`drip` opens a connection and sends data slowly over time. This helps simulate stress or abuse patterns that can affect vulnerable servers.

### Key Parameters:

* `--size`: total size of data to send (in bytes)
* `--rate`: speed to send (bytes/second)
* `--delay`: how long to wait before starting the request
* `--method`: HTTP method to use (e.g., GET, POST)

### Real-World Examples:

#### Example 1: Slow POST request simulating upload abuse

```bash
drip --size 10000 --rate 5 --method POST http://target.com/upload
```

#### Example 2: Delay before sending request body

```bash
drip --delay 3000 --size 2000 http://example.com/
```

#### Example 3: Simulate Slowloris for testing server robustness

```bash
drip --size 50000 --rate 2 --method POST http://test.com/slow-endpoint
```

If the server is not configured properly, it may get stuck waiting and exhaust resources.

---

## Summary 

| Tool     | JavaScript Support | Main Use Case                             | Suitable For                    |
| -------- | ------------------ | ----------------------------------------- | ------------------------------- |
| `wget`   | No                 | Downloading files, recursive website copy | Scripting, automation           |
| `curl`   | No                 | Sending HTTP requests, API testing        | Developers, hackers, automation |
| `browsh` | Yes                | Browse full JS-based sites via terminal   | Remote access, low bandwidth    |
| `lynx`   | No                 | View simple static HTML pages in terminal | Accessibility, recon, legacy    |
| `drip`   | N/A                | Simulate slow client attacks or uploads   | Security testing, server stress |

---

