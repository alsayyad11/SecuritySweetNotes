![image](https://github.com/user-attachments/assets/4dbc0e85-4345-4bb5-b4a3-5ffac256248f)


## 🔧DotDotPwn - The Directory Traversal Fuzzer

---

## 📘 **Definition**:

- **DotDotPwn** is a tool designed specifically to identify **Directory Traversal** and **Path Traversal** vulnerabilities.
- It works by fuzzing URLs or parameters to discover whether an attacker can access directories or files outside the intended scope.
- It supports multiple protocols such as **HTTP**, **FTP**, and **TFTP**, making it a versatile option during application or infrastructure testing.
  
---

##  **Installation**:

If you're using **Kali Linux**, DotDotPwn comes pre-installed.

To manually install it:

```bash
git clone https://github.com/wireghoul/dotdotpwn.git
cd dotdotpwn
chmod +x dotdotpwn.pl
```

If required modules are missing:

```bash
cpan
cpan> install <module_name>
```

---

##  **Usage**:

###  Basic Command Format:

```bash
./dotdotpwn.pl -m <mode> -h <hostname> -u <URI> [additional options]
```

###  Example for HTTP fuzzing:

```bash
./dotdotpwn.pl -m http -h 0a3300000377c97e837950880037008c.web-security-academy.net -u "/image?filename=22.jpg" -t 5
```

### 🔍 Explanation:

* `-m http` — sets the protocol to HTTP.
* `-h` — the hostname (without `http://` or `https://`).
* `-u` — the vulnerable URI path (usually includes the file parameter).
* `-t 5` — sets the number of threads for concurrent requests.

---

## ⚙️ **Useful Options**:

| Option                     | Description                                           |
| -------------------------- | ----------------------------------------------------- |
| `-o output.txt`            | Saves the output to a file                            |
| `-d 5`                     | Sets the depth of traversal (`../` levels)            |
| `--cookie "SESSIONID=xyz"` | Send cookies with request                             |
| `-b`                       | Sends payloads in the request body instead of the URL |
| `-v`                       | Verbose mode — shows detailed output                  |

---

## How to use : 

#### Step 1 Open Terminal type: dotdotpwn [space] — help

![image](https://github.com/user-attachments/assets/0d880b23-866f-4b78-8375-d37096499aff)

#### Step 2 :
choose the target and protocol and type the relevant attributes in the command in my case, I tested this tool on Mutillidae and I passed the following command

```
dotdotpwn -m http -h 172.16.111.134/mutillidae/index.php?page=
```

![image](https://github.com/user-attachments/assets/1810103e-7891-4a2d-bc64-a829d2eb9095)

#### Step 3 Hit Enter to launch

![image](https://github.com/user-attachments/assets/b53ce032-987e-415f-b730-904fad2075af)

#### and the tool will do all the fuzzing.

