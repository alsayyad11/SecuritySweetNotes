## URL Deduplication with `urldedupe`

`urldedupe` is a command-line utility developed by **TomNomNom**, used to intelligently remove duplicate URLs from a list. It is especially useful when dealing with large amounts of URLs gathered from tools like `waybackurls`, `gau`, or `katana`.

---

### What Makes `urldedupe` Special?

Unlike regular `sort -u`, `urldedupe` is **context-aware**:

* It **ignores the order of query parameters**, treating `?a=1&b=2` and `?b=2&a=1` as the same.
* It **removes empty or duplicate parameters**, such as `?a=1&b=` or `?a=1&b`.

This helps reduce noise and redundancy during parameter analysis or fuzzing preparation.

---

### Installation

If you have Go installed:

```bash
go install github.com/tomnomnom/hacks/urldedupe@latest
```

Then add Go binaries to your PATH if not already:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

---

### Usage

**Basic syntax:**

```bash
urldedupe < input.txt > output.txt
```

or using a pipe:

```bash
cat input.txt | urldedupe > output.txt
```

for more than one file :

```bash
cat input1.txt input2.txt | urldedupe > output.txt
```

**Example:**

```bash
cat waybackurls.txt | urldedupe > unique_urls.txt
```

This will take a list of potentially messy, redundant URLs and output only the unique, cleaned ones.

---

### Example Input

```text
https://example.com/page?id=1&sort=asc
https://example.com/page?sort=asc&id=1
https://example.com/page?id=1&sort=
https://example.com/page?id=1
```

### Example Output (after `urldedupe`):

```text
https://example.com/page?id=1&sort=asc
https://example.com/page?id=1
```

Notice how `urldedupe` recognized that the first two URLs are equivalent (despite parameter order) and removed duplicates accordingly.

---


