

## 1) Save all URLs that contain query parameters (`?`) into `parameters.txt`

### Simple, safe command (recommended)

```bash
grep -F '?' urls.txt | tee parameters.txt
```

Explanation:

* `grep -F` treats the pattern as a literal string (no regex). So `?` is matched as a literal character.
* `tee parameters.txt` writes the matching lines to `parameters.txt` **and** prints them to the terminal.
* This will match any URL that contains a `?` (i.e., it has a query string).

### Variant — use PCRE to ensure there is at least one query key/value:

```bash
grep -P '\?.+' urls.txt | tee parameters.txt
```

* `-P` uses PCRE (GNU grep). `\?.+` matches a `?` followed by one or more characters — avoids matching an URL that ends with `?` with nothing after (rare).

### Append rather than overwrite

If you want to append to `parameters.txt` instead of replacing it:

```bash
grep -F '?' urls.txt | tee -a parameters.txt
```

### Count how many parameterized URLs were collected

```bash
grep -F '?' urls.txt | tee parameters.txt | wc -l
# or if saved already:
wc -l parameters.txt
```

---

## 2) Save all JavaScript file URLs into `js_files.txt` (robust)

We want to match these cases:

* `https://example.com/script.js`
* `https://example.com/script.js?v=1.2.3`
* `https://cdn.example.com/assets/main.min.JS` (case-insensitive)

### Correct, robust command:

```bash
grep -iE '\.js($|\?)' urls.txt | tee js_files.txt
```

Explanation:

* `-i` = case-insensitive (matches `.JS`, `.Js`, etc.).
* `-E` = extended regex.
* `'\.js($|\?)'` matches `.js` followed by end-of-line (`$`) OR a literal `?` (for query strings).
* `tee js_files.txt` saves and prints the results.

### Remove query strings and dedupe canonical JS paths

To get a canonical list of JS paths without version querystrings and no duplicates:

```bash
grep -iE '\.js($|\?)' urls.txt \
  | sed 's/[?].*$//' \
  | sort -u \
  | tee js_files_unique.txt
```

* `sed 's/[?].*$//'` removes everything from `?` to the end (strip query).
* `sort -u` deduplicates.

### Count JS files

```bash
# total matches (with duplicates)
grep -iE '\.js($|\?)' urls.txt | wc -l

# unique canonical JS files
grep -iE '\.js($|\?)' urls.txt | sed 's/[?].*$//' | sort -u | wc -l
```

---

## 3) Helpful extra filters & patterns

### Match specific parameter name (e.g., `id=`)

```bash
grep -E '[?&]id=' urls.txt | tee id_params.txt
```

* Matches `?id=` or `&id=` in any position.

### Extract just the query string from each URL

```bash
grep -F '?' urls.txt | sed -n 's/^[^?]*?\([^#]*\).*$/\1/p' | tee queries.txt
```

* This prints only the `param=value&...` portion.

### Extract JS filenames (basenames) from JS URLs

```bash
grep -iE '\.js($|\?)' urls.txt | sed 's/[?].*$//' | sed 's#.*/##' | sort -u | tee js_names.txt
```

* `sed 's#.*/##'` strips the path, leaving `main.js`, `vendor.js`, etc.

### Check which JS URLs are live (status codes) with `httpx`

```bash
grep -iE '\.js($|\?)' urls.txt | sed 's/[?].*$//' | sort -u | httpx -silent -status-code -o js_http_status.txt
```

* `httpx` will check each JS URL and write status codes (install httpx first).

---

## 4) Common pitfalls & performance tips

* **Do not run `grep ?` unquoted** — the shell may expand `?` to filenames. Always quote or use `-F`.
* **Case sensitivity** — use `-i` to catch `.JS`.
* **Duplicates** — archived sources produce duplicates; use `sort -u` to dedupe.
* **Very large files** — for very large URL lists use `rg` (ripgrep) which is faster:

  ```bash
  rg -i '\.js($|\?)' urls.txt | tee js_files.txt
  ```
* **URL-encoded `?`** — if the file contains `%3F` (encoded question mark), `grep -F '?'` won’t match that. Usually you don’t have to handle `%3F` unless sources are weird.
* **Binary or weird lines** — if `urls.txt` is huge, consider streaming and processing in chunks.

---

## 5) Full ready-to-run bash script (performs everything and prints a summary)

Save this as `filter_urls.sh`, make executable with `chmod +x filter_urls.sh`, then run `./filter_urls.sh urls.txt`.

```bash
#!/usr/bin/env bash
# filter_urls.sh
# Usage: ./filter_urls.sh urls.txt
set -euo pipefail

INFILE="${1:-urls.txt}"
OUT_DIR="${2:-.}"
mkdir -p "$OUT_DIR"

PARAM_FILE="$OUT_DIR/parameters.txt"
JS_FILE="$OUT_DIR/js_files.txt"
JS_UNIQ="$OUT_DIR/js_files_unique.txt"
JS_NAMES="$OUT_DIR/js_names.txt"

echo "[*] Input file: $INFILE"
echo "[*] Output dir: $OUT_DIR"

# 1) Parameterized URLs (literal '?')
echo "[*] Extracting parameterized URLs to $PARAM_FILE"
grep -F '?' "$INFILE" | tee "$PARAM_FILE"

# Count param URLs
PARAM_COUNT=$(wc -l < "$PARAM_FILE" || echo 0)
echo "[*] Parameterized URLs found: $PARAM_COUNT"

# 2) JS URLs (case-insensitive, handle querystrings)
echo "[*] Extracting JS URLs to $JS_FILE"
grep -iE '\.js($|\?)' "$INFILE" | tee "$JS_FILE"

# Total JS matches
JS_COUNT=$(wc -l < "$JS_FILE" || echo 0)
echo "[*] Total JS URL matches: $JS_COUNT"

# 3) Canonical JS file list (strip query strings, dedupe)
echo "[*] Generating unique canonical JS file list: $JS_UNIQ"
grep -iE '\.js($|\?)' "$INFILE" \
  | sed 's/[?].*$//' \
  | sort -u \
  | tee "$JS_UNIQ"

JS_UNIQ_COUNT=$(wc -l < "$JS_UNIQ" || echo 0)
echo "[*] Unique canonical JS files: $JS_UNIQ_COUNT"

# 4) JS basenames (main.js, vendor.js, etc.)
echo "[*] Extracting JS basenames to $JS_NAMES"
cat "$JS_UNIQ" | sed 's#.*/##' | sort -u | tee "$JS_NAMES"
JS_NAMES_COUNT=$(wc -l < "$JS_NAMES" || echo 0)
echo "[*] Unique JS basenames: $JS_NAMES_COUNT"

# 5) Optional: check live JS files via httpx (if httpx exists)
if command -v httpx >/dev/null 2>&1; then
  echo "[*] httpx found — checking HTTP status of canonical JS files (output: $OUT_DIR/js_http_status.txt)"
  cat "$JS_UNIQ" | httpx -silent -status-code -o "$OUT_DIR/js_http_status.txt"
  echo "[*] Saved js HTTP status to $OUT_DIR/js_http_status.txt"
else
  echo "[*] httpx not installed — skipping JS live check. Install httpx to check statuses."
fi

echo "[*] Done. Summary:"
echo "  - Parameterized URLs: $PARAM_COUNT (saved to $PARAM_FILE)"
echo "  - JS matches: $JS_COUNT (saved to $JS_FILE)"
echo "  - Unique JS files: $JS_UNIQ_COUNT (saved to $JS_UNIQ)"
echo "  - JS basenames: $JS_NAMES_COUNT (saved to $JS_NAMES)"
```

---

## 6) Quick examples (copy-paste)

Save parameterized URLs and count:

```bash
grep -F '?' urls.txt | tee parameters.txt
wc -l parameters.txt
```

Save JS URLs and unique canonical JS files:

```bash
grep -iE '\.js($|\?)' urls.txt | tee js_files.txt
grep -iE '\.js($|\?)' urls.txt | sed 's/[?].*$//' | sort -u | tee js_files_unique.txt
wc -l js_files_unique.txt
```

Check JS files live (if `httpx` installed):

```bash
cat js_files_unique.txt | httpx -silent -status-code -o js_status.txt
```

---

## 7)  notes

* Use `-F '?'` for the simplest and safest match for querystrings.
* Use `-iE '\.js($|\?)'` to reliably catch `.js` files including querystrings and different cases.
* Deduplicate (`sort -u`) after stripping querystrings if you want canonical asset lists.
* For very large lists, use `rg` for speed: `rg -i '\.js($|\?)' urls.txt`.
* Always inspect a small sample before running big scans (e.g., `grep ... | head`) to validate patterns.

---
