
## General Command Structure

```
cat <input_file> | urldedupe [options] > <output_file>
```

* **`cat <input_file>`**
  Reads your raw URL list from a file.

* **`|` (pipe)**
  Sends that list as standard input to the next command.

* **`urldedupe [options]`**

  * Strips or normalizes parts of each URL (fragments, query parameters)
  * Removes exact and semantic duplicates
    Common options:
  * `-s` / `--strip-fragment`
  * `-n` / `--normalize-query`
  * `-i` / `--ignore-case`
  * `-d DOMAIN` / `--domain DOMAIN`

* **`> <output_file>`**
  Redirects and saves the cleaned, unique URLs into a new file.

---

## Example

```bash
cat waymoreUrls.txt | urldedupe -s > uniq-urls.txt
```

* Reads `waymoreUrls.txt`
* Strips URL fragments (`-s`)
* Outputs the deduplicated list to `uniq-urls.txt`
