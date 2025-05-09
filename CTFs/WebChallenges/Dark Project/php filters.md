## 1. What Are PHP Filters?

**PHP Filters** are a feature in PHP that allow developers (or attackers) to manipulate the way files and streams are processed.
 Using wrappers like :

```
php://filter
```

you can apply transformations on file contents before they're read or written.

---

### Syntax

```

php://filter/\[read=filter1|filter2...]\[write=filter3...]/resource=target\_file

```

- `read=`: filters applied while **reading**
- `write=`: filters applied while **writing**
- `resource=`: the actual file or stream you want to read/write

---

### Commonly Used Filters

| Filter Name                 | Description                           |
|----------------------------|---------------------------------------|
| `convert.base64-encode`    | Encodes content in Base64             |
| `convert.base64-decode`    | Decodes Base64 content                |
| `string.toupper`           | Converts text to uppercase            |
| `string.tolower`           | Converts text to lowercase            |
| `string.rot13`             | Applies ROT13 cipher                  |
| `zlib.deflate` / `inflate` | Compression/decompression (zlib)      |

---

###  Example 

If you want to view the raw source code of a PHP file (like `index.php`) without executing it:

```

php://filter/read=convert.base64-encode/resource=index.php

````

This will return the Base64-encoded contents of the file. You can decode it locally to inspect the original PHP source.

> PHP filters **do not execute PHP code**. They are only for transforming file content. So you **cannot achieve RCE directly** using filters alone.

---

##  2. Using PHP Filters in LFI Exploitation

When there's a Local File Inclusion (LFI) vulnerability like this:

```php
<?php
include($_GET['page']);
?>
````

You can use `php://filter` to help escalate the attack.

---

###  1. Source Code Disclosure

```
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=config.php
```

This returns the contents of `config.php` (such as database credentials) in Base64 format, allowing you to decode and analyze it offline.

---

### 2. Preparing for RCE via File Write (Log Poisoning, Uploads, etc.)

If you have a secondary vulnerability that allows you to write files to disk (e.g., web server access logs or uploaded files), you can inject PHP code into that file and use LFI to include it — potentially achieving Remote Code Execution.

---

### 3. Bypassing WAFs or Input Filters

Some Web Application Firewalls (WAFs) or filters might block known sensitive keywords like `../../` or `passwd`. You can use encoding or filters to bypass those protections.

Example:

```

php://filter/read=convert.base64-encode|string.rot13/resource=index.php

```

---
