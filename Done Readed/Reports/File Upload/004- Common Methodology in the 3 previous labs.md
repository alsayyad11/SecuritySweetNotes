
This methodology applies to all cases where file upload features can be abused to trigger **Stored XSS** using SVG, HTML, or script-containing payloads.

---

## 1. Identify Upload Functionality

Look for any upload feature in the target app, such as:

* Profile picture upload
* Contact image upload
* Wiki page attachments
* File repository uploads
* Document upload fields
* Any other "Choose File" / "Upload" buttons

---

## 2. Prepare and Upload Malicious Payload

Use an SVG file containing embedded JavaScript. Example payload:

```xml
<svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg">
  <polygon points="0,0 0,50 50,0" />
</svg>
```

Alternatively, for HTML payloads:

```html
<script>alert(1)</script>
```

Upload it with:

* Real `.svg` extension
* Faked `.png`, `.jpg`, `.jpeg` extension (for bypass)

---

## 3. Bypass Extension & MIME Type Filters

Try various evasion techniques:

* Rename `.svg` file to `.png`, `.jpg`, or `.jpeg`
* Use **multi-extension filenames** like:

  * `xss.jpg.svg`
  * `xss.png.html`
* Modify the **Content-Type header** via Burp Suite to:

  * `image/png`
  * `image/svg+xml`
  * `text/html`
* Test **null byte injection** (if server is vulnerable):

  * `xss.jpg%00.svg`

---

## 4. Observe File Behavior

After uploading:

* Is the file accessible from a public or raw URL?
* Does it appear inside any rendered UI (wiki, profile, etc.)?
* Is it rendered inline in the page (not downloaded)?
* Does clicking the image trigger any script execution?

---

## 5. Trigger the Payload

Try:

* Opening the uploaded file directly in the browser
* Viewing the page where it’s embedded (e.g., a wiki or contact profile)
* Clicking interactive SVG elements (like polygons or groups) to trigger events

---

## 6. Analyze HTTP Response Headers

Use browser DevTools or Burp to check:

* `Content-Type`: Is it `image/svg+xml` or `text/html`?
* `Content-Disposition`: Is it missing or set to `inline`?
* CSP Headers: Are they strict enough to block inline scripts?

---

## 7. Try Extended Variants

Explore additional bypass vectors:

| Variant                   | Description                                                      |
| ------------------------- | ---------------------------------------------------------------- |
| **SVG disguised as PNG**  | SVG payload uploaded with `.png` extension                       |
| **Multi-extension files** | Upload files like `xss.jpg.svg`, `xss.png.html`, etc.            |
| **Raw endpoint access**   | Open file via `/raw/` or `/uploads/` if exposed                  |
| **MIME spoofing**         | Send misleading Content-Type headers                             |
| **Polyglot files**        | Upload hybrid files that are both valid images and valid HTML/JS |
| **Null byte injection**   | Filenames like `xss.jpg%00.svg` if null bytes are mishandled     |

---

## 🛠 Tools Commonly Used

| Tool                      | Purpose                                  |
| ------------------------- | ---------------------------------------- |
| **Burp Suite**            | Intercept and modify upload requests     |
| **DevTools**              | Inspect headers, rendering behavior, CSP |
| **ImageMagick** or `file` | Verify actual MIME/content type          |

---
