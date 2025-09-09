

## 1. What is Data Encoding?

**Encoding** means converting data from one form into another format so that it can be stored, transmitted, and understood consistently by computers and humans.

* Computers only understand **binary (0s and 1s)**.
* Humans use **letters, numbers, and symbols**.
* Encoding is the bridge that maps human-readable text into machine-readable binary.

**Example:**

* The letter **A** → in ASCII = `65` (decimal) → in binary = `01000001`.
* When you type “A” into a browser, it is encoded and sent as `01000001`, which the server later decodes back to “A”.

**Why it matters on the web:**

* Text, images, files, multimedia all need encoding to be reliably sent across the internet.
* Without encoding, systems could misinterpret data (e.g., show “????” instead of Arabic characters).

---

## 2. Importance of Encoding in Security Testing

For penetration testers, encoding is not only about representation — it’s also about **manipulation**.

* Attackers/testers often encode malicious payloads to **bypass filters** or trick applications.
* By testing how an application handles different encodings, you can discover vulnerabilities.

**Example in SQL Injection:**

```sql
-- Normal payload
' OR 1=1 --

-- Encoded payload (%27 = ')
%27%20OR%201%3D1%20--
```

Both payloads are the same, but one is URL-encoded to bypass weak filters.

**Example in XSS:**

```html
<script>alert(1)</script>
```

can be encoded as:

```html
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

---

## 3. Character Sets (Charsets)

A **charset** defines the collection of symbols and how they map to numbers (code points).

* Every character = unique numeric value.
* Helps computers store, process, and render text properly.

**Examples of charsets:**

* **ASCII** (basic English letters, digits, punctuation).
* **Latin-1 (ISO-8859-1)** (Western European languages).
* **Unicode** (all languages, symbols, emojis).

**Analogy:** Think of a charset like a **dictionary**:

* Word → Meaning.
* Character → Numeric code.

---

## 4. ASCII (American Standard Code for Information Interchange)

* Developed in the 1960s.
* Represents **128 characters** using 7 bits (0–127).
* Covers:

  * Uppercase A–Z (65–90).
  * Lowercase a–z (97–122).
  * Digits 0–9 (48–57).
  * Punctuation (!, @, #, etc.).
  * Control characters (newline, tab, etc.).

**Limitations:**

* Only supports English.
* Cannot represent Arabic, Chinese, emojis, etc.

**Example:**

* `A` = 65.
* `a` = 97.
* `0` = 48.

<img width="1200" height="401" alt="S" src="https://github.com/user-attachments/assets/d0714b61-8ea2-4af1-9d92-9c21e59ae771" />

You can see the full mapping at: [ASCII Table](https://www.ascii-code.com/)

---

## 5. Unicode — The Modern Standard

ASCII was too limited, so **Unicode** was created.

* Covers **all writing systems** (Arabic, Chinese, Hindi, etc.), plus emojis and symbols.
* Each character has a **code point** (e.g., “😀” = `U+1F600`).
* Allows true internationalization.

**Encoding schemes inside Unicode (called UTF):**

* **UTF-8**
* **UTF-16**
* **UTF-32**

---

## 6. Character Encoding Schemes

### 6.1 UTF-8

* Uses **8-bit units (1 byte)**.
* Variable length:

  * ASCII characters → 1 byte.
  * Other characters → 2–4 bytes.
* **Backward compatible with ASCII.**
* **Most common encoding on the web today.**

**Example:**

* `A` → `01000001` (1 byte).
* `é` → `11000011 10101001` (2 bytes).
* `😀` → requires 4 bytes.

---

### 6.2 UTF-16

* Uses **16-bit units (2 bytes)**.
* Characters in Basic Multilingual Plane (BMP) → 2 bytes.
* Others (like emojis) → 4 bytes (surrogate pairs).
* Common in **Windows** and **Java** systems.

**Example:**

* `A` → `00000000 01000001` (2 bytes).
* `😀` → `11011000 00111111 11011100 00000000` (4 bytes).

---

### 6.3 UTF-32

* Fixed length = **4 bytes per character**.
* Simplifies processing but wastes space.
* Rarely used in web, but useful in internal systems.

---

## 7. Why Encoding Matters in Attacks

Encoding often interacts with **input validation** and can open doors to bypasses.

### 7.1 URL Encoding (Percent Encoding)

* Converts unsafe characters into `%` followed by hex.
* Example:

  * Space → `%20`
  * `<` → `%3C`
  * `'` → `%27`

**Attack scenario:**
WAF blocks `<script>`, but `%3Cscript%3E` might slip through.

---

### 7.2 HTML Entity Encoding

* Uses `&entity;` format.
* `<` → `&lt;`
* `>` → `&gt;`
* `&` → `&amp;`

**Attack scenario:**
An app that only decodes once may let double-encoded payloads through:

```html
&lt;script&gt;alert(1)&lt;/script&gt;
```

Decoded once → `<script>alert(1)</script>`.

---

### 7.3 Base64 Encoding

* Represents binary data as ASCII text.
* Common in cookies, JWT tokens, and data URLs.
* **Not encryption**, just representation.

**Example:**

* `hello` → `aGVsbG8=`

**Attack scenario:**
Sensitive tokens in cookies are base64 encoded:

```text
eyJ1c2VyIjoiYWRtaW4ifQ==
```

Decoded → `{"user":"admin"}`

---

### 7.4 Double Encoding

* Encoding data multiple times to bypass filters.
* `'` → `%27` → `%2527`

**Attack scenario:**
If the server decodes twice, `%2527` → `%27` → `'`.

---

## 8. Encoding in Penetration Testing

Security testers check:

1. How the app encodes/decodes user input.
2. Whether filters apply before or after decoding.
3. If multiple encodings cause bypass.

**Practical Example — SQL Injection:**

```sql
-- Blocked payload:
' OR 1=1 --

-- Encoded payload:
%27%20OR%201%3D1%20--
```

**Practical Example — XSS:**

```html
<script>alert(1)</script>
```

Encoded as:

```html
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```

---

## 9. Main Points

* **Encoding** is about safe data transmission and storage.
* **Charsets** define what characters exist (ASCII, Unicode).
* **Encoding schemes** define how they’re stored (UTF-8, UTF-16, UTF-32).
* **Pen testers** exploit encoding to bypass filters in attacks like XSS, SQLi, RCE.
* Always test with **different encodings** to see how the app reacts.

