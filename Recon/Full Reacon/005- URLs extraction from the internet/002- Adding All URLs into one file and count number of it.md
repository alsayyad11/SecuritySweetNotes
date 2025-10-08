## **1. Adding All URLs into a File Using `tee`**

When you run a command like `gau`, it prints all found URLs directly to the **terminal (stdout)**.
But you usually want to **save those URLs** for later — for filtering, scanning, or combining with other tools.

There are two common ways to save output:

1. Using **redirection (`>`)**
2. Using **`tee`**

### **Option 1 — Redirection (`>`)**

```bash
gau example.com > urls.txt
```

* This command saves **only** to the file `urls.txt`.
* You **won’t see** the URLs printed on your screen while the command runs.
* Everything is written silently into the file.

---

### **Option 2 — Using `tee`**

```bash
gau example.com | tee urls.txt
```

This is more flexible and often preferred.

#### **How it works:**

* `tee` takes the output from `gau`
* It **writes it to the terminal** **and** **saves it to a file** at the same time.

So:

* You can **see URLs** as they appear live in your terminal.
* You also **store them** inside `urls.txt` for later use.

#### **Example Output:**

```bash
https://example.com/
https://example.com/login
https://api.example.com/v1/users
https://cdn.example.com/js/main.js
```

All these lines are:

* Printed on your screen, and
* Saved inside `urls.txt`.

---

### **Pro Tip**

If you want to **append** (not overwrite) to a file each time you run it:

```bash
gau example.com | tee -a urls.txt
```

The `-a` flag means “append”.

---

## **2. Checking How Many URLs You Collected**

Once the URLs are saved in a file (like `urls.txt`), you can easily check how many lines — i.e., how many URLs — you have collected.

Use the command:

```bash
wc -l urls.txt
```

### **Explanation:**

* `wc` stands for **word count**
* `-l` means **count lines only**
* Each line in `urls.txt` represents **one URL**

So, if the output is:

```
5820 urls.txt
```

That means you collected **5,820 URLs** in total.

---

### **Example Full Workflow**

```bash
# Step 1: Run GAU and save + view output
gau example.com | tee urls.txt

# Step 2: Count how many URLs were collected
wc -l urls.txt
```

**Example output:**

```
5820 urls.txt
```

That means GAU found **5,820 URLs** related to `example.com`.

---

### **Optional — Filter Unique URLs**

Sometimes you’ll have duplicates.
You can clean and count only **unique URLs**:

```bash
cat urls.txt | sort -u | tee unique_urls.txt | wc -l
```

**Explanation:**

1. `cat urls.txt` → reads the file
2. `sort -u` → sorts and removes duplicate lines
3. `tee unique_urls.txt` → saves the clean output
4. `wc -l` → counts how many unique URLs remain

---

### **Example Output:**

```
5703
```

So out of 5,820 total URLs, **5,703 are unique** after removing duplicates.

---

## **In Summary**

| Step                  | Command            | Purpose                            |                                |                           |
| --------------------- | ------------------ | ---------------------------------- | ------------------------------ | ------------------------- |
| Save all URLs to file | `gau example.com   | tee urls.txt`                      | Collect and save while viewing |                           |
| Append new URLs later | `gau newtarget.com | tee -a urls.txt`                   | Add more URLs to same file     |                           |
| Count all URLs        | `wc -l urls.txt`   | Count total number of lines (URLs) |                                |                           |
| Count unique URLs     | `cat urls.txt      | sort -u                            | wc -l`                         | Count only unique results |

---

### **Example Use Case**

You’re doing recon on `porsche.com`:

```bash
gau porsche.com | tee urls.txt
wc -l urls.txt
```

Output:

```
[+] Collected 8,932 URLs
```
