
<p align="center">
  <img src="https://github.com/user-attachments/assets/beaabdff-7c5e-43cc-b8df-27427eb1160a" alt="image" width="500" />
</p>

- `robots.txt` : is a plain text file placed in the **root directory** of a website to instruct **web crawlers** (like Googlebot, Bingbot, etc.) on which paths they are allowed or disallowed from crawling.

### Default path:
```

[https://example.com/robots.txt](https://example.com/robots.txt)

````

A `robots.txt` file consists of one or more sets of directives targeted at specific or all crawlers.

| Directive     | Description                                              |
|---------------|----------------------------------------------------------|
| `User-agent`  | The name of the bot (e.g., `Googlebot`, or `*` for all)  |
| `Disallow`    | Paths that should not be crawled                         |
| `Allow`       | Exceptions to `Disallow` (used mainly by Googlebot)      |
| `Sitemap`     | Points to the site's XML sitemap                         |


### 🧾 Example:

![image](https://github.com/user-attachments/assets/3382b890-8ba4-4749-82e4-ca23400cfe41)

---

### why we use it ?? 

*  Prevents indexing of low-value pages (e.g., `/cart`, `/checkout`)
*  Helps avoid duplicate content
*  Optimizes crawl budget for large websites

> Misconfigurations can block important content or expose sensitive URLs!

---

## It's Risks

Although `robots.txt` is **not a security mechanism**, developers often mistakenly list **sensitive directories**, like:

```txt
Disallow: /backup/
Disallow: /secret/
Disallow: /admin-panel/
```

> Attacker can easily read the file and manually visit these hidden paths!

---


## PoCs

###  `robots.txt` Content:

```txt
User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /hidden-login/
```

###  Exploitation:

* Visited: `https://victim.com/admin/` → Admin dashboard appeared
* Visited: `https://victim.com/backup/` → Found `db.sql` backup
* Visited: `https://victim.com/hidden-login/` → Secret login page not linked elsewhere

---

لو حابب أحوله كمان لملف `.md` جاهز أو PDF، قولي وابعتهولك فورًا.
```
