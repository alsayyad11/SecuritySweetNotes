#  Dark Project – Hidden PHP Source Disclosure 
> via `php://filter`

## 1. Initial Observation – View Page Source

When I first accessed the website, everything looked normal. It had standard links like **"About"**, **"Contact"**, and **"Projects"**. The UI was clean, and nothing seemed suspicious at first glance.

Out of habit, I inspected the **page source** (`Ctrl + U`) hoping to find something interesting — maybe hidden parameters, comments, or scripts — but **there was absolutely nothing unusual**. The HTML looked pretty standard.

However, what caught my attention was that **clicking the links didn’t actually change the page content**, even though the URL changed. That behavior was strange enough to make me dig deeper.

![alsayyad11 (Ahmed Elsayyad) - Google Chrome 5_8_2025 6_55_07 PM](https://github.com/user-attachments/assets/5aea38d0-2cc6-4f9c-a1de-f5e396754f44)

---

## 2. Digging Deeper – Inspecting the URL Parameters

While clicking through the navigation, I noticed the URLs looked like this:

```
http://wcamxwl32pue3e6m14nzyr6cn3kmm2360kxlcg30-web.cybertalentslabs.com/index.php?home=about
```

This seems like a typical pattern where the `home` parameter loads a corresponding page component (like "about" or "contact"). But when I replaced the `home` value with something more suspicious, like:

```

?home=php://filter/convert.base64-encode/resource=index

```

![alsayyad11 (Ahmed Elsayyad) - Google Chrome 5_8_2025 7_02_27 PM](https://github.com/user-attachments/assets/e827c6cf-1613-4a2b-b25e-a3c7a9510ed1)


...I was surprised by the response: **instead of a normal web page, I got a long Base64-encoded string**!

![Dark Project - Google Chrome 5_8_2025 7_04_36 PM](https://github.com/user-attachments/assets/1ddb66d8-cf55-45a5-b134-431fd9d6e80a)

![Dark Project - Google Chrome 5_8_2025 7_04_46 PM](https://github.com/user-attachments/assets/f5800ddf-0770-456c-91f0-db4d5a9f2609)

---

## 3. Understanding the Exploit – PHP Filters Abuse

### What is `php://filter`?

The `php://filter` stream wrapper allows you to apply filters to file streams in PHP. Here’s what the payload does:

```

php://filter/convert.base64-encode/resource=index

```

- `php://filter`: Tells PHP to treat the file as a filtered stream.
- `convert.base64-encode`: Applies a Base64 encoding filter.
- `resource=index`: Specifies the file to apply the filter on (`index.php`).

 **Result**: Instead of executing the `index.php` script normally, the server returns its raw source code **encoded in Base64**.

---

## 5. Conclusion – What Did We Learn?

This lab was a textbook case of **source code disclosure via PHP filters**. Let’s break it down:

| Element        | Description |
|----------------|-------------|
| **Vulnerability** | `php://filter` stream wrapper used without sanitization. |
| **Exploit**    | Replacing a `home=` parameter with a Base64-encoding filter that exposes raw PHP source. |
| **Impact**     | Full source code of backend logic can be extracted, including possible credentials, queries, file paths, etc. |
| **Mitigation** | Sanitize input strictly. Never allow raw file paths or streams to be passed via user-controlled GET parameters. |

---
