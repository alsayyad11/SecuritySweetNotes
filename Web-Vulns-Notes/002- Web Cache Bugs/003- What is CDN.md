### What is a CDN?

**CDN** stands for **Content Delivery Network**.

A **CDN** is a network of servers distributed across different locations around the world. The main purpose of a CDN is to deliver **web content** (like HTML pages, images, videos, CSS, JavaScript files) **faster and more reliably** to users, no matter where they are located.

Instead of every user requesting data directly from the **origin server** (your main web server), the CDN caches a copy of your content on its servers. When a user requests your website, the CDN delivers the content from the server **closest to them**, which reduces latency and speeds up loading time.

---

### How does a CDN work?

1. **Caching content:**

   * The CDN caches static files like images, CSS, JS, and sometimes even HTML pages.
   * When a user requests a page, the CDN checks if it has a cached copy.

     * If **yes** → it serves it directly (**cache HIT**)
     * If **no** → it fetches the content from the origin server, caches it, then serves it (**cache MISS**)

2. **Geographical distribution:**

   * CDNs have multiple servers (called **edge servers**) in different cities or countries.
   * Users are automatically served content from the **nearest edge server**, which reduces loading times and server load.

3. **Security benefits:**

   * CDNs can also protect your server from **DDoS attacks** because the traffic is distributed across many servers.
   * Some CDNs include **WAF (Web Application Firewall)** features that filter malicious requests before they reach your server.

---

### Example:

Imagine your website’s origin server is in **New York**, but a user in **Cairo** wants to visit your site:

* Without CDN → User request goes all the way to New York → longer loading time
* With CDN → User request goes to the **closest edge server in Cairo** → faster response

---

* **Edge server:** A CDN server located close to end users.
* **Origin server:** Your main web server where the original content is hosted.
* **Cache HIT:** The requested content is found in the CDN cache and served directly.
* **Cache MISS:** The content is not in the cache, so the CDN fetches it from the origin server.

---

So basically, a CDN is like a **global network of “mini-servers”** that hold copies of your website content, making your site faster, more reliable, and safer.

---
