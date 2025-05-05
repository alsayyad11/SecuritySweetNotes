# 🔐 Web Security Tools – Burp Suite & OWASP ZAP

## 🔍 Burp Suite

### ✅ What is Burp Suite?
Burp Suite is a tool for testing the security of websites.  
It works like a **middleman** between your browser and the website.  
It helps you see, change, and test the data going to and from the website.

---

### ✅ What is it used for?
- Find security problems in websites.  
- Change requests and responses between browser and server.  
- Test things like **login forms**, **search boxes**, and **APIs**.  
- Try attacks like **SQL Injection** and **XSS**.

---

### ✅ Main Parts of Burp Suite:

#### 1. **Proxy**
Shows all traffic between your browser and the website.  
You can **intercept**, **view**, and **edit** requests and responses.

#### 2. **Repeater**
Lets you send the same request many times.  
You can change the request and test how the website responds.

#### 3. **Intruder**
Sends many requests quickly.  
Used for **Brute Force**, **Fuzzing**, and testing many inputs.

#### 4. **Scanner** *(Pro version only)*
Scans the website automatically for security issues.  
Shows you weak points and how to fix them.

#### 5. **Decoder**
Helps you **decode/encode** data like Base64 or URL encoding.

#### 6. **Comparer**
Compares two requests or responses to find differences.

#### 7. **Extender**
Add plugins (BApps) to improve Burp Suite features.

---

## 🛠️ OWASP ZAP

### ✅ What is OWASP ZAP?
ZAP is a free and open-source tool to test website security.  
It is made by OWASP and works like Burp Suite.  
It’s a great choice for beginners.

---

### ✅ What is it used for?
- Scan websites for problems.  
- Test web apps and APIs.  
- Intercept and modify requests/responses.  
- Use with CI/CD pipelines in DevOps.

---

### ✅ Main Parts of OWASP ZAP:

#### 1. **Intercepting Proxy**
See and change requests and responses.  
Works like Burp's Proxy.

#### 2. **Spider**
Finds all links and pages on the website.  
Helps to map the site.

#### 3. **Active Scanner**
Sends attacks to find weak points in forms, links, and inputs.

#### 4. **Passive Scanner**
Watches traffic without attacking.  
Finds issues in the background.

#### 5. **Fuzzer**
Sends many different inputs to test how the website handles them.

#### 6. **API Scanner**
Reads OpenAPI/Swagger files and tests API endpoints.

#### 7. **Alerts Panel**
Shows a list of all security issues found, with details and fix tips.

---
