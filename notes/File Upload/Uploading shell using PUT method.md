![ii](https://github.com/user-attachments/assets/8cbba17d-484a-4106-b82a-8f01359bf5b0)

### What is the HTTP PUT Method?

In the HTTP protocol, **PUT** is a method used to upload or update a resource directly on the server. In other words, instead of uploading a file or data via a form using POST, you send the entire file as the request body along with the URL specifying where you want the file to be stored on the server.

* For example, if you want to upload an image named `photo.jpg` to the `/uploads/` directory, you send a PUT request to `/uploads/photo.jpg` with the image content.
* The server, upon receiving the request, stores the content directly at that path on disk.

---

### Difference Between PUT and POST for File Uploads

* **POST** is usually used to upload files or data through forms on web pages, and the server may process or store the data in a specific location.
* **PUT** stores the file or resource directly at the path specified in the request URL, meaning you control the filename and location on the server.

---

### Why is HTTP PUT Dangerous for File Upload?

* Some servers have PUT enabled without proper security controls.
* This allows anyone to upload malicious files (like web shells or PHP scripts) into writable directories.
* Once the file is uploaded, the attacker can access it via a browser and execute commands in the file, which can lead to a full server compromise.

---

### How Does an Attacker Upload Files Using PUT Without a File Upload Form?

* The attacker does not need a web page or form.
* They use external tools like `curl`, Postman, or custom scripts to send a direct PUT request to the server.
* This request contains the file path in the URL and the file content in the request body.
* If the server supports PUT and accepts the request, it saves the file at the specified path.

---

### Practical Example of a PUT Request to Upload a Malicious PHP File

```http
PUT /images/exploit.php HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-httpd-php
Content-Length: 49

<?php echo file_get_contents('/path/to/file'); ?>
```

* Here, the attacker uploads a PHP file named `exploit.php` to the `/images` directory.
* The file contains PHP code that reads the content of another file on the server.
* If the server is not secured properly, this code runs when the file is accessed, enabling remote code execution.

---

### How to Check if a Server Supports HTTP PUT?

* Send an **OPTIONS** request to various server paths.
* The server responds with the allowed HTTP methods (e.g., GET, POST, PUT, DELETE, etc.).
* If the response shows that PUT is allowed on certain paths, it could be a security risk.

---

### How to Send an OPTIONS Request to Test for PUT Support?

#### 1. Using curl in Terminal

```bash
curl -X OPTIONS https://httpbin.org/get -i
```

* This sends an HTTP OPTIONS request to the specified URL.
* The `-i` flag includes headers in the output.
* The response will contain an `Allow` header showing supported methods, e.g., `Allow: HEAD, GET, OPTIONS`.

---

#### 2. Using JavaScript in Browser Console

```js
fetch('https://httpbin.org/get', { method: 'OPTIONS' })
  .then(response => {
    console.log('Allowed Methods:', response.headers.get('allow'));
    return response.text();
  })
  .then(text => console.log(text))
  .catch(err => console.error(err));
```

* This code sends an OPTIONS request and logs the allowed methods to the console.

---

#### 3. Using Postman

* Open Postman.
* Select `OPTIONS` from the request method dropdown.
* Enter `https://httpbin.org/get` as the request URL.
* Click Send.
* The response headers will include `Allow` showing permitted HTTP methods.

---

### How to Secure Your Server Against PUT Exploitation?

* Enable PUT only when absolutely necessary.
* Disable PUT in public or web file hosting directories.
* Set server permissions to prevent unauthorized file creation or modification.
* Use Web Application Firewalls (WAF) or server settings to block or log suspicious PUT requests.
* Verify uploaded files to ensure no executable or malicious scripts exist.

---

