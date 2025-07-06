![image](https://github.com/user-attachments/assets/c78cc815-99fd-4989-8f75-73c03453ffb2)

### What is HTTP?

**HTTP (Hypertext Transfer Protocol)** is an **application layer protocol** designed specifically for communication between **web clients (browsers)** and **web servers**. It is the foundation of data exchange on the World Wide Web and is used for transmitting hypermedia documents such as HTML.

HTTP is **stateless**, meaning each request from the client to the server is independent and does not retain any memory of previous requests. This statelessness allows the protocol to be fast and efficient, but it also means that session management must be handled separately (e.g., using cookies or session IDs).

HTTP operates on top of the **TCP (Transmission Control Protocol)**, which ensures reliable delivery of packets between client and server.

![h](https://github.com/user-attachments/assets/e43f68e8-c694-467d-b4bb-c7282ea0ce5e)

---

### Client-Server Architecture

HTTP follows a simple **client-server model**:

* The **client** (usually a browser) initiates communication by sending a **request**.
* The **server** processes the request and sends back a **response**.

Each resource (HTML page, image, video, etc.) is uniquely identified using a **URL (Uniform Resource Locator)** or **URI (Uniform Resource Identifier)**.

---

### HTTP Versions

#### HTTP 1.0

* Introduced in 1996
* Opens a new TCP connection for each request
* Does **not support persistent connections**
* Limited functionality

#### HTTP 1.1

* Introduced enhancements over 1.0
* **Persistent Connections**: Reuses the same TCP connection for multiple requests/responses, reducing overhead
* **Pipelining**: Allows multiple requests to be sent without waiting for individual responses
* **Chunked Transfer Encoding**: Enables the transfer of dynamically generated content without knowing its length beforehand

> **Note**: HTTP/2 and HTTP/3 exist and offer major performance improvements, but HTTP/1.1 remains the most widely used version in many environments.

---

### HTTP Protocol Basics

The communication in HTTP is performed through **requests** and **responses**:

#### 1. HTTP Request

* Sent by the **client** to initiate communication
* Contains information such as:

  * HTTP method (GET, POST, etc.)
  * URL of the requested resource
  * Request headers
  * Optional body (e.g., form data in POST requests)

#### 2. HTTP Response

* Sent by the **server** back to the client
* Contains:

  * HTTP status code (e.g., 200 OK, 404 Not Found)
  * Response headers
  * Optional body (e.g., HTML content, JSON data)

---

### Visual Overview

```
Browser (Client)          <---- HTTP Request ----         Web Server
                          ---- HTTP Response --->
```

---

### Special Characters in HTTP

HTTP messages use special characters to denote the end of lines and headers:

| Character | Meaning                         |
| --------- | ------------------------------- |
| \r        | Carriage Return (start of line) |
| \n        | Line Feed (next line)           |
| \r\n      | End of header line / new line   |

**\r\n** is equivalent to pressing the **Enter** key. It's used to properly format HTTP headers so that the receiving server or client can correctly interpret the message.

---
