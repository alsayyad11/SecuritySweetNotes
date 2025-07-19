##  What is `XMLHttpRequest`?

`XMLHttpRequest` is a built-in JavaScript object that allows a web page to send and receive data from a server **asynchronously** — meaning it doesn’t require the page to reload.

It’s mainly used for:

* Fetching data from a server (e.g., HTML, JSON, XML, text)
* Sending data to a server (e.g., form submissions via POST)
* Creating dynamic web content (AJAX)

Despite the name, it is **not limited to XML**.

---

##  Basic Syntax

```javascript
let xhr = new XMLHttpRequest();
xhr.open(method, url);
xhr.onload = function() {
  // Handle response here
};
xhr.send();
```

---

##  Key Methods

| Method                            | Description                                                    |
| --------------------------------- | -------------------------------------------------------------- |
| `open(method, url)`               | Initializes a new request. `method` can be GET, POST, etc.     |
| `send(body)`                      | Sends the request. If `POST`, you can pass data in `body`.     |
| `setRequestHeader(header, value)` | Sets custom HTTP headers (after `open()` and before `send()`). |
| `abort()`                         | Cancels the request.                                           |

---

##  Key Properties

| Property       | Description                                                     |
| -------------- | --------------------------------------------------------------- |
| `responseText` | The plain text response from the server.                        |
| `responseXML`  | If the server returns XML, this contains a parsed XML document. |
| `status`       | HTTP status code (e.g., 200, 404, 500).                         |
| `readyState`   | Request state (0 to 4).                                         |
| `onload`       | Function called when request is successfully completed.         |
| `onerror`      | Function called if there's an error in the request.             |

---

##  readyState Values

| Value | Meaning                                       |
| ----- | --------------------------------------------- |
| 0     | UNSENT – Request not initialized              |
| 1     | OPENED – `open()` has been called             |
| 2     | HEADERS\_RECEIVED – Response headers received |
| 3     | LOADING – Response is being downloaded        |
| 4     | DONE – Request finished and response is ready |

---

##  Example 1 – GET Request

```javascript
let xhr = new XMLHttpRequest();
xhr.open("GET", "https://jsonplaceholder.typicode.com/posts/1");

xhr.onload = function() {
  if (xhr.status === 200) {
    console.log("Response:", xhr.responseText);
  } else {
    console.error("Error:", xhr.status);
  }
};

xhr.onerror = function() {
  console.error("Request failed.");
};

xhr.send();
```

---

##  Example 2 – POST Request with JSON

```javascript
let xhr = new XMLHttpRequest();
xhr.open("POST", "https://jsonplaceholder.typicode.com/posts");

xhr.setRequestHeader("Content-Type", "application/json");

xhr.onload = function() {
  console.log("Response:", xhr.responseText);
};

let data = JSON.stringify({
  title: "Hello",
  body: "This is a test",
  userId: 1
});

xhr.send(data);
```

---

##  Common Use Cases

* Fetch data without reloading the page (AJAX)
* Submit forms asynchronously
* Build APIs and Single Page Applications
* Background data syncing (like auto-saving drafts)

---

##  Security Notes

* `XMLHttpRequest` follows **Same-Origin Policy**:

  * You can't send or read requests to other domains unless the server explicitly allows it using **CORS** headers.
* It can be used maliciously in **XSS** payloads to steal data.
* Always sanitize inputs and restrict which files/resources can be accessed from client-side JS.

---

##  Comparison with `fetch()`

| Feature        | `XMLHttpRequest`          | `fetch()`                 |
| -------------- | ------------------------- | ------------------------- |
| Syntax         | Verbose                   | Cleaner and promise-based |
| Streaming      | No                        | Yes (ReadableStreams)     |
| Support        | Older browsers            | Newer browsers only       |
| Error handling | via events like `onerror` | via `.catch()`            |

> In modern apps, `fetch()` is preferred due to its simplicity and modern API, but `XMLHttpRequest` is still important for legacy support and understanding how AJAX works.

---

##  Summary

* `XMLHttpRequest` is a core part of modern web development.
* Enables communication with the server **without reloading the page**.
* Useful in building dynamic, fast, and responsive web apps.
* However, modern developers are encouraged to use `fetch()` or libraries like `Axios` for better readability and control.

---
