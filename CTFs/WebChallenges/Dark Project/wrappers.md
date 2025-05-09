## What Are Wrappers?
- **Wrappers** are a programming concept used to allow access to different types of data sources or functionalities in a uniform way.
- They act as an interface between your application and a resource (like files, network services, etc.), enabling you to interact with these resources using standard functions or methods.

In PHP, a **stream wrapper** allows access to **different kinds of data** (such as files, remote URLs, or raw input) using **stream functions** like `fopen()`, `fread()`, `file_get_contents()`, `include()`, etc. Wrappers define **how the data is accessed** or **what resource to access**.

---

## Common Types of Wrappers :

* **File Wrappers**: Handle interaction with regular files or directories.
* **Network Wrappers**: Handle communication with remote servers (e.g., HTTP, FTP).
* **Memory Wrappers**: Deal with in-memory data storage.
* **Custom Wrappers**: Specific interfaces for other types of resources or services.

---

## PHP Wrappers

In PHP, stream wrappers define the protocol or method of accessing a resource. Below are the most commonly used stream wrappers:

| Wrapper        | Description                                                        | Example in PHP                                                     |
| -------------- | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `file://`      | Access local files (this is the default wrapper)                   | `fopen("file.txt", "r");`                                          |
| `http://`      | Read content from a remote HTTP URL                                | `file_get_contents("http://example.com");`                         |
| `ftp://`       | Access files over FTP                                              | `fopen("ftp://example.com/file.txt", "r");`                        |
| `php://input`  | Access raw POST data (like JSON or XML)                            | `file_get_contents("php://input");`                                |
| `php://memory` | Read/write temporary data stored in memory                         | `fopen("php://memory", "w+");`                                     |
| `php://temp`   | Temporary storage, switches to a file if data exceeds memory limit | `fopen("php://temp", "r+");`                                       |
| `php://filter` | Apply filters (e.g., encoding, compression) to file or stream      | `include("php://filter/convert.base64-encode/resource=file.txt");` |

---

### PHP Wrapper Syntax

The general syntax for using a stream wrapper in PHP is:

```php
wrapper://resource
```

For example:

```php
$file = fopen("http://example.com/file.txt", "r"); // Using the http:// wrapper to fetch a remote file
$content = file_get_contents("php://input"); // Reading raw POST data
```

---

## `php://filter` Stream Wrapper

This is a special wrapper in PHP that applies **filters** to a file or stream before reading or writing. It's often used in security contexts to manipulate data or inspect the contents of files without executing them. For example:

```php
php://filter/read=convert.base64-encode/resource=somefile.php
```

This will **Base64 encode** the contents of `somefile.php` instead of executing it as PHP code.

---

## Wrappers vs. Filters

| Feature  | Wrapper                                        | Filter                                               |
| -------- | ---------------------------------------------- | ---------------------------------------------------- |
| Purpose  | Defines **where** the data comes from (source) | Defines **how** the data is transformed or processed |
| Examples | `file://`, `http://`, `ftp://`                 | `convert.base64-encode`, `string.toupper`            |
| Used In  | `fopen()`, `file_get_contents()`, `include()`  | `php://filter` wrapper                               |

---
