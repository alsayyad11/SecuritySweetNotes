# Lab : Web shell upload via obfuscated file extension
[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension)

## Lab Description

This lab contains a vulnerable image upload function that tries to protect the server by blacklisting certain dangerous file extensions such as `.php`. However, this protection can be bypassed using **classic obfuscation techniques**, which allow attackers to disguise malicious files in ways that evade the blacklist.

For example, using techniques like **mixed case extensions** (e.g., `.pHp`), **double extensions** (e.g., `shell.php.jpg`), or **URL-encoded characters** (e.g., `shell%2Ephp`), attackers can trick the server into accepting and eventually executing a **PHP web shell** that appears harmless at first glance.

> **Hint**: The blacklist is not comprehensive and can be bypassed using a clever variation of the file extension.

Your goal in this lab is to:

- Upload a basic PHP web shell using an obfuscated or disguised filename.
- Access and execute the web shell to issue commands.
- Use the shell to read the contents of the file located at `/home/carlos/secret` on the server.
- Submit the secret using the submission button in the lab banner to complete the lab.

You can log in to your own account using the following credentials:  
- **Username:** `wiener`  
- **Password:** `peter`

---

## Solution 

- At first login with credentials `wiener` , `peter` .
- Then go to image upload functionality on **My Account** page .
  
   ![image](https://github.com/user-attachments/assets/8b1f6754-9862-4f3b-a986-23ac932fdca2)

- At previous labs we write a simple web shell in a file and named it `SimpleShell.php` that's content is :
  
```php
<?php
echo "<pre>";
echo file_get_contents("/home/carlos/secret");
echo "</pre>";
?>
```

it's role is to print content of `/home/carlos/secret` 

- Now upload this file using **Image upload** functionality.Observe we got an error :

  ![PM](https://github.com/user-attachments/assets/fd3fb4ce-f952-413e-9030-f8daf7c35fab)


To resolve this issue, we need to bypass the file extension validation by using an obfuscation technique involving a **null byte injection**.

### Technique

Upload your PHP shell file named `SimpleShell.php` with an obfuscated filename like:

- `SimpleShell.php%00.jpg`
- `SimpleShell.php%00.png`

This tricks the server into thinking it's an image file during the upload validation but may still treat it as a `.php` file at runtime due to how it interprets the null byte.

### Explanation

- `%00`: This represents a **null byte** in URL encoding. In certain programming languages or older server implementations (such as early versions of PHP), the null byte is treated as a **string terminator**. This means that everything **after** the null byte is **ignored** during execution.
- `.jpg` or `.png`: These extensions are appended after the null byte to **bypass file upload validation**. Many upload filters only allow files with these "safe" image extensions.


When you upload `SimpleShell.php%00.jpg`, the validation logic sees `.jpg` and allows it. However, if the server truncates the filename at `%00` when handling execution, it will run the file as `SimpleShell.php`.

This allows you to successfully upload and execute your PHP web shell despite extension filtering.

![p](https://github.com/user-attachments/assets/fcb348dd-3a78-4e93-823b-d026a013cbe1)

- In the browser reload the My Account page and in the burp suite under HTTP history find GET /files/avatars/SimpleShell.php%00.jpg request, observe its response we got the error 404 not found.

![tt](https://github.com/user-attachments/assets/fa50d2ae-2c2e-40eb-bcf0-028b51b8d892)

- Send this request to the Repeater tab and replace GET /files/avatars/SimpleShell.php%00.jpg with GET /files/avatars/SimpleShell.php and send the request. Observe we got user carlos secret.

![q](https://github.com/user-attachments/assets/e5bff59b-9629-4aca-91bc-87fbb6e7f3f9)

---

- ## Copy the secret and submit it in the browser to solve the lab successfully …

![i](https://github.com/user-attachments/assets/609080b2-c826-4175-8f79-1a4ba8e360f2)

![qa](https://github.com/user-attachments/assets/cce2cc5e-cf3f-432a-a231-4b3acb18aede)




