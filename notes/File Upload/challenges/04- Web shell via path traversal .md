# Lab : Web shell upload via path traversal 
[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal)


## Lab Description

This lab contains a vulnerable image upload function that is supposed to allow users to upload image files safely. The server is configured to prevent execution of any user-supplied files to avoid malicious code execution. However, this security measure can be bypassed by exploiting a [**secondary vulnerability**] known as **Path Traversal**.

The Path Traversal vulnerability allows an attacker to manipulate the file path when uploading a file, enabling them to place files outside the designated upload directory. This means an attacker can upload a PHP web shell to a directory where the server will execute it, despite the original security restrictions.

Your goal in this lab is to :

- Upload a simple PHP web shell disguised as an allowed image file.
- Exploit the Path Traversal vulnerability to save the web shell in a directory that allows PHP execution.
- Use the web shell to read the contents of the file located at `/home/carlos/secret` on the server.
- Extract and submit this secret using the submission button in the lab banner to complete the lab.

You can log in to your own account using the following credentials:  
- **Username:** `wiener`  
- **Password:** `peter`

---

## Solution 

- At first I will login with credentials ( `wiener` , `peter` ) .
- Go to **Image upload** functionality in **My Account** page.
  
  ![image](https://github.com/user-attachments/assets/d4334f56-b363-438e-a692-21cbda6a13e0)

- At previous labs we write a simple web shell in a file and named it `SimpleShell.php` that's content is :
  
```php
<?php
echo "<pre>";
echo file_get_contents("/home/carlos/secret");
echo "</pre>";
?>
```

it's role is to print content of `/home/carlos/secret` 

- Now upload this file using **Image upload** functionality. Observe we successfully uploaded the file.

![x](https://github.com/user-attachments/assets/df84a5d2-d63a-4e7b-861d-10e78cee7320)

- The path where user-uploaded files are stored has strict restrictions that prevent the execution of any files uploaded by end users.
- This means that even if we upload a PHP web shell there, the server will not run it as executable code.
- Therefore, to successfully execute our web shell, we need to bypass this limitation by uploading the file to a different directory on the server. 
- This other directory does not have the same execution restrictions, allowing the server to run PHP scripts placed there. Exploiting this misconfiguration or vulnerability (such as a Path Traversal flaw) lets us save our malicious file outside the protected upload folder.

=====

Move back to Burp Suite and navigate to the **HTTP history** tab. Locate the **POST /my-account/avatar** request, which is responsible for uploading the avatar image.

Send this request to the **Repeater** tab to modify it. In the request body, find the `filename` parameter for the uploaded file. Change its value from `filename="your-filename.php"` to `filename="../your-filename.php"` by adding the `../` path traversal sequence.

Send the modified request and observe the response. Although we attempted to upload the file outside the default directory, the file is still saved to the original location `/files/avatar/your-filename.php`.

- Before changing file path `SimpleShell.php`:

    ![z](https://github.com/user-attachments/assets/a546d08b-5cc6-4700-99c5-98d0513b7689)

- After changing file path to `../SimpleShell.php` :
  
    ![a](https://github.com/user-attachments/assets/b09c1076-fcd1-4cdc-b751-2471c3cd9ac5)
  
> To resolve this issue we need to encode “/” (slash) in our filename parameter value using URL encoding in the Decoder tab.

```
- when it plain text ( / )
- after URL Encoding it converted to be ( %2f ) 
```

- after we changed the slash to URL encoding , we will change file name from `../SimpleShell.php` to `..%2fSimpleShell.php` .

   ![s](https://github.com/user-attachments/assets/915425c4-08e6-49af-90ea-6f6d4ba4c869)

> GG now uploaded to one directory back successfully.

- Now I will Reload  My Account page to observed in the burp suite under HTTP history GET /files/avatar/..2fSimpleShell.php request.
- Send it to **Repeater** , you will got `404 Not found` error in response of `GET files/avatar/..2fSimpleShell.php` request.
- That error happend bacause our file is uploaded at this path `files/SimpleShell.php` Not at this path `files/avatar/..2fSimpleShell.php`

. this path `files/avatar/..2fSimpleShell.php`

![d](https://github.com/user-attachments/assets/ee851564-2ae8-4849-8000-0b95392726f7)

. this path `files/SimpleShell.php`

![f](https://github.com/user-attachments/assets/47a49612-6043-4258-a814-af13b292c3d5)

---
## 🎉 We ge the secret , Now copy it and submit it in the browser to solve the lab .

![g](https://github.com/user-attachments/assets/0f6c35a4-ad57-432a-8add-e4cdba986082)

![h](https://github.com/user-attachments/assets/6b90d558-e309-4302-ba6a-451aedf15323)
