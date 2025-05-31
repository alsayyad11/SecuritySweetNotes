# Lab : Remote code execution via polyglot web shell upload
[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload)

## Lab Description

This lab contains a vulnerable image upload function. Although the server attempts to verify the contents of the uploaded file to ensure it is a genuine image, this validation is insufficient. As a result, it is still possible to upload and execute server-side code.

To solve the lab, you need to:

- Upload a basic PHP web shell disguised as an image file.
- Use the web shell to read the contents of the file located at `/home/carlos/secret`.
- Submit the extracted secret using the submission button in the lab banner.

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

- Now upload this file using **Image upload** functionality.Observe we got an error :
  
![par](https://github.com/user-attachments/assets/c6700781-f1f7-499b-a895-f18096cf31ad)


> The server does not rely on checking the file extension or the `Content-Type` header for validation. Instead, it verifies the actual content of the file by inspecting the **magic bytes** (a unique signature at the beginning of files). In this lab, the upload function only accepts JPG files, and it specifically checks that the image metadata contains the correct magic bytes corresponding to a valid JPG image.


 - JPG magic bytes :
   
 ![Ne](https://github.com/user-attachments/assets/d015e1d9-3c7c-4969-8c9a-e4d0c08a051f)
أكيد، هكتبه لك بشكل مفصل وعلمي بالإنجليزي مع توضيح الخطوات:

````md
To execute our PHP web shell embedded within an image file, the following detailed steps were taken using Burp Suite's Repeater tool:

1. **Embedding PHP code in the image content:**  
   Instead of uploading a standalone PHP file, the PHP shell code was injected directly into the content/body of an image upload request. The code used is:

   ```php
   <?php
   echo "<pre>";
   echo file_get_contents("/home/carlos/secret");
   echo "</pre>";
   ?>
````

This code, when executed, will read the contents of the `/home/carlos/secret` file on the server and display it in a formatted manner.

2. **Modifying the filename:**
   The original filename in the upload request was changed from `image.jpg` to `image.php`. This step attempts to trick the server into treating the uploaded file as a PHP script rather than a regular image.

3. **Changing the Content-Type header:**
   The HTTP request header `Content-Type` was modified from a typical image MIME type (e.g., `image/jpeg`) to `application/x-php`. This informs the server that the content being uploaded should be interpreted as PHP code.

4. **Sending the modified request:**
   After these modifications, the request was sent to the server. The server accepted the file and executed the embedded PHP code, successfully returning the contents of the target file `/home/carlos/secret`.

![zz](https://github.com/user-attachments/assets/fe2cd8f6-69c2-4c90-b414-4a06158064e5)

- In the browser reload the My Account page and in the burp suite under HTTP history find GET /files/avatars/image.php  request , then send it to Repeater and send it as request.

- ooooooooooh , shell executed successfuly in it and I got the secret.

  ![PM](https://github.com/user-attachments/assets/b23d157e-402e-4c8c-8f0c-1d79db4a937c)

---

- ## Copy the secret and submit it in the browser to solve the lab successfully …

![oo](https://github.com/user-attachments/assets/bc08e601-2290-47c4-92f8-93f723e72ac0)


  ![pa](https://github.com/user-attachments/assets/e05d5e93-747e-45ec-9d7e-07e01c75d1d8)


  

