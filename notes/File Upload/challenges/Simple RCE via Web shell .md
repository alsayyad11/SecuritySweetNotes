# Lab : Remote code execution via web shell upload  
[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload)

---

##  Lab Description 

1. **This lab contains a vulnerable image upload function.**  
   - The “avatar” upload form accepts any file without checking its type or contents.  
   - Even though it’s labeled for images, the server writes your upload straight to disk.

2. **It doesn’t perform any validation on the files users upload before storing them on the server’s filesystem.**  
   - No file-extension whitelist: you can submit `shell.php` instead of `avatar.jpg`.  
   - No MIME-type or magic-byte check: the server never inspects the file header.  
   - No content scanning: PHP tags (`<?php ... ?>`) or other code aren’t blocked.

3. **To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`.**  
   - **Basic PHP web shell** = a few lines of PHP that read and print that secret file.  
   - Once uploaded, visiting your shell’s URL causes the server to execute your code and return the secret.

4. **Submit this secret using the button provided in the lab banner.**  
   - After you retrieve the text, look for the lab’s banner at the top of the page.  
   - Paste the secret into the input box and click **Submit** to mark the lab solved.

5. **You can log in to your own account using the following credentials: `wiener:peter`**  
   - **Username:** `wiener`  
   - **Password:** `peter`  
   - Use these to sign in, then navigate to **My account → Avatar** to reach the upload form.

![parrot](https://github.com/user-attachments/assets/23b179da-4b8e-4f93-a854-b0d9b04e2420)

---
---
---
> Any upload file feild must check the file extension & file type & file content 
---
---
---

## Solution 

- after login using the following credentials: `wiener:peter`
- I found an upload image functionality to display the avatar.
  
![parro](https://github.com/user-attachments/assets/8ab02cc2-a418-4815-a7b0-f603283ba31f)

- Now upload any image :

  ![parr](https://github.com/user-attachments/assets/69697997-28c6-4c4d-9336-c57634145742)

![par](https://github.com/user-attachments/assets/0e45e5a1-ba33-4862-9151-baae0e16e00f)

- After going back to the homepage we see the avatar has been updated as shown in the screenshot below.

  ![pa](https://github.com/user-attachments/assets/1763bffa-5599-431d-9033-a7b11e21f752)

  > This means the file uploaded onto the server has been executed and since the file type was an image thus the server simply returns the contents of the file as response to the user and displays the avatar on the user page.


- Now check burp suite for the requests captured.

  ![p](https://github.com/user-attachments/assets/36ab9ce9-c185-4c1c-afbc-3dd3557002a1)
  
- See it in Repeater :
  
  ![pp](https://github.com/user-attachments/assets/2b9f67ef-4d21-4d7c-a0b0-5fa30444e73a)

- Let's create a web shell using PHP and change the name of the file to “SimpleShell.php” or anything else but with “.php” extension.
- Further remove the image file content since now image is not being uploaded onto the server. Now send this request and analyse the response.
  
  ![t](https://github.com/user-attachments/assets/c0b1d821-a86f-4d47-a9ef-e7951eafc147)

- Like you see in the response above the web shell has been uploaded onto the web server successfully. This finally gives us access to the server.
- Now we simply execute the command by changing the name of the file in the GET method from the image file to the exploit file.
- This makes the server to visit the mentioned location where the exploit file is stored and execute it.
- Since the server does not perform any validation on the file being uploaded and that it is also configured to execute the “.php” files not checking the contents of the file before executing.
- The server executes the file and tries to read the file mentioned in the web shell.

  ![gg](https://github.com/user-attachments/assets/c7e998be-2100-4b8c-849d-36d164098512)

- Finally we did it and now I will go to the path which he asked me to give him it's content ( I will do that be edit the web shell content from "Hello Hunter" to "/home/carlos/secret" and Resend it and open SimpleShell.php and I will found the needed target their .

 ![ee](https://github.com/user-attachments/assets/87946233-9f60-45b8-afa6-4ab8cef60f55)
 
 ![ttt](https://github.com/user-attachments/assets/49e9973e-7337-44fe-b3e2-146bffcaf822)

- Now I will Submit it :

  ![pp](https://github.com/user-attachments/assets/e229a5af-eb39-45f3-b09e-5ed12eae4021)
  
  ![mm](https://github.com/user-attachments/assets/140080e4-a2ca-4eb8-bdb7-4e04702db51b)

---
---
---

## Summary :
The main idea behind this lab is that the server **does not check or filter the files** that users upload. This means we can upload a web shell instead of a normal image file. Because the server **allows these uploaded PHP files to run**, when we access the web shell, the server will execute the code inside it and reveal the secret information.

There are two important steps to this attack:

1. **Upload the web shell:**  
   Use the file upload feature to upload a malicious PHP file (the web shell). Since the server doesn’t validate the file type or content, it accepts and stores our PHP script.

2. **Run the web shell:**  
   Access the uploaded PHP file on the server to run it. This lets us execute commands or read files on the server, like the secret file. Sometimes, just uploading the file is enough if the server automatically runs it, but often you need to visit the file’s URL to trigger it.

Because there is no protection to block or restrict these actions, this vulnerability allows an attacker to take control of the server by uploading and running their own code.

