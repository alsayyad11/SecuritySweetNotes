# Lab : Web shell upload via Content-Type restriction bypass  
[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass)

## Lab Description

This lab contains an image upload function that is vulnerable due to improper validation. Although it attempts to prevent users from uploading files other than the expected image types, its validation relies solely on user-controlled inputs such as the `Content-Type` header or file extension. This kind of validation can easily be bypassed by an attacker.

Your goal is to exploit this vulnerability by uploading a simple PHP web shell disguised as an allowed image file. Once uploaded, you will use the web shell to execute commands on the server remotely.

Specifically, you need to read the contents of the file located at `/home/carlos/secret` on the server. After extracting this secret information, submit it using the submission button in the lab banner to complete the lab.

You can log in to your own account using the following credentials:  
- **Username:** wiener  
- **Password:** peter

---

## Solution 

[In the previous lab](https://github.com/alsayyad11/SecuritySweetNotes/blob/main/notes/File%20Upload/challenges/02-%20Simple%20RCE%20via%20Web%20shell%20.md) , we observed that the file upload functionality was completely insecure — it didn’t validate the file name, file extension, MIME type, or the actual contents of the uploaded file. 
This allowed us to easily upload a malicious file, such as a PHP web shell, and have it executed on the server without any restrictions.

---

## Developer’s Attempt to Secure File Uploads

To mitigate the vulnerability, the developer added a basic file type check that was intended to accept only files with the MIME type `image/jpeg`. The assumption was that by restricting uploads to JPEG images, it would prevent the upload of dangerous files like `.php` scripts.

However, this defense mechanism had a major flaw: it trusted the `Content-Type` header sent by the client during the file upload request.

![z](https://github.com/user-attachments/assets/3512df5e-9ce7-4648-ac53-2e968aa6ae14)


---

## Bypassing the Protection Using Burp Repeater

Since the `Content-Type` header is completely controlled by the user (i.e., the browser or any custom tool), we used **Burp Suite Repeater** to modify the request. Originally, the malicious PHP file was sent with a `Content-Type` of `application/x-php`, which would likely be rejected.

By simply changing this value to `image/jpeg`, the server accepted the file—even though it still contained PHP code.

Once the file was uploaded, we accessed it through the browser, and the server executed it as PHP, giving us remote code execution through the uploaded web shell.

![x](https://github.com/user-attachments/assets/f072f77f-6879-483a-ac0d-1585c668f9d5)

---

## Why This Worked

The server's file upload implementation was flawed due to weak or missing security checks. Specifically, it failed to:

- Validate the **actual content of the uploaded file** (such as using magic bytes or MIME type detection).
- Check or restrict the **file extension** or **file name**.
- Prevent execution of uploaded files by placing them in a **publicly accessible and executable directory**.

Additionally, the server **relied solely on the `Content-Type` header** provided by the client to determine whether the uploaded file was valid. This is highly insecure because:

- Attackers can easily **spoof the `Content-Type` header** using tools like Burp Suite or by crafting raw HTTP requests.
- The header is controlled entirely by the client and **does not reflect the true nature of the file**.

### How It Could Be Prevented

To prevent this kind of attack, secure file upload implementations should:

- Inspect the file’s **magic bytes** or use server-side MIME detection to verify content type.
- Only allow uploads with **whitelisted file extensions** (e.g., `.jpg`, `.png`).
- **Rename** uploaded files and store them in **non-executable directories** (outside the web root).
- Prevent direct access to uploads or **serve them through a script** that enforces strict access control.


