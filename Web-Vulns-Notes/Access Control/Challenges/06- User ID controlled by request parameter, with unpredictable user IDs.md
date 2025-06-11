# Lab : User ID controlled by request parameter, with unpredictable user IDs 
[**Click here to enter the Lab**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids)

## Lab Description 
This lab has a **horizontal privilege escalation** vulnerability. Each user is identified using a **GUID** (a long unique ID like `550e8400-e29b-41d4-a716-446655440000`).

My objective is to access the account of another user named **Carlos** and retrieve **his API key** to solve the lab.

We can log in using the following credentials :

> **Username:** `wiener`
> **Password:** `peter`

---

## Solution

At First, I will **explore** the website while logged out. I’ll go through several posts one by one, checking who wrote them. When I find a post by **Carlos**, I’ll click on **his username**, which should take me to his profile page.

In the URL of that page, I expect to see something like:

```
https://example.com/my-account?id=550e8400-e29b-41d4-a716-446655440000
```

That long string is Carlos’s **GUID**, and I will copy it for later use.

![p](https://github.com/user-attachments/assets/6a785aba-a2de-4908-9b20-6b2140812408)

![pa](https://github.com/user-attachments/assets/413f1e38-e620-4aa3-87f0-7fe08c0a1168)

---

Next, I will go to the login page and sign in using:

* **Username:** `wiener`
* **Password:** `peter`

Once I’m logged in, I’ll go to my account page. The URL should look like:

```
https://example.com/my-account?id=MY-GUID-HERE
```

![r](https://github.com/user-attachments/assets/50fdb753-dcd9-49d5-ad6c-621d4918ba03)

I will replace **my own GUID** in the URL with **Carlos’s GUID** that I copied earlier, and press **Enter**.

If the site is vulnerable, it should show **Carlos’s account page**, even though I’m still logged in as `wiener`.

### Before change GUID 
![PM](https://github.com/user-attachments/assets/d48a5efc-4fcb-4ace-acfb-c88e660f14e8)

### After change GUID 
> On Carlos’s account page, I will look for his **API key** and copy it.

![l](https://github.com/user-attachments/assets/fd1e9706-d8d3-4280-8887-6417b305ad3e)

---


 ## Final Step : Submit Carlos’s API Key

* Copy the retrieved API key.
* Paste it in the **submission field** on the lab page.
* Click **Submit**.

![fPM](https://github.com/user-attachments/assets/cff0891f-3c3d-4d6d-b25b-c36d620ef965)

---
