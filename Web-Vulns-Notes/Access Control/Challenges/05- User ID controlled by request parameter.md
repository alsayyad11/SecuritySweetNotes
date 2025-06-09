# Lab : User ID controlled by request parameter 
[**Click here to enter the Lab**](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter)

## Lab Description

This lab demonstrates a horizontal privilege escalation vulnerability in a web application's user account page. In such attacks, a malicious user takes advantage of insufficient access control to access other users' data by manipulating identifiers (like usernames, user IDs, etc.) in requests.
> To solve the lab, obtain the API key for the user carlos and submit it as the solution.

We can log in using the following credentials :

* Username: `wiener`
* Password: `peter`

  ---
  # Solution

### At first I will log In with Provided Credentials

```plaintext
Username: wiener  
Password: peter
```

---

### Then I will Navigate to my Account Page

* Observe the **URL structure**. It will look something like:

```
/my-account?id=wiener
```
![o](https://github.com/user-attachments/assets/96c82a00-0a06-46a2-8f21-045aeef02dee)

> This is a strong indicator of a **user identifier being passed via GET parameter**.

---

### Now I will Send Request to Burp Repeater

1. Open **Burp Suite** and enable the **intercept**.
2. While visiting the `/my-account` page, capture the request.
3. Right-click the request and choose:

```
Send to Repeater
```

---

### Now I will Modify the `id` Parameter

* In Burp Repeater, locate the `id` parameter in the GET request:

```http
GET /my-account?id=wiener HTTP/1.1
```

* Change the value from `wiener` to `carlos`:

```http
GET /my-account?id=carlos HTTP/1.1
```

---

### Then Send the Modified Request

* Click **"Send"** in Burp Repeater.
* Analyze the **response**:

  * If the application is vulnerable, you should see **Carlos's account data**, including his **API key**.

Example API Key response (look for something like this):

```json
{
   "username": "carlos",
   "api_key": "j2h3k5-9ad1f8-...etc"
}
```
![p](https://github.com/user-attachments/assets/dc8af879-7e71-4638-b358-bac8b1af0176)

---

 ## Final Step : Submit Carlos’s API Key

* Copy the retrieved API key.
* Paste it in the **submission field** on the lab page.
* Click **Submit**.

![pf](https://github.com/user-attachments/assets/cc1d62ad-489f-4c46-9aaf-8b63be59bd7c)


> The vulnerability exploited here is a horizontal privilege escalation, where the application fails to properly enforce access controls. Although each user has a unique account page identified by a parameter in the URL (such as ?id=wiener), the server does not verify whether the logged-in user is authorized to access the data tied to the given ID. As a result, simply changing the parameter to another valid username (e.g., ?id=carlos) allows unauthorized access to sensitive information belonging to that user—such as an API key—despite not having their credentials.

