# Lab : User role can be modified in user profile

[**Click here to enter the Lab**](https://0ab30098041f449f80b321eb00580033.web-security-academy.net/)

## Lab Description

This lab features an admin panel located at the `/admin` path.
The admin panel is only accessible to logged-in users with a `roleid` of 2.

The objective is to access the admin panel and use it to delete the user **carlos**.

We can log in using the following credentials :

* Username: `wiener`
* Password: `peter`

---

# Solution 

1. **At first** Logge in with the provided credentials ( `wiener` : `peter` ).

2. **Then** go to ‘My account’ section.

3. I observed the update email feature.

![PM](https://github.com/user-attachments/assets/b98b7e96-11e0-4d2b-b1cd-7997aa6f6ddb)

4. Now I will try to update it and I will use Burp Suite’s Proxy to intercept HTTP requests.

5. Send the update email request to **Repeater** and see it's result .

![p](https://github.com/user-attachments/assets/bce53edf-dcab-4d00-9e13-d338c405608e)

6. I observed a `roleid : 1 `

> This simply means that the user we logged in with (`wiener`) has a `roleid` of **1**, which usually indicates a **regular user** (not an admin).
In this system, roles are represented by numeric values:
* `roleid: 1` = Regular User
* `roleid: 2` = Admin → the only role allowed to access the `/admin` page

I will try to change it from `roleid: 1` to `roleid: 2` and resend request and see the result .

![PM](https://github.com/user-attachments/assets/fea7172b-d505-40d8-a70c-68e05eb50376)

go to th browser and we will find my role changed form regular user to admin and the admin panel appeared .

![rr](https://github.com/user-attachments/assets/56f0b290-9d16-424d-854c-054feae473eb)

---

 ## Final Step
 
Now I wil Accesse the admin panel by clicking “Admin panel” and delete the user carlos to solve the lab.

![ii](https://github.com/user-attachments/assets/e8778830-82e8-4c67-a428-8f8409dcd75d)

