#  Lab : Unprotected admin functionality with unpredictable URL
[**Click here to enter the Lab**](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url)

## Lab Description

This lab has an unprotected admin panel. It’s located at an unpredictable location, but the location is disclosed somewhere in the application.
and we must Access the hidden admin panel and delete the user carlos to solve the lab.

> The admin panel is not protected by authentication or access control and can be accessed if the URL is known.

## Solution 

- From the lab’s homepage, we try guessing the URL, but this gives us a 404 error.
- Next step: Check for robots.txt file by navigating to /robots.txt.
> Unfortunately, this also leads to a “Not Found” page.

## Source Code Analysis 
 
* Open the **source code** of the homepage (`Right-click > View Page Source` or `Ctrl+U`). 
* Look for **JavaScript** or **HTML comments** that may contain clues. 
 
> Discovered JavaScript :

![image](https://github.com/user-attachments/assets/c31f61ff-7c16-4f03-ab4d-f796a04cec2d)

### this it the code : 
 
```js 
 <script>
var isAdmin = false;
if (isAdmin) {
   var topLinksTag = document.getElementsByClassName("top-links")[0];
   var adminPanelTag = document.createElement('a');
   adminPanelTag.setAttribute('href', '/admin-apkr8f');
   adminPanelTag.innerText = 'Admin panel';
   topLinksTag.append(adminPanelTag);
   var pTag = document.createElement('p');
   pTag.innerText = '|';
   topLinksTag.appendChild(pTag);
}
</script>
``` 


### Code Explanation : 
 
* `var isAdmin = false;` — This variable shows the script is inactive and likely left in development. 
* `if (isAdmin) { ... }` — Conditional block for admin users. 
* `adminPanelTag.setAttribute('href', '/admin-ve1m4v');` — This line reveals the hidden path to the admin panel. 
* The URL is dynamic and changes per lab instance (`/admin-[random]`), meaning it can’t be guessed, but was accidentally exposed via code. 


## Get into admin panel  

1. I will Copy the admin panel path from the JavaScript: e.g., `/admin-ve1m4v`. 
2. I will Append it to the lab domain in my browser: 
   `https://<lab-id>.web-security-academy.net/admin-ve1m4v` 
3. I will land on the **Admin Panel** page. 
4. I will Use the available button to **delete the user `carlos`**. 

 ## Final Step

* After deleting the user **carlos**, the lab will detect the change and mark the lab as solved.
  
![image](https://github.com/user-attachments/assets/5d3ea20e-8d68-4aa2-a778-ee24642aa1e2)
