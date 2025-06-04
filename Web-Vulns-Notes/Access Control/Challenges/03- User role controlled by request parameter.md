# Lab : User role controlled by request parameter 
[**Click here to enter the Lab**](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter)

## Lab Description

This lab has an admin panel at `/admin`, which identifies administrators using a **forgeable cookie**. 
 
> We must access the admin panel and delete the user `carlos` to solve the lab. 
 
we can log in using the following credentials: 
 
* **Username:** `wiener` 
* **Password:** `peter` 

 ---

## Solution 
 
> Before identifying the actual vulnerability, we explored a few common enumeration and bypass techniques that founded in the last labs : 
 
1. **Guessing the Admin Panel Path** 
 
   * From the homepage, we tried accessing `/admin`, `/administrator`, `/admin-panel`, etc. 
   * All attempts resulted in a **404 Not Found** error. 
 
2. **Checking `robots.txt` for Hidden Paths** 
 
   * We navigated to `/robots.txt` hoping to find a disallowed admin path. 
   * Unfortunately, this also returned a **"Not Found"** page. 
 
3. **Viewing the Source Code for Clues** 
 
   * We inspected the **HTML source** of the homepage to check for hidden links or comments. 
   * No comments or hidden elements were found. 
   * Also reviewed JavaScript files to see if any variables, conditions, or routes hinted at admin access — nothing useful was discovered. 
 
> After these methods failed, we shifted focus to analyzing **client-side storage and cookies**. 

---

> **Hint** :   The application uses a cookie called `Admin` to identify admin users. By default, it's set to `false`, but it's **not signed or encrypted**, meaning it can be easily modified to `true` to gain unauthorized admin access. 


* So that , I will login using regular credentials `wiener` , `peter`
* Then Modify the `Admin` cookie to `true`. 
* Then Access `/admin` and delete the user `carlos`.



---

## Actual Solution: Modify the `Admin` Cookie (via DevTools or Extension)

To access the admin panel, we need to **change the `Admin` cookie value from `false` to `true`**.
This can be done in one of two ways:
**using the browser’s built-in Developer Tools** or **using the Cookie-Editor extension**.

---

###  Way 1 : Using Browser DevTools

1. Log in to the application using:

   ```
   Username: wiener  
   Password: peter 
   ```

2. Open **Developer Tools** (`F12`) OR `Ritht Click` & choose inspect page then  → go to `Application` → `Storage` → `Cookies`.

3. Locate the cookie named:

   ```
   Admin=false
   ```

4. Modify it to:

   ```
   Admin=true
   ```

5. Refresh the page and go to:

   ```
   /admin
   ```

6. You should now see the admin panel. Use it to **delete user `carlos`** and solve the lab.

---

### Way 2: Using the Cookie-Editor Extension

If you prefer using a UI extension instead of DevTools:

1. Install the **[Cookie-Editor](https://chrome.google.com/webstore/detail/cookie-editor/fngmhnnpilhplaeedifhccceomclgfbg)** extension (available for Chrome/Firefox).

2. Log in using:

   ```
   Username: wiener  
   Password: peter
   ```

3. Click the Cookie-Editor icon from your browser toolbar.

4. Find the cookie named `Admin`, and change its value from:

   ```
   false → true
   ```

5. Save the changes and navigate to:

   ```
   /admin
   ```

6. Use the admin panel to **delete user `carlos`**.

---

 ## Final Step

* After deleting the user **carlos**, the lab will detect the change and mark the lab as solved.

![PM](https://github.com/user-attachments/assets/26607d66-c6f8-4206-a9ba-beeabccadb43)
