# Lab : Unprotected admin functionality
[**Click here to enter the Lab**](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality)

## Lab Description

This lab has an unprotected admin panel.

Solve the lab by deleting the user carlos.

## Solution

* **What's robots.txt :**
   `robots.txt` file is a publicly accessible text file placed at the root of a website. It instructs search engine crawlers (bots) which parts of the website to crawl or avoid indexing. Although intended for crawlers, this file can reveal hidden or sensitive directories.

* **Try access the robots.txt file**
  Add `/robots.txt` to the end of the lab’s URL to try access the file directly & **Note what you see**.

  ![p](https://github.com/user-attachments/assets/b7a3d6ec-8fe9-4c70-886d-6c52dc46bcfb)

* **Locate the admin panel URL**
  Inside the `robots.txt` file, you will find a disallowed path that points to the administrator panel, for example:

  ```
  Disallow: /administrator-panel
  ```

* **Navigate to the admin panel**
  Go to the revealed URL by entering:

  ```
  http://<lab-url>/administrator-panel
  ```
  
   ![t](https://github.com/user-attachments/assets/454bef98-f6f1-40f1-bcf2-48ed9e275824)

  This page does not have proper access restrictions, so you can access it freely.

* **Delete the user "carlos"**
  Inside the admin panel, locate the user management section. Find the user named **carlos** and delete their account by clicking the delete button or link.

![pt](https://github.com/user-attachments/assets/de0cd9d8-bc33-4ba4-b352-6b829c6c36f8)

---

## Final Step

* After deleting the user **carlos**, the lab will detect the change and mark the lab as solved.
  
![PM](https://github.com/user-attachments/assets/c117ae9e-9ba6-47dd-9f50-76e8b1efb55a)
