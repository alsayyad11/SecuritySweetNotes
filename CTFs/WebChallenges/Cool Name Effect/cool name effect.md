
## 1. Understanding the Challenge Description

The challenge says :

> “Webmaster developed a simple script to do cool effects on your name, but his code not filtering the inputs correctly. Execute JavaScript alert and prove it.”

![image](https://github.com/user-attachments/assets/38e44c07-6fc2-40db-896c-72ca75c672ef)

This tells us:

* The developer created a script that shows special effects on the name you input.
* But, the code doesn't **properly sanitize or filter the user input**.
* You’re required to **trigger a JavaScript `alert()`** as proof of the vulnerability.

From this, it’s **very clear** that the challenge is about **exploiting an XSS vulnerability**.

---

## 2. Initial Testing of the Application

We visit the challenge page and try a basic name like:

```
Ahmed M Alsayyad
```

The script displays the name with some cool effects.
So now we know the input is being **dynamically rendered** somewhere on the page — and that could be where XSS is possible.

Next, we inspect the **page source** to analyze the HTML and JavaScript code behind the effects.

![image](https://github.com/user-attachments/assets/8bc0c540-8bdf-4507-a72a-16e0d0118df0)

---

## 3. Source Code Analysis ( **Enumeration** )

When analyzing the page source of a web application, it’s common to encounter multiple <script> tags. As part of the inspection process, each script should be reviewed to identify which one handles user input or dynamic behavior. During this process, encountering a script that appears obfuscated — with unreadable or intentionally scrambled code — is a strong indicator that it may contain critical logic, hidden functionality, or even potential vulnerabilities. This makes it a key point of interest for further analysis.

![image](https://github.com/user-attachments/assets/5b906f98-039b-481e-8501-e5c53e309141)

### Like this : 

![image](https://github.com/user-attachments/assets/2ebdb2d0-206e-4348-9691-7b70145a33a3)

---

## 4. Identifying Obfuscated Code 

When examining the script, we see:

* Use of `eval(...)`
* Variable names that are meaningless (e.g., `p,a,c,k,e,d`)
* A structure that looks like encoded strings and tables

All of this points to a known obfuscation technique called **Dean Edwards’ Packer**.
It compresses and hides the JavaScript using string lookup tables and base conversion, then runs it using `eval()` at runtime.

---

## 5. Deobfuscating the Code – Using the Console

To make sense of the obfuscated script, we do a clever trick:

1. Open the browser’s **DevTools (F12)**
2. Copy the entire obfuscated script
3. **Replace `eval(...)` with `console.log(...)`**

![image](https://github.com/user-attachments/assets/7289a0d9-4c1d-466f-a387-592d70994efe)


Why?
Because we don’t want to run the code blindly — we want to **see the actual JavaScript after unpacking**.

After doing this and executing it in the browser console, the unpacked code is printed clearly.

And here’s the major hint:

```js
['y','o','u','r',' ','f','l','a','g',' ','i','s',':']
```

This shows that somewhere inside the code, a message saying **"your flag is:"** is being constructed — which means we’re close.

![image](https://github.com/user-attachments/assets/5d28dc0d-a0a3-47f4-9251-364c37ba6d1d)

---

## 6. Analyzing the Actual Function: `newAlert`

From the deobfuscated code, we find a function like:

```js
newAlert = function() {
  var z = ['y','o','u','r',' ','f','l','a','g',' ','i','s',':'];
  ...
}
```

This function is used to **print or construct the flag message**.

Then, we find this crucial piece:

```js
window.alert = newAlert;
window.prompt = newAlert;
window.confirm = newAlert;
```

This tells us:

* Every time `alert()`, `prompt()`, or `confirm()` is called — it’s not the default browser popup.
* Instead, the custom `newAlert()` function is triggered, which displays the flag.

So now our **goal** becomes simple: **trigger the `alert()` function** from our input — and it will execute `newAlert()`.

![image](https://github.com/user-attachments/assets/aa5bb6db-8e70-4dbb-8729-32b39b074ed8)

---

## 7. Exploiting the XSS && create the Payload

To exploit the vulnerability, we need to inject JavaScript into the input field.

After trying several inputs, we found this **perfect payload**:

```html
<img src=x onerror="alert()">
```

Explanation:

* `<img src=x>` — this tries to load an image from a non-existent path.
* Since `x` does not exist, the browser triggers the `onerror` event.
* `onerror="alert()"` — this calls the `alert()` function.
* Since `window.alert` was redefined to `newAlert`, we trigger `newAlert()` — and the flag is revealed.

![image](https://github.com/user-attachments/assets/cc69afe6-b0b7-4b7f-a549-cf217919886d)

---

## 8. Getting the Flag – Final Step

As soon as we submit the payload, the `alert()` is triggered.

But instead of the default popup, we see:

```
your flag is: <actual_flag_here>
```

Which means the XSS was successful, and we’ve completed the challenge.

![image](https://github.com/user-attachments/assets/df1cf243-0123-493f-86eb-46ade3796ab8)

---

## 9. Final Summary

Let’s break down the entire process clearly:

| Step | Description                                                                   |
| ---- | ----------------------------------------------------------------------------- |
| 1    | Read the challenge description                                                |
| 2    | Tested how input is handled on the page                                       |
| 3    | Opened page source to look for JavaScript                                     |
| 4    | Found obfuscated script (packed code)                                         |
| 5    | Replaced `eval()` with `console.log()` in the DevTools console                |
| 6    | Revealed the actual logic: `newAlert()` function and overwriting of `alert()` |
| 7    | Crafted XSS payload to call `alert()` from within input                       |
| 8    | Payload triggers `newAlert()` and displays the flag                           |

---

## Notes and Takeaways

* Use of `eval()` is a red flag — often associated with obfuscation and potential vulnerabilities.
* Obfuscation does **not** equal security — tools like DevTools easily reveal obfuscated code.
---
