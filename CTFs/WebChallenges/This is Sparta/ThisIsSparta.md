#  Web Login Challenge 
> Analysis and Bypass via JavaScript Deobfuscation

## Overview  
I’m presented with a simple web application that prompts for a username and password. However, I do not know the correct credentials. The objective is to inspect the web page and deduce the correct username and password by analyzing the frontend code.

Let’s dive in step by step.

---

![image](https://github.com/user-attachments/assets/e199bb53-64cc-4d69-8708-2d5cf666fd3d)

## Step 1: Initial Observation  
Clicking on the "Hint" button reveals a vague message:

> “Easier than Ableton”

This isn’t very informative, but it hints that the challenge is likely simpler than it seems. So I moved on to inspect the page’s source code.

![image](https://github.com/user-attachments/assets/585b1f56-5db2-453f-945f-287e74f2ab15)

---

## Step 2: Viewing the Page Source 

![image](https://github.com/user-attachments/assets/29aa70db-35e5-4b7e-8a06-9e6c9474feaa)

Opening the page source doesn’t reveal much at first glance, but there is one suspicious JavaScript block that immediately stands out:

```javascript
var _0xae5b = [
  "\x76\x61\x6C\x75\x65", "\x75\x73\x65\x72", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64",
  "\x70\x61\x73\x73", "\x43\x79\x62\x65\x72\x2d\x54\x61\x6C\x65\x6E\x74",
  "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x43\x6F\x6E\x67\x72\x61\x74\x7A\x20\x0A\x0A",
  "\x77\x72\x6F\x6E\x67\x20\x50\x61\x73\x73\x77\x6F\x72\x64"
];

function check() {
  var _0xeb80x2 = document[_0xae5b[2]](_0xae5b[1])[_0xae5b[0]];
  var _0xeb80x3 = document[_0xae5b[2]](_0xae5b[3])[_0xae5b[0]];

  if (_0xeb80x2 == _0xae5b[4] && _0xeb80x3 == _0xae5b[4]) {
    alert(_0xae5b[5]);
  } else {
    alert(_0xae5b[6]);
  }
}
````

At this point, it's clear that the script uses hexadecimal obfuscation. Time to decode.

---

## Step 3: Deobfuscation Using CyberChef

I copied the hex values into CyberChef to decode the strings. After processing the obfuscated values, here’s the clean version of the array:

```javascript
var _0xae5b = [
  "value",
  "user",
  "getElementById",
  "pass",
  "Cyber-Talent",
  "Congratz",
  "wrong Password"
];
```

---

## Step 4: Interpreting the Logic

Let’s now analyze what the function check() is actually doing:

```javascript
function check() {
  var username = document.getElementById("user").value;
  var password = document.getElementById("pass").value;

  if (username == "Cyber-Talent" && password == "Cyber-Talent") {
    alert("Congratz");
  } else {
    alert("wrong Password");
  }
}
```

### Explanation:

* Line 1: Retrieves the value of the input field with ID user → username.
* Line 2: Retrieves the value of the input field with ID pass → password.
* Line 3–5: Compares both username and password with the string `"Cyber-Talent"`.

  * If both match, show “Congratz”.
  * Else, show “wrong Password”.

---

## Step 5: Final Conclusion

Based on this logic, the correct credentials are:

* 🔑 Username: `Cyber-Talent`
* 🔑 Password: `Cyber-Talent`

Submitting these values…

✅ Success! The page returns the flag:

```
FLAG: {J4V4_Scr1Pt_1S_Aw3s0me}
```

![image](https://github.com/user-attachments/assets/98834fe9-f928-4abf-b2d4-5a0666577c52)

---
> Although this was a relatively simple challenge, it reinforces the importance of understanding how front-end logic can be exposed and reverse-engineered. JavaScript obfuscation can sometimes delay analysis, but with tools like CyberChef and a methodical approach, it’s usually easy to unravel.

---
