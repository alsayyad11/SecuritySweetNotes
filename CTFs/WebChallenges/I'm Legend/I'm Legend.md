# CyberTalents challenge name "I am a legend".

## At the start of the challenge we find a login page 
> I will test some vulns and see source code rivew to check if their is some thing unusual

![image](https://github.com/user-attachments/assets/4e0f2b3b-6d47-4453-9c97-425560b069e1)

---

## So I will check if their is a script in source code 

### Right-click → View Page Source
- Once we inspect the source code:
  We scroll down and immediately notice a strange-looking <script> block at the bottom of the page.

- It doesn’t look like normal JavaScript — instead, it’s filled with patterns like:

```
[]+(![]+[])[+[]]+...
```

> This clearly indicates that the code is obfuscated, most likely using a technique called JSFuck, or something similar that heavily disguises the logic.

![image](https://github.com/user-attachments/assets/70661571-7476-4b9a-af7a-caa5f84d6e8e)

---

## There is an abnormal script obviously in the bottom here, so let’s google how to rewrite it to an understandable one.
### Key point:
- This script is using some form of JavaScript obfuscation — meaning the code is deliberately made unreadable.
- It’s very common in CTFs and web challenges to hide sensitive logic or credentials this way.

---
## To be able to read this code , we must convert it to normal js code.
- we will do it with online tools like [filipemgs tool](https://filipemgs.github.io/poisonjs/)

![image](https://github.com/user-attachments/assets/6e37229f-6212-4e2b-b5b7-f52fbb185ee1)

### Why is this tool useful?
This is a multi-purpose JavaScript deobfuscation tool that can handle &&
It allows you to paste obfuscated JavaScript and automatically converts it back into a readable, beautified version.

- JSFuck
- eval(unescape(...))
- P.A.C.K.E.R
- base64-encoded scripts
- nested obfuscation layers

---

### After decoding the script:

* You’ll see a readable JavaScript function like `check()` or `validate()`.
* Inside the function, you'll likely find some logic that checks for **hardcoded credentials**, such as:

```js
let user = document.getElementById("username").value;
let pass = document.getElementById("password").value;

if (user == "Cyber" && pass == "Talent") {
    alert("FLAG: {Y0u_4r3_4_L3g3nd}");
}
```

![image](https://github.com/user-attachments/assets/18bccb17-162c-4b07-b9e6-d540f5471448)
