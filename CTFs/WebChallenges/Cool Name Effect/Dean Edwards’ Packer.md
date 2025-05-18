<p align="center">
  <img src="https://github.com/user-attachments/assets/8b75a72b-61bf-4d46-96b8-5b91b9558f89" alt="Centered Image">
</p>



## 1. Intro

**Dean Edwards’ Packer** is a **JavaScript obfuscator** that:

* **Minifies** code (makes it smaller),
* **Obfuscates** it (makes it hard to understand),
* And uses **self-unpacking at runtime** (the code unpacks itself when executed).

In simple terms, it takes readable JavaScript code and turns it into unreadable, compressed code that still functions normally in the browser.

---

## 2. How Does It Work?

### Stage 1: Minification

This step removes unnecessary parts of the code, such as:

* Comments,
* Whitespace and newlines,
* Long variable/function names (they're shortened to letters like `a`, `b`, `c`).

The purpose here is to reduce the file size and slightly increase the difficulty of reading the code.

---

### Stage 2: Obfuscation

This is where the real transformation happens:

* Code is converted into a string-based representation using **string lookup tables** and **symbol replacement**.
* Every meaningful token (functions, variables, keywords) is encoded and replaced with indexes or obscure symbols.
* The entire logic is wrapped inside an `eval()` or `Function()` call that decodes and runs it at runtime.

Techniques used here:

* String Array Mapping (a dictionary of keywords)
* Base conversions (like Base36 or Base62)

---

### Stage 3: Runtime Unpacking

At runtime (i.e., when the browser runs the script):

* The obfuscated code is passed to `eval()` or `Function()` which decodes the original logic.
* The decoded JavaScript executes as if it was written normally.

So the code that looked like gibberish becomes functional JavaScript during execution.

---

## 3. Step-by-Step Example

### Original Code:

```javascript
function greet(name) {
  alert("Hello " + name);
}
greet("Ali");
```

---

### After Minification:

```javascript
function a(b){alert("Hello "+b)}a("Ali");
```

---

### After Packer Obfuscation:

```javascript
eval(function(p,a,c,k,e,d){
  e=function(c){return c.toString(36)};
  if(!''.replace(/^/,String)){
    while(c--) d[c.toString(a)]=k[c]||c.toString(a);
    k=[function(e){return d[e]}];
    e=function(){return'\\w+'};
    c=1;
  }
  while(c--) if(k[c]) p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);
  return p;
}('2(1("Ali"));function 1(c){3("Hello "+c)}',4,4,'|greet|eval|alert'.split('|'),0,{}));
```

That's what happens:

* The entire logic is encoded into a single line of JavaScript.
* Functions and keywords are replaced with numbers and mapped to a lookup table.
* `eval()` runs the decoding logic during runtime and executes the original code.

---

## 4. General Structure 

```javascript
eval(function(p,a,c,k,e,d){...})(<payload>, <base>, <count>, <dictionary>);
```

Explanation of components:

* `p`: The compressed JavaScript payload.
* `a`: The numeric base used for encoding (typically 36 or 62).
* `c`: The number of unique words replaced in the code.
* `k`: The dictionary (array) containing original tokens.
* `e` and `d`: Functions for decoding and replacing tokens during runtime.

---

## 5. Base Encoding

Dean Edwards' Packer uses base conversions like:

* **Base36**: Numbers and lowercase letters
* **Base62**: Numbers + uppercase + lowercase

Example:

* If `k[3] = "alert"`, then `3` in base36 = `"3"`, which gets mapped to `"alert"` at runtime.

---

## 6. Why Do Developers Use Packer?

| Purpose             | Explanation                                               |
| ------------------- | --------------------------------------------------------- |
| Code Hiding         | Prevents others from reading or copying the logic easily. |
| File Size Reduction | Smaller code = faster loading time.                       |
| Tamper Resistance   | Makes it harder to modify logic by hand.                  |
| Obfuscation         | Makes reverse engineering more difficult.                 |

---

## 7. Disadvantages

| Problem               | Explanation                                              |
| --------------------- | -------------------------------------------------------- |
| Performance Issues    | Uses `eval()` which slows down execution slightly.       |
| Security Risk         | `eval()` opens up the possibility for injection attacks. |
| Easy to Deobfuscate   | Many public tools can reverse the process.               |
| Doesn’t Protect Logic | The logic is still there—just hidden.                    |

---

## 8. Tools to Deobfuscate Packer Code

Several tools are available that can easily reverse code packed using Dean Edwards’ method:

* **[de4js](https://lelinhtinh.github.io/de4js/)** – Web-based JavaScript deobfuscator.
* **JSNice** – Restores readable code with better variable names.
* **beautifier.io** – Formats minified/obfuscated code for readability.
* **Browser DevTools** – `eval` output can be viewed using breakpoints and console inspection.

---
