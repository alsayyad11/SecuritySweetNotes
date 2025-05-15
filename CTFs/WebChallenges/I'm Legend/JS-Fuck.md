<p align="center">
  <img src="https://github.com/user-attachments/assets/985bf98e-4261-4b18-9b9b-ca49fb68e77b" alt="image" />
</p>


## 1. What is JSFuck exactly?

JSFuck is a way to write JavaScript code using **only 6 characters**, instead of normal letters and digits.

---

## 2. What are those 6 characters?

The characters used in JSFuck are:

```
[ ] ( ) ! +
```

These are all the characters you use to write any JavaScript code in JSFuck.

---

## 3. How do you write code with JSFuck?

The trick is that you use JavaScript's own features to build letters, numbers, and words.

### The key basics used:

| Normal JavaScript value | How to write it in JSFuck | Explanation                                          |
| ----------------------- | ------------------------- | ---------------------------------------------------- |
| `false`                 | `![]`                     | `[]` is an empty array; `!` negates it, so false     |
| `true`                  | `!![]`                    | `![]` is false, negated again gives true             |
| `undefined`             | `[][[]]`                  | Accessing empty array inside empty array → undefined |
| `NaN`                   | `+{}`                     | Unary plus on an empty object → Not-a-Number         |
| `0`                     | `+[]`                     | Unary plus on empty array → 0                        |
| `1`                     | `+!+[]`                   | Unary plus on negation of 0 (true) → 1               |

---

## 4. How to extract letters from strings?

In JavaScript, you can get a character from a string using brackets, e.g.:

```js
"false"[0]  // returns "f"
```

Since `![]+[]` equals `"false"` as a string, we can take letters from it:

```js
(![]+[])[0] // "f"
(![]+[])[1] // "a"
```

This way, you can build all letters you need, one by one.

---

## 5. Building words and commands:

Once you can get letters, you concatenate them to form words like:

* `alert`
* `console`
* `document`
* or any other JavaScript keywords.

Then you write commands and execute them!

---

## 6. Simple example: writing `"alert"` in JSFuck:

* `a` = `(![]+[])[1]`
* `l` = `(![]+[])[2]`
* `e` = `(![]+[])[4]`
* `r` = `(!![]+[])[1]`
* `t` = `(!![]+[])[0]`

Concatenate:

```js
(![]+[])[1]+(![]+[])[2]+(![]+[])[4]+(!![]+[])[1]+(!![]+[])[0]
```

---

## 7. Writing English letters and digits (0-9) in JSFuck

### Letters a - z

| Letter | Example JSFuck Generation | Simple Explanation                             |
| ------ | ------------------------- | ---------------------------------------------- |
| a      | `(![]+[])[1]`             | `'false'` string, char at index 1 is 'a'       |
| b      | `({}+[])[2]`              | `'[object Object]'` char at index 2 is 'b'     |
| c      | `({}+[])[1]`              | `'[object Object]'` char at index 1 is 'c'     |
| d      | `({}+[])[5]`              | `'[object Object]'` char at index 5 is 'd'     |
| e      | `(![]+[])[4]`             | `'false'` char at index 4 is 'e'               |
| f      | `(![]+[])[0]`             | `'false'` char at index 0 is 'f'               |
| g      | `(true+[])[5]`            | `'true'` char at index 5 (needs more building) |
| h      | -                         | Rare or complex construction                   |
| i      | `([![]]+[][[]])[10]`      | `'undefinedfalse'` char at index 10 is 'i'     |
| j      | -                         | Rare or complex construction                   |
| k      | -                         | Rare usage                                     |
| l      | `(![]+[])[2]`             | `'false'` char at index 2 is 'l'               |
| m      | `({}+[])[7]`              | `'[object Object]'` char at index 7 is 'm'     |
| n      | `([][[]]+[])[1]`          | `'undefined'` char at index 1 is 'n'           |
| o      | `({}+[])[1]`              | `'[object Object]'` char at index 1 is 'o'     |
| p      | `([]+"")[7]`              | `'undefinedfalse'` char at index 7 is 'p'      |
| q      | -                         | Rare usage                                     |
| r      | `(!![]+[])[1]`            | `'true'` char at index 1 is 'r'                |
| s      | `(![]+[])[3]`             | `'false'` char at index 3 is 's'               |
| t      | `(!![]+[])[0]`            | `'true'` char at index 0 is 't'                |
| u      | `([][[]]+[])[0]`          | `'undefined'` char at index 0 is 'u'           |
| v      | -                         | Rare usage                                     |
| w      | -                         | Rare usage                                     |
| x      | -                         | Rare usage                                     |
| y      | `(NaN+"")[1]`             | `'NaN'` char at index 1 is 'a' (indirect)      |
| z      | -                         | Rare usage                                     |

---

### Digits 0-9

| Digit | JSFuck Representation                           | Explanation                     |
| ----- | ----------------------------------------------- | ------------------------------- |
| 0     | `+[]`                                           | Unary plus on empty array → 0   |
| 1     | `+!+[]`                                         | Unary plus on negation of 0 → 1 |
| 2     | `+!+[]+!+[]`                                    | 1+1 = 2                         |
| 3     | `+!+[]+!+[]+!+[]`                               | 1+1+1 = 3                       |
| 4     | `+!+[]+!+[]+!+[]+!+[]`                          | 1+1+1+1 = 4                     |
| 5     | `+!+[]+!+[]+!+[]+!+[]+!+[]`                     | 1+1+1+1+1 = 5                   |
| 6     | `+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]`                | 1+1+1+1+1+1 = 6                 |
| 7     | `+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]`           | 1+1+1+1+1+1+1 = 7               |
| 8     | `+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]`      | 8                               |
| 9     | `+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]+!+[]` | 9                               |

---

## 8. Advantages of JSFuck:

* **Hard to understand:** The resulting code is extremely difficult to read, making the original code unclear.
* **Bypasses some filters:** Sometimes it can bypass filters or security that block normal scripts.
* **Educational challenge:** Used for CTF challenges or as a fun code puzzle.

---

## 9. Disadvantages of JSFuck:

* **Huge code size:** Even a simple snippet can expand 10 to 100 times larger.
* **Hard to maintain:** Very difficult to edit or debug.
* **Slow performance:** Takes longer to parse and run due to complexity.
* **Limited practical use:** Mostly used in challenges, obfuscation, or security testing, not real-world projects.

---

## 10. Is JSFuck safe?

**Yes**, it's just normal JavaScript code, but the problem is its extreme obfuscation which makes it hard to analyze or audit.

---

## 11. Helpful Tools for JSFuck

1. **Official JSFuck Website:**

   [https://jsfuck.com/](https://jsfuck.com/)

   * Main site to encode JavaScript to JSFuck.
   * Has tools for encoding and generating code.

2. **JSFuck Decoder Website:**

   [https://enkhee-osiris.github.io/Decoder-JSFuck/](https://enkhee-osiris.github.io/Decoder-JSFuck/)

   * Free site to decode JSFuck code back to normal JavaScript.
   * Easy to use: paste the code and click decode.

3. **PoisonJS (Advanced Obfuscation Tool):**

   [https://filipemgs.github.io/poisonjs/](https://filipemgs.github.io/poisonjs/)

   * Tool for advanced JavaScript obfuscation, including JSFuck and other techniques.
   * Used for code protection or security challenges.

---

## 12. Quick Summary:

| Feature       | Description                                  |
| ------------- | -------------------------------------------- |
| Characters    | Only `[ ] ( ) ! +`                           |
| Purpose       | JavaScript obfuscation and encoding          |
| Advantages    | Hard to read, bypasses some security filters |
| Disadvantages | Huge code size, slow, hard to maintain       |

---

