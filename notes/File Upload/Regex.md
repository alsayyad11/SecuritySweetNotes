<p align="center">
  <img src="https://github.com/user-attachments/assets/410020e1-00b8-4ff1-84af-706833319f77" alt="image" />
</p>


# What is Regex?

**Regex** stands for **Regular Expression**.
It is a special language used to **search**, **match**, and **validate** patterns inside text.

Think of it like this:

> You are telling the computer: "Find or check text that looks like this specific pattern."

---

## What is Regex used for?

1. **Validation**: Check if input is correct (like an email or phone number).
2. **Search**: Find specific words, numbers, or characters in text.
3. **Replace**: Change parts of text based on pattern (e.g., replace all numbers with stars).

---

# Basic Regex Symbols

| Symbol   | Meaning                                                     |
| -------- | ----------------------------------------------------------- |
| `\d`     | Any digit (0–9)                                             |
| `\w`     | Any letter, digit, or underscore (`a-z`, `A-Z`, `0-9`, `_`) |
| `.`      | Any character except newline                                |
| `+`      | One or more of the previous thing                           |
| `*`      | Zero or more                                                |
| `^`      | Start of the line                                           |
| `$`      | End of the line                                             |
| `{n}`    | Exactly n times                                             |
| `[abc]`  | One of these characters: a or b or c                        |
| `[^abc]` | Any character except a, b, or c                             |
| `\s`     | Whitespace (space, tab, newline)                            |
| `\b`     | Word boundary (start or end of word)                        |

---

# Example 1: Egyptian Phone Number

Check if a mobile number:

* Starts with `01`
* Has 9 more digits after that
* Total: 11 digits

**Regex Pattern**:

```regex
^01\d{9}$
```

**Explanation**:

* `^` = Start of line
* `01` = Must start with 01
* `\d{9}` = Exactly 9 digits
* `$` = End of line

**Valid examples**:

* `01012345678` ✅
* `01234567890` ✅

**Invalid examples**:

* `1012345678` ❌ (Doesn't start with 01)
* `012345` ❌ (Too short)
* `01123456789abc` ❌ (Has letters)

---

# Example 2: Email Validation

We want to make sure the email is like:
`something@something.something`

**Regex Pattern**:

```regex
^\w+@\w+\.\w+$
```

**Explanation**:

* `\w+` = One or more word characters (letters, numbers, \_)
* `@` = The @ symbol
* `\w+` = Domain name (like gmail, yahoo)
* `\.` = A dot `.`
* `\w+` = Top-level domain (like com, net)

**Valid examples**:

* `ahmed@gmail.com` ✅
* `test123@yahoo.net` ✅

**Invalid examples**:

* `@gmail.com` ❌ (Missing part before @)
* `ahmed@.com` ❌ (Missing domain)
* `ahmed@gmail` ❌ (Missing `.com` or similar)

---

# Example 3: Extract Numbers from Text

**Text**:
`I have 2 dogs, 15 chickens, and 3 ducks.`

**Regex Pattern**:

```regex
\d+
```

**Matches**:

* `2`, `15`, `3`

Explanation:

* `\d` = digit
* `+` = one or more

---

# Example 4: Word starts with 'a' and ends with 'z'

**Regex Pattern**:

```regex
^a.*z$
```

**Explanation**:

* `^` = Start of word
* `a` = Must start with a
* `.*` = Any characters in between
* `z` = Must end with z
* `$` = End of word

**Valid**:

* `abcz` ✅
* `amazingz` ✅

**Invalid**:

* `hello` ❌ (Doesn't start with a or end with z)
* `aztest` ❌ (z not at the end)

---

# How to Try Regex Yourself

Use this site to test patterns:
**[https://regex101.com](https://regex101.com)**

You can:

* Write your regex on the left
* Enter a sample text
* See what matches and explanations on the right

---

