---
title: "Akar Ransomware"
date: 2025-1-28
categories: [Malware Analysis,Ransomware]
tags: [Malware Analysis,Ransomware]
---

## Executive Summary
The code obfuscates files and directories by validating input, deriving an encryption key using an **MD5** hash, and applying **custom XOR-based** encryption (`xtea_encrypt` and `xxtea_encrypt`). It targets specific file extensions by encrypting their contents, appending `".hbbie"` to filenames, and recursively processing subdirectories. The program also generates an encrypted `"readme.txt"` in a specified directory, using environment variables and a hardcoded Base64-encoded payload (flagg).

---

### Sample Information

| **Attribute**             | **Details**                                                |
|---------------------------|------------------------------------------------------------|
| **File name**             | `svchost.exe`                                              |
| **File size**             | `10 KB`                                                   |
| **File type**             | `Executable File`                                           |
| **MD5**                   | `18fae5dff5e3f8ebdaad49e80e3e4aec`                        |
| **SHA1**                  | `bee92af18b3ae3d4ec3d3b64a26809b5305abaab`               |
| **SHA256**                | `7cc7881fe0efe0e08bfe3b41171569bc90f350716ddb8c99abe875994f779453` |
| **Packer / compiler info**| `Microsoft .NET`                                            |
| **Compile time**          | `Sat Aug 25 12:19:41 2063 (UTC)`                            |

---

## Case-Specific Requirements

### Machine
- **Windows Environment**
- **Linux Environment**

### Tools Used
- **De4dot**
- **DNSPY**
- **Python**
- **Detect It Easy (DIE)**

---

## Static Analysis

Inspecting the file using **Detect It Easy (DIE)** the file have the protection called Confuser version 1.X and the library was dotnet. Checking the entropy the file was readable but some of the text was gibberish.

![img](assets/10-AkarRansomware/image188.png)

![img](assets/10-AkarRansomware/image189.png)

Utilize **de4dot** to pack back the gibberish:

![img](assets/10-AkarRansomware/image190.png)
 
After unpacked, the entropy has become low (from `5.22013` to `4.88867`) to make it more readable.

![img](assets/10-AkarRansomware/image191.png)

Using the new **svhosts-cleaned.exe** version, now the text will become readable:

![img](assets/10-AkarRansomware/image192.png)

The Main function is the starting point. It checks if the program was run with the correct input and validates it by creating a hash using the c_256 function. If the validation fails, it stops. If it passes, the program checks for a specific system variable to decide whether it should continue. If the variable isn’t found, it sets up by decoding a hidden string, creating an encryption key, and calling p_f to start encrypting files.

![img](assets/10-AkarRansomware/image193.png)

`C_256` function generates a hash from the input provided when the program starts. This is used to verify if the program should run, acting like a encrypted key to unlock its functionality.

![img](assets/10-AkarRansomware/image194.png)

The `p_f` function looks through files and folders. It targets files with certain extensions, encrypts them using xtea_encrypt, and renames them with a new extension ‘.hbbie’. It also goes into subfolders to repeat the process, making sure no file is left out.

![img](assets/10-AkarRansomware/image195.png)

The `xxtea_encrypt` function was a formula to encrypt data.

![img](assets/10-AkarRansomware/image196.png)

The `xtea_encrypt` function encrypts the actual content of the files, making them unreadable. It’s the main tool the ransomware uses to lock victims out of their data.

![img](assets/10-AkarRansomware/image197.png)

The ransomware relies on a key derived from the MD5 hash of the input (c_256) for validation. If the key matches a hardcoded value (Substring 8-16 MD5 must have "d1762555582b513f") and the "da2607bg" environment variable is missing, it targets the directory "%userprofile%\Desktop\work".

![img](assets/10-AkarRansomware/image198.png)

![img](assets/10-AkarRansomware/image199.png)
 
The p_f function scans files with specific extensions (e.g., .exe, .txt, .doc) encoded as Base64 combined with an encryption using xtea_encrypt, and renames them with the .hbbie extension.

![img](assets/10-AkarRansomware/image200.png)

---

### Decoding Process (flagg)

While the extension and files using xtea_encrypt and the note text using xxtea_encrypt, a reverse process of formula must be made. But first, the key will be needed to decode it.
Knowing the MD5 have the content in substring which was = “d1762555582b513f” we can brute force the key using the script crafted below:

```python
import hashlib, itertools, string

t, c = "d1762555582b513f", string.ascii_letters + string.digits
for l in range(10):
    for k in map(''.join, itertools.product(c, repeat=l)):
        print(f"Key: {k}, MD5: {(h:=hashlib.md5(k.encode()).hexdigest())}, Substring: {h[8:16]}")
```

Key was found with the number of `‘1777’`

![img](assets/10-AkarRansomware/image201.png)

Reversing the xxtea_encrypt:

![img](assets/10-AkarRansomware/image202.png)

Adding the key of ‘1777’ and checking the encrypted key:

![img](assets/10-AkarRansomware/image203.png)
 
The string flagg and the array was extracted from dotnet source code:

![img](assets/10-AkarRansomware/image204.png)
 
Calling the function call of xxtea_decrypt to decode with the key:

![img](assets/10-AkarRansomware/image205.png)

Using the key to decoded we will get the notes:

![img](assets/10-AkarRansomware/image206.png)

---

### Decoding Process (.hbbie)


To reverse the encrypted. Using reversing of xtea_encrypt instead of xxtea_encrypt, because the xxtea_decrypt was for notes(flagg) , extensions(array). Step below was encoded the .hbbie extension into base64:

![img](assets/10-AkarRansomware/image207.png)

Reversing the xtea_encrypt:

![img](assets/10-AkarRansomware/image208.png)

Assign variable:

![img](assets/10-AkarRansomware/image209.png)

Calling the function call of xtea_decrypt:

![img](assets/10-AkarRansomware/image210.png)

We get to see the content of flag.txt.hbbie into plaintext:

![img](assets/10-AkarRansomware/image211.png)
 
Full code of the decrypted:

```python
import base64
import hashlib

###FUNCTION CALL
def xtea_decrypt(data, xtea_key):
    decrypted = bytearray(data)
    for i in range(len(decrypted)):
        decrypted[i] -= 2
        decrypted[i] ^= xtea_key[i % len(xtea_key)]
    return decrypted

def xxtea_decrypt(data, key):
    decrypted = bytearray(data)
    for i in range(len(decrypted)):
        decrypted[i] ^= key[i % len(key)]
    return decrypted

##########################################################################################
###KEY
password = "1777"
print(f"KEY: {password}")

md5_hash = hashlib.md5(password.encode()).hexdigest()
print(f"MD5 hash: {md5_hash}")

key = md5_hash[28:].encode()
print(f"enc key: {key}")
##########################################################################################
###VARIABLE
flagg = ("DggFDhJtVkcSfFhEVxR7V1daGXFdWUlAXVlQQVdQGQwMCgc/ODkzexJVVBJgBAlmeQVtHwMDDgU/PjQ4"
         "c1hVEn1SGWtdQUsSYVFXQVtAUERXFH1TRlUZd1xXS0tCQFxWEnVXVhJwVkVcWFZTVlFdHD8+NDh7Whl9"
         "QFBcQBJAVhJ5UVxCEm1WR0AUaldcR1BGW0JcEnZVTVMSZ1hUVxR4XFYUa1dRW09XQBR/W15RShJrW0wS"
         "elVPVxJAVhJxW1dGU1dNEmdHFz84OTNmXUYDElpATUIIGxZXSkRAR0hODUVDRUBDWl5XHF1aUF1cOTNw"
         "ZncDEgF5d0V0VkpmCm1BfllbDlhhQwBVcwV0C3h3Y2ADQwFKXVw0OD8+R2FXV0xAW0BAEnhBSkYSdVcS"
         "e1hVR0FdVlwSVVdWEmRLW0RVWksSfkxBRhR4XF1AUVdAFHBeXkFKW11aRw==")

arr = ({"HEBBRg==","HFBWUQ==","HERdVA=="}) #array of the extension

flag = "VlpaV0tcUlNZbVxVSFlTb2BTT0NvVVhfX11YUQ==" #flag.txt.hbbie
##########################################################################################
###readme.txt###
decoded_flagg = base64.b64decode(flagg)
decrypted_flagg = xxtea_decrypt(decoded_flagg, key)
print(f"\nreadme.txt: \n{decrypted_flagg.decode('utf-8', errors='ignore')}\n") #note of flagg

##########################################################################################
#string[] array = new string[]
for encoded in arr:
    decoded = base64.b64decode(encoded)
    decrypted = xxtea_decrypt(decoded, key)
    print(f"extension: {decrypted.decode('utf-8', errors='ignore')}")


#flag.txt.hbbie
decoded_flag = base64.b64decode(flag)
decrypted_flag = xtea_decrypt(decoded_flag, key)
print(f"\nFlag (flag.txt.hbbie): {decrypted_flag.decode('utf-8', errors='ignore')}")
```

---

## IOCs

| **IOC**                                     | **Type**            |
|---------------------------------------------|---------------------|
| `e9b73bccd1762555582b513ff9d02492`          | Hash of Key         |
| `1777`                                      | Key                 |
| `hxxp[://]expyuzz4wqqyqhjn[.]onion`         | URL                 |
| `3MNwFbsT8YxLko7jSw9gA1M9JCZR1w8xoh`        | BTC                 |

---

## Additional Notes

- **What is the key to run this Ransomware?**  
  `1777`
- **Provide the kill-switch string that can prevent this Ransomware from executing.**  
  `da2607bg`
- **What is the encryption key?**  
  `2492`
- **Provide the persona or the threat group name for this Ransomware.**  
  `R00TK1T-1777`
- **Provide TOR onion URL link found in the Ransomware.**  
  `hxxp[://]expyuzz4wqqyqhjn[.]onion`
- **Provide BTC address of the Ransomware operator.**  
  `3MNwFbsT8YxLko7jSw9gA1M9JCZR1w8xoh`
- **Decrypt the file and retrieve the flag.**  
  `flag{nice_catch_lets_gooooo}`
