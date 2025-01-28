---
title: "Assembly Exercise"
date: 2025-1-28
categories: [Assembly, Malware-Analysis-and-Reversing-Workshop]
tags: [Assembly, Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

# Executive Summary

This exercise demonstrates bypassing the `cmp` instruction to obtain the flag. The most efficient method I found was through patching.

---

## Sample Information

| **Attribute**       | **Value**                                                               |
|---------------------|-------------------------------------------------------------------------|
| **File Name**       | exercise1.exe                                                           |
| **File Size**       | 400 KB                                                                  |
| **File Type**       | Application Executable (EXE)                                           |
| **MD5**             | 9427e326732b6c4b674229e9ebcf2a34                                       |
| **SHA1**            | 3cc42b5dfdd4b49d63fc1d5d0ccc45796df498e4                               |

---

## Case-Specific Requirements

### Machine
- **Environment**: Windows

### Tools Used
- **IDA**

---

## Static Analysis

When the program is executed, it doesn't display much at first, as shown below:

![img](assets/13-Exercise/image226.png)

The program checks the computer's hostname. If it matches `"DESKTOP-TRAINING"`, it prompts the user for a password. If the password is `"awesome_training@1337"`, the program performs a simple XOR operation on an array of data and prints the result. If either the hostname doesn't match or the password is incorrect, the program exits with an error message. It also handles errors in retrieving the computer's hostname.

![img](assets/13-Exercise/image227.png)

Instead of bypassing the password check, I decided to jump directly to the encryption routine:

![img](assets/13-Exercise/image228.png)

By following the `jump if zero (jz)` address:

![img](assets/13-Exercise/image229.png)

Navigate to `Edit > Patch Program > Assemble`:

![img](assets/13-Exercise/image230.png)

Change the instruction at this address:

![img](assets/13-Exercise/image231.png)

To `jump not zero (jnz)` with the updated address:

![img](assets/13-Exercise/image232.png)

You’ll notice the program’s behavior has now changed:

![img](assets/13-Exercise/image233.png)

Now go to `Edit > Patch Program > Apply Patches to Input File…`:

![img](assets/13-Exercise/image234.png)

A confirmation dialog will appear—just click `OK`:

![img](assets/13-Exercise/image235.png)

Run the file again, and you'll see the flag:

![img](assets/13-Exercise/image236.png)

---

### Additional Notes

- **Password for the Challenge**: `awesome_training@1337`
- **Flag**: `flag{n1c3_on3_r3vers3r_k33p_1t_up}`
