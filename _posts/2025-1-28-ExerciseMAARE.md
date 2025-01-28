---
title: "Assembly Exercise"
date: 2025-1-28
categories: [Assembly,Malware-Analysis-and-Reversing-Workshop]
tags: [Assembly,Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

## Executive Summary

An Exercise to bypass the cmp and get the flag. Using Patching method was the most convenient for me.

---

## Sample information

| **Attribute**         | **Value**                                                                                      |
|-----------------------|------------------------------------------------------------------------------------------------|
|File name	| exercise1.exe |
|File size	| 400 KB |
|File type	| Application Executable (EXE) |
|MD5 |	9427e326732b6c4b674229e9ebcf2a34 |
|SHA1	| 3cc42b5dfdd4b49d63fc1d5d0ccc45796df498e4 |

---

## Case Specific Requirements

### Machine
- **Environment**: Windows

### Tools Used
- **IDA**

---

## Static Analysis

While running nothing happen it only show like image below:

![img](assets/13-Exercise/image226.png)

This program checks if the computer's hostname is `"DESKTOP-TRAINING"`. If it is, it prompts the user to enter a password. If the password matches the predefined value `"awesome_training@1337"`, it performs a simple XOR operation on an array of data and prints the result. If the password is incorrect or the hostname doesn't match, the program exits with an error message. The program also handles errors in retrieving the computer's hostname.

![img](assets/13-Exercise/image227.png)

My trick, instead of bypassing the password check and desktop, we can jump rightaway to the mysterious encryption:

![img](assets/13-Exercise/image228.png)

Clicking on the initial `jump if zero (jz)` address:

![img](assets/13-Exercise/image229.png)

Goto `Edit>Path Program>Assemble`

![img](assets/13-Exercise/image230.png)

Change the initial address:

![img](assets/13-Exercise/image231.png)

Into `jump not zero(jnz)` and the address:

![img](assets/13-Exercise/image232.png)

Now we can see the line taking changes:

![img](assets/13-Exercise/image233.png)
 
Now Goto `Edit>Patch program>Apply patches to input file…`

![img](assets/13-Exercise/image234.png)
 
It will pop something like this below, just hit `‘ok’`:

![img](assets/13-Exercise/image235.png)
 
Run the file and we get the flag:

![img](assets/13-Exercise/image236.png)

---

### Additional Notes

- **Password for the Challenge**: `awesome_training@1337`

- **Flag**: `flag{n1c3_on3_r3vers3r_k33p_1t_up}`



