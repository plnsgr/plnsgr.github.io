---
title: "Backdoor SRVCP"
date: 2025-1-28
categories: [Malware Analysis]
tags: [Malware Analysis]
---


## Executive Summary

A malicious program named "srvcp.exe" performs backdoor activities while hiding its presence and execution. A registry entry adds data with the key "srvcp.exe" under the `CurrentVersion\Run` key, suggesting persistent execution.

---

## Case Details

### Sample Information

| **Attribute**       | **Details**                                   |
|---------------------|-----------------------------------------------|
| **File name**       | Backdoor.exe.bin                             |
| **File size**       | 29 KB                                        |
| **File type**       | Application Execution (EXE)                  |
| **MD5**             | e9fe9148a69a1b8f70996435787609c3             |
| **SHA1**            | 8679002da8a6b0d31abbe61e273ff1b48a6d9a2b     |
| **SHA256**          | 9de606047ae141a872a7ddb78782fc8a8da5518e879b2239ec931560b7983ba8 |
| **Compile time**    | `compiler-stamp, Fri Apr 28 06:26:11 2000 | UTC` |

---

### Case Specific Requirements

- **Machine**:  
  - Windows Environment  

- **Tools Used**:  
  - Detect It Easy  
  - PEStudio  
  - IDA  
  - Python  
  - Floss  
  - FakeNet  
  - APILogger  
  - ApiMonitor  
  - Diffview  
  - Process Hacker  
  - EventViewer  

---

## Static Analysis

Using **Detect It Easy (DIE)**, the file type appears as a compiler of LCC-Win32 with GUI32.  

![img1](assets/8-Backdoor/image118.png)

After using DIE, flags were checked with **PEStudio** to locate the entry point and identify suspicious libraries for further dynamic analysis.  

![img2](assets/8-Backdoor/image119.png)

- **Entry point**: `0x0011CB`

![img](assets/8-Backdoor/image120.png)

- **IDA Analysis**:  
  - The program starts at the exact entry point address.
 
  ![img](assets/8-Backdoor/image121.png)  

  - Parameters are sent into `sub_4013F0` and then to `sub_4012C6`.
 
  ![img](assets/8-Backdoor/image122.png)  

#### Observations:
- At line 36, `RegOpenKeyExA` adds the key in `HKEY_LOCAL_MACHINE` if not present.

![img](assets/8-Backdoor/image123.png)  

- Seven gibberish parameters and three additional ones (`Str`, `String1`, and `buf`) are passed to `sub_4012C6`.

![img](assets/8-Backdoor/image124.png)  

![img](assets/8-Backdoor/image125.png)  

- Variables are encoded using mathematical operations, with decoding later handled in `sub_405608`.

![img](assets/8-Backdoor/image126.png)  

#### Decoding Script:

```python
def sub_4012C6(a1):
    v1 = len(a1)
    ra1 = ""
    for i in range(v1):
        v5 = ord(a1[i])
        v5 ^= (v1 - i) % 30
        ra1 += chr(v5)
    return ra1

data = [
    "nhl*pwf",  # 0 -> gus.ini
    "|ahkl",    # 1 -> mikey
    "wtwgr",    # 2 -> setpr
    "|cdkk",    # 3 -> jiggy
    "mfqEce",   # 4 -> daFuck
    "~h`PmfqEce",  # 5 -> daFuckWhat
    "v}~y{*%mj&qldkg",  # 6 -> fight me, pussy
    "'98;6",     # 7 -> 79;=
    "O_ATU@VDE@",  # 8 -> AGGRESSIVE
]

buf = [
    '\x11', '`', '9', 'a', '7', 'n', '5', 'c', '3', 'd', '1', 'e', '/', 'z', '-', '\x7F',
    '+', 'x', ')', 'y', '\'', 'v', '%', 'k', '#', 'l', '!', 'm', '=', 'p', ';', 'q',
    '9', 'r', '7', '\x7F', '5', '|', '3', 'u', '1', 'v', '/', 'k', '-', 'h', '+',
    'i', ')', 'j', '\'', 'g', '%', 'J', 'L', 'Q', 'H'
]

decoded_strings = [sub_4012C6(s)[::-1] for s in data]
decoded_buf = sub_4012C6(buf)[::-1]
parent = "HKCU"
sub_key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

print(f"Registry Path: {parent}\\{sub_key}\n")
for i, value in enumerate(decoded_strings):
    print(f"Encoded :  '{data[i]}' : \t{value}")

print(f"buf: {decoded_buf}")
print(f"Registry Path: {parent}\\{sub_key}\n")
for i, value in enumerate(decoded_strings):
    print(f"Encoded :  '{data[i]}' : \t{value}")

print(f"buf: {decoded_buf}")
```

The image below will show what the script above will print out look like:

![img](assets/8-Backdoor/image128.png)  
 
Another entrance function call was Start Address created a Thread:

![img](assets/8-Backdoor/image129.png)

![img](assets/8-Backdoor/image130.png)  
 
At line 127, variable v41 will send the v6 after the if else condition meets the requirement of j==58 or not.

![img](assets/8-Backdoor/image131.png)  

Entering the Sub_404CB1 will return the strings functions:

![img](assets/8-Backdoor/image132.png)  

Checking the .idata of each array returns the image above (sub_404CB1) to the v41.
 
![img](assets/8-Backdoor/image133.png)  
 
On the function call of sub_404195 Calling the FileName and Commandline:

![img](assets/8-Backdoor/image134.png)  

.idata of FileName[]

![img](assets/8-Backdoor/image135.png)  

Sub_40121B of the CommandLine parameter send:

![img](assets/8-Backdoor/image136.png) 

.idata of CommandLine[]

![img](assets/8-Backdoor/image137.png)  

Sub_403BDB will call other strings:

![img](assets/8-Backdoor/image138.png) 

Similar to previous steps, go through the .data to see the strings.

![img](assets/8-Backdoor/image139.png)  

After going through of IDA, Another quick method to extract all available strings can be made using Floss:

![img](assets/8-Backdoor/image140.png)  

Checking the available strings:

![img](assets/8-Backdoor/image141.png)  

![img](assets/8-Backdoor/image142.png)  

The auto decodes of the previous python able to receive some of the encoded strings. With the URI and port number:

![img](assets/8-Backdoor/image143.png)  

---

## Dynamic Analysis

Using **PEStudio**, the file flags `Write` and `Execute` permissions. 

![img](assets/8-Backdoor/image144.png)

Suspicious libraries include `WS2_32.dll` and `wsock32.dll`.  

![img](assets/8-Backdoor/image145.png)

Flags on imports section:

![img](assets/8-Backdoor/image146.png)

### Observations:
- **Network Traffic**:  
  - **FakeNet** revealed connection attempts to C2.

  ![img](assets/8-Backdoor/image147.png)
  
- **Registry Changes**:  
  - Verified with **Diffview**.
  
  ![img](assets/8-Backdoor/image150.png)

- **API Calls**:  
  - Monitored using **ApiLogger**
  
  ![img](assets/8-Backdoor/image148.png)
  
  - Monitored using **APIMonitorx86**
  
  ![img](assets/8-Backdoor/image149.png)


Additional inspection using **Process Hacker** showed activity with `\Device\Afd` during connection attempts.  

![img](assets/8-Backdoor/image151.png)

Reading the Memories was able to display similar to static analysis decoded.

![img](assets/8-Backdoor/image152.png)

EventViewer revealed no successful C2 connections.

![img](assets/8-Backdoor/image153.png)

---

## IOCs (Indicators of Compromise)

| **IOC**                                | **Type**             |
|----------------------------------------|----------------------|
| `Irc[.]mcs[.]net:6667`                 | URL                  |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Registry           |
| `gus.ini`                              | String               |
| `srvcp.exe`                            | String               |
| `Service Profiler`                     | String               |
| `ftp -s:c:\flog`                       | String               |
| `c:\flog`                              | Directory            |
| `mikey`                                | String               |
