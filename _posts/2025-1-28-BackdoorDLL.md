---
title: "Backdoor DLL"
date: 2025-1-28
categories: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
tags: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

## Executive Summary

**Backdoor.dll** sets up a reverse shell that connects to a remote server, listens for incoming commands, and executes them on the infected machine. It uses standard Windows networking APIs (Winsock) and process creation functions to facilitate the remote execution of arbitrary commands. This type of behavior is typical of a backdoor or remote access Trojan (RAT).

---

## Case Details

### Sample information

| **Attribute**         | **Value**                                                                                      |
|-----------------------|------------------------------------------------------------------------------------------------|
|File name	| `backdoor.dll` |
|File size	| `160 KB` |
|File type	| `Application Extension (DLL)` |
|MD5 |	`290934c61de9176ad682ffdd65f0a669` |
|SHA1	| `a4b35de71ca20fe776dc72d12fb2886736f43c22` |
|SHA256 |	`f50e42c8dfaab649bde0398867e930b86c2a599e8db83b8260393082268f2dba` |
|Packer / compiler info	| `dynamic-link-library` |
|Compile time	 | `Sun Dec 19 16:16:38 2010 (UTC)` |

---

## Case-Specific Requirements

### **Environment**
- **Operating System:** Windows

### **Tools Used**
- **IDA**  

---

## Static Analysis

Using **IDA** to load the dll.

![img](assets/12-BackdoorDLL/image219.png)

The malware checks for a `mutex` to ensure that only one instance of the malware runs at a time. 

![img](assets/12-BackdoorDLL/image220.png)

If the mutex is not found, it creates it using `CreateMutexA`. While checking the name of the mutex was `“SADFHUHF”`.

![img](assets/12-BackdoorDLL/image221.png)
 
The malware connects to the remote by using the `socket()` function and establishes a connection with the remote server using `connect()`. 

![img](assets/12-BackdoorDLL/image222.png)

The IP address `127.26.152.13`. while port was not assign, default port was `‘80’`

![img](assets/12-BackdoorDLL/image223.png)
 
The malware terminates when it receives the command `q` from the remote server. This command prompts the program to close the connection and exit.

![img](assets/12-BackdoorDLL/image224.png)

When the `sleep(60000)` command is received, the malware will sleep for `60000 milliseconds` which euqivalent to `6.55 minutes`.

![img](assets/12-BackdoorDLL/image225.png)

The prefix string exec causes the malware to execute arbitrary commands on the infected machine. When the malware receives a command starting with `exec`, it uses `CreateProcessA` to run the specified command on the system.

---

## IOCs
| IOC                        | Type        |
|----------------------------|-------------|
| 127.26.152.13:80           | IP:PORT     |

---

##	 Additional Notes

- **What is the name of the mutex used by the malware?**
  - `SADFHUHF`

- **What is the IP address and port the malware connects to?**
  - `127[.]26[.]152[.]13[:]80`
  
- **What is the command that causes the malware to terminate?**
  - `q`
  
- **What is the command that causes the malware to sleep, and how many minutes will it sleep?**
  - `Sleep:60000 | sleep:6.55min`
  
- **What is the prefix string causing the malware to be able to execute arbitarary command line?**
  - `exec`


