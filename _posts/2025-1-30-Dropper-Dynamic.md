---
title: "Dropper Dynamic"
date: 2025-1-30
categories: [Malware Analysis, Malware-Analysis-and-Reversing-Workshop]
tags: [Malware Analysis, Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

## Executive Summary

The executable file `dropper.exe` exhibits behaviors typically associated with dropper malware. The malware retrieves the system directory path, constructs a path to a target file (`wupdmg.exe`) in the `System32` directory, and generates a new path for a file (`winup.exe`) in the temporary directory. It then attempts to move the target file from its original location to the temporary directory, suggesting an attempt to conceal or relocate the file to evade detection. These activities are indicative of a preparation for further malicious actions.

---

## Case Details

### Sample Information

| **Attribute**           | **Value**                                                           |
|-------------------------|---------------------------------------------------------------------|
| **File Name**           | `dropper.exe.bin`                                                   |
| **File Size**           | `36 KB`                                                             |
| **File Type**           | `Application Executable (EXE)`                                      |
| **MD5**                 | `625ac05fd47adc3c63700c3b30de79ab`                                  |
| **SHA1**                | `9369d80106dd245938996e245340a3c6f17587fe`                          |
| **SHA256**              | `0fa1498340fca6c562cfa389ad3e93395f44c72fd128d7ba08579a69aaf3b126`  |
| **Compile Time**        | `Fri Aug 30 22:26:59 2019 (UTC)`                                    |

---

### **Case Specific Requirements**

- **Machine**: Windows Environment  
- **Tools Used**:  
    - IDA  
    - ApiMonitor  
    - Floss  
    - Resource Hacker  

---

## Static Analysis

Using **IDA** and beginning with the main function, the program follows these key steps:

1. Using **IDA** and starting with the main function. The main function orchestrates the execution flow. It begins by dynamically loading `psapi.dll` and retrieving function pointers for `EnumProcesses`, `EnumProcessModules`, and `GetModuleBaseNameA`. It then enumerates all running processes, checking each process using `sub_401000`. 

![img](assets/14-Dropper-Dynamic/image1.png)

2. If a matching process is found, it attempts to inject a remote thread using `sub_401174`.

![img](assets/14-Dropper-Dynamic/image2.png)

3. If successful, it moves `wupdmgr.exe` to a temporary directory and calls `sub_4011FC` to execute the resource. The function ensures error handling by checking the return values of critical API calls.

![img](assets/14-Dropper-Dynamic/image3.png)

4. Proceed with the function `sub_401000` is designed to check whether a given process ID belongs to `winlogon.exe`. It begins by initializing string buffers and opening the process with specific access rights. The function then retrieves the process name using function pointers `EnumProcessModules` and `GetModuleBaseNameA`. If the process name matches `winlogon.exe`, the function returns 1, indicating success; otherwise, it returns 0.

![img](assets/14-Dropper-Dynamic/image4.png)

5. The function `sub_4010FC` is responsible for enabling a specified privilege for the current process token. It retrieves the token handle using `OpenProcessToken`, then initializes a `_TOKEN_PRIVILEGES` structure to enable the privilege. The function attempts to look up the privilege value using `LookupPrivilegeValueA` and applies it with `AdjustTokenPrivileges`. 

![img](assets/14-Dropper-Dynamic/image5.png)

6. The function `sub_401174` attempts to inject a remote thread into a specified process. It first calls `sub_4010FC` to enable `SeDebugPrivilege`, then loads the `sfc_os.dll` library and retrieves an exported function at ordinal 2. The target process is opened with full access using `OpenProcess`, and if successful, a **remote thread** is created in that process using `CreateRemoteThread`.

![img](assets/14-Dropper-Dynamic/image6.png)

7. In **main** if `sub_401174` with the `v11` parameter not exist. It will return 1 and proceed another operation. This sequence of operations retrieves the Windows directory path and constructs the full path to `\system32\wupdmgr.exe`, then obtains the temporary directory path and constructs a new file path for `\winup.exe` within it. Finally, it moves `wupdmgr.exe` from the system directory to the temporary directory under the new name `winup.exe`.

![img](assets/14-Dropper-Dynamic/image7.png)

Using **Floss**, a mysterious URL was discovered that wasn't visible during the **IDA** analysis. 

![img](assets/14-Dropper-Dynamic/image8.png)

![img](assets/14-Dropper-Dynamic/image9.png)

Using **Resource Hacker** to locate the URL.

![img](assets/14-Dropper-Dynamic/image10.png)

---

## Dynamic Analysis

Using **ApiMonitor**, running `dropper.exe` initiates the following behavior:

1. It loads `psapi.dll` after the DllMain function.

![img](assets/14-Dropper-Dynamic/image11.png)

2. The executable performs actions like enumerating processes (`EnumProcesses`), retrieving module names (`GetModuleBaseNameA`), and attempting to access processes like `winlogon.exe` using `OpenProcess`. However, access to `winlogon.exe` is denied due to insufficient permissions, as indicated by `"Access is denied"` errors and invalid handle responses (0x00000005).

![img](assets/14-Dropper-Dynamic/image12.png)

---

## Indicators of Compromise (IOCs)

| **IOC**                                    | **Type**     |
|--------------------------------------------|--------------|
| hxxp[://]www[.]practicalmalwareanalysis[.]com/updater[.]exe | URL          |
| C:\WINDOWS\system32\wupdmgr.exe            | Path Directory |
| C:\WINDOWS\system32\wupdmgrd.exe           | Path Directory |
| winup.exe                                  | File         |

---

## Additional Notes

- **Variables in the main function**:
  `14` 
- **Library loaded at runtime**:
  `psapi.dll`
- **3rd WinAPI resolved from psapi.dll**:
  `EnumProcesses`
- **Process the malware checks for existence**:
  `winlogon.exe`
- **Second library loaded at runtime**:
  `sfc_os.dll`
- **Original filename moved to the temporary folder**:
  `wupdmgr.exe`
- **MD5 of dropped file in system32 folder**:
  `6a95c2f88e0c09a91d69ffb98bc6fce8`
- **Windows API used to execute the dropped file**:
  `WinExec`
- **Full URL requested by malware**:
  `hxxp[://]www[.]practicalmalwareanalysis[.]com/updater[.]exe`




