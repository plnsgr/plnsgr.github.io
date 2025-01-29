---
title: "Dropper Dynamic"
date: 2025-1-30
categories: [Malware Analysis, Malware-Analysis-and-Reversing-Workshop]
tags: [Malware Analysis, Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

## Executive Summary

The executable file `dropper.exe` shows behaviors typically associated with dropper malware. It retrieves the system directory path, constructs a path to a target file (`wupdmg.exe`) in the `System32` directory, and generates a new path for a file (`winup.exe`) in the temporary directory. The malware attempts to move the target file from its original location to the temporary directory, possibly to evade detection. These activities suggest preparations for further malicious actions.

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

### Case Specific Requirements

- **Machine**: Windows Environment  
- **Tools Used**:  
    - IDA  
    - ApiMonitor  
    - Floss  
    - Resource Hacker  

---

## Static Analysis

The following analysis was conducted using **IDA** starting with the main function:

1. The main function dynamically loads `psapi.dll` and retrieves function pointers for `EnumProcesses`, `EnumProcessModules`, and `GetModuleBaseNameA`. It then enumerates all running processes, checking each one using `sub_401000`.

   ![img](assets/14-Dropper-Dynamic/image1.png)

2. If a matching process is found, it attempts to inject a remote thread using `sub_401174`.

   ![img](assets/14-Dropper-Dynamic/image2.png)

3. If the injection is successful, it moves `wupdmgr.exe` to a temporary directory and calls `sub_4011FC` to execute the resource. The function handles errors by checking the return values of critical API calls.

   ![img](assets/14-Dropper-Dynamic/image3.png)

4. `sub_401000` checks whether a given process ID matches `winlogon.exe`. It opens the process and compares its name to `winlogon.exe`. If the process name matches, it returns success; otherwise, it returns failure.

   ![img](assets/14-Dropper-Dynamic/image4.png)

5. `sub_4010FC` enables a specified privilege for the current process token. It retrieves the token handle and uses `AdjustTokenPrivileges` to apply the privilege.

   ![img](assets/14-Dropper-Dynamic/image5.png)

6. `sub_401174` attempts to inject a remote thread into a specified process by enabling `SeDebugPrivilege`, loading `sfc_os.dll`, and using `CreateRemoteThread`.

   ![img](assets/14-Dropper-Dynamic/image6.png)

7. In the main function, if `sub_401174` with the `v11` parameter does not exist, it returns 1 and proceeds with another operation. This operation constructs paths for `wupdmgr.exe` and `winup.exe` in the system and temporary directories, respectively, then moves `wupdmgr.exe` from the system directory to the temporary directory as `winup.exe`.

   ![img](assets/14-Dropper-Dynamic/image7.png)

Additionally, using **Floss**, a mysterious URL was discovered that wasn't visible during the **IDA** analysis.

   ![img](assets/14-Dropper-Dynamic/image8.png)

   ![img](assets/14-Dropper-Dynamic/image9.png)

The URL was located using **Resource Hacker**.

   ![img](assets/14-Dropper-Dynamic/image10.png)

---

## Dynamic Analysis

Using **ApiMonitor**, running `dropper.exe` reveals the following behavior:

1. It loads `psapi.dll` after the DllMain function.

   ![img](assets/14-Dropper-Dynamic/image11.png)

2. The executable performs actions like enumerating processes (`EnumProcesses`), retrieving module names (`GetModuleBaseNameA`), and attempting to access processes like `winlogon.exe` using `OpenProcess`. However, access to `winlogon.exe` is denied due to insufficient permissions, as indicated by `"Access is denied"` errors.

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

- **Variables in the main function**: `14`
- **Library loaded at runtime**: `psapi.dll`
- **3rd WinAPI resolved from psapi.dll**: `EnumProcesses`
- **Process the malware checks for existence**: `winlogon.exe`
- **Second library loaded at runtime**: `sfc_os.dll`
- **Original filename moved to the temporary folder**: `wupdmgr.exe`
- **MD5 of dropped file in system32 folder**: `6a95c2f88e0c09a91d69ffb98bc6fce8`
- **Windows API used to execute the dropped file**: `WinExec`
- **Full URL requested by malware**: `hxxp[://]www[.]practicalmalwareanalysis[.]com/updater[.]exe`
