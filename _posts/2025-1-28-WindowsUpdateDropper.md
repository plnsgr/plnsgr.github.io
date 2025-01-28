---
title: "Windows Update Dropper"
date: 2025-1-28
categories: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
tags: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

## Executive Summary

The malware **"WindowsUpdate.exe"** is designed to establish persistence on the system, communicate with a command and control (C2) server, and execute system commands. It ensures it runs at startup by creating a registry entry, connects to a remote server to receive instructions, and spawns additional processes like cmd.exe to perform its tasks. It also creates directories and executes commands to check connectivity, indicating its capability to maintain control and perform actions remotely.

---

## Case Details

### Sample Information

| **Attribute**         | **Value**                                                                                         |
|-----------------------|-------------------------------------------------------------------------------------------------|
| **File Name**         | Windowsupdate.exe                                                                 |
| **File Size**         | 82 KB                                                                                           |
| **File Type**         | Application (EXE)                                                                               |
| **MD5**               | ef5be9083b7eaf2afe65513284add844                                                                |
| **SHA1**              | 8ee0f896e8bee3439e55ff9400c23c466bea6f36                                                        |
| **SHA256**            | d50a686e8551dc2f366a4318bc604e9661fb2f6d60a978562ae1bf36543b7c6f                             |
| **Compile-time**      | Sat Jan 18 06:31:26 2025 (UTC) |

---

### Case-Specific Requirements

- **Machine**  
  Windows Environment

- **Tools Used**
  - IDA
  - X32dbg
  - Diffview
  - ProcMon
  - Wireshark

---

## Static Analysis

Initial program (main func) 5 function was called with separate functionality:

![Static Analysis Function Call](assets/6-WindowsUpdateDropper/image84.png)

1. runPingcommand:
   
   ![runPingcommand](assets/6-WindowsUpdateDropper/image85.png)

2. createFolderAndCopySelf:
   
   ![createFolderAndCopySelf](assets/6-WindowsUpdateDropper/image86.png)

3. createRegistryRunEntry:
   
   ![createRegistryRunEntry](assets/6-WindowsUpdateDropper/image87.png)

4. openShellConnection:
   
   ![openShellConnection](assets/6-WindowsUpdateDropper/image88.png)

Utilizing the x32dbg to check the strings inside memory

![x32dbg Strings](assets/6-WindowsUpdateDropper/image89.png)

---

## Dynamic Analysis

While performing analysis using **DiffView**, the malware creates a mini process of `cmd.exe` and `pings google[.]com`.

![Diffview](assets/6-WindowsUpdateDropper/image90.png)

Looking forward to any created file location and found it was saved in `Public\personal` folder.

![Diffview1](assets/6-WindowsUpdateDropper/image91.png)

Confirming the Directory:

![Directory1](assets/6-WindowsUpdateDropper/image92.png)

Checking the Registry:

![Registry Location](assets/6-WindowsUpdateDropper/image93.png)

The **ProcMon** also detected the registry created in the CurrentVersion\Run.

![ProcMon](assets/6-WindowsUpdateDropper/image94.png)

Head into the `Registry Editor (Regedit)`, and the file was present inside of it with the folder created by malware.

![Registry Location1](assets/6-WindowsUpdateDropper/image95.png)

In ProcMon, the TCP can also be seen as it tries to reconnect and disconnect from port 4444.

![ProcMon1](assets/6-WindowsUpdateDropper/image96.png)

Checking the IP address on Wireshark to confirm the connection itself.

![Wireshark Connection](assets/6-WindowsUpdateDropper/image97.png)

---

## Indicators of Compromise (IOCs)

| **IOC**                                              | **Type** |
|------------------------------------------------------|----------|
| 188[.]127[.]247[.]130:4444                           | IP:Port |
| HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateProgram | Registry |

---

## Additional Notes

- **Full command executed by the malware:**  
  `ping -n 1 google.com >nul 2>&1`

- **Full path, including the filename, of the malware being copied:**  
  `C:\Users\Public\personal\windowsupdate.exe`

- **Registry value name created by the malware for the persistence mechanism:**  
  `Software\Microsoft\Windows\CurrentVersion\Run`  
  `WindowsUpdateProgram`

- **IP address and port number of the C2 server that the malware is attempting to connect to:**  
  `188.127.247.130:4444`

- **Windows API function used by the malware to create a new folder:**  
  `CreateDirectory`

- **Process created by the malware after it connects to the C2 server:**  
  `cmd.exe`

- **Windows API function used to establish the connection to the C2 server:**  
  `WSAConnect`
