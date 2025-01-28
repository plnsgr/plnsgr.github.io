---
title: "SnakeKeylogger"
date: 2025-1-28
categories: [Malware Analysis]
tags: [Malware Analysis]
---

## Executive Summary

This document provides a detailed analysis of the SnakeKeylogger malware. Upon opening the malicious document, the macro executes automatically, downloads a file from a specified URL, saves it to the `C:\ProgramData` directory, and executes it. This behavior automates the delivery and execution of the malicious payload on the victim's system.

---

## Case Details

### **Sample Information**

| **Attribute**         | **Value**                                                                                         |
|-----------------------|-------------------------------------------------------------------------------------------------|
| **File Name**         | `715a3d7675672d8474b83bedfee8e594b96856fa34a915debf9ae57c171ee366.docm`                         |
| **File Size**         | 15.8 KB                                                                                        |
| **File Type**         | Microsoft Office Word Macro-Enabled Document (DOCM)                                            |
| **MD5**               | `9ce250e7dace223506f0d22240530bb6`                                                             |
| **SHA1**              | `24a87a2730fb3913369ae8f67ea459afc57976bd`                                                     |
| **SHA256**            | `715a3d7675672d8474b83bedfee8e594b96856fa34a915debf9ae57c171ee366`                             |

---

## Case-Specific Requirements

### **Environment**
- **Operating System:** Windows

### **Tools Used**
- **OLEVBA**  
- **Wireshark**  
- **Fakenet**

---

## Static Analysis

Using **OLEVBA**, it was observed that the macro present in the `.docm` file contains the following malicious code:

![img1](assets/1-SnakeKeylogger/image2.png)

The macro is programmed to execute upon opening the document using the `AutoOpen` function. It:
- Downloads an executable file `nawBVBlSWH7iu7T.scr` from a malicious URL.
- Saves it to the `C:\ProgramData` directory.
- Executes the downloaded file immediately.

### Key Observations:
- The script uses `WinHttp.WinHttpRequest` for HTTP requests.
- The `ADODB.Stream` object is utilized to save the downloaded file.

---

## Dynamic Analysis

### **Wireshark Analysis**
Using **Wireshark**, communication with the Command and Control (C2) server was identified. The captured traffic confirmed the malicious GET request to the C2 server:

![img2](assets/1-SnakeKeylogger/image3.png)

### **Fakenet Analysis**
With **Fakenet**, similar results were obtained. The tool detected the same C2 server and the GET request used by the malware to download the payload:

![img3](assets/1-SnakeKeylogger/image4.png)

### **File Location**
The malicious payload is saved to:

`C:\ProgramData\nawBVBlSWH7iu7T.scr`

![img4](assets/1-SnakeKeylogger/image5.png)

---

## Indicators of Compromise (IOCs)

| **Type**               | **Value**                                                                                         |
|-----------------------|-------------------------------------------------------------------------------------------------|
| **URL**               | `hxxp[://]52575815-38-20200406120634[.]webstarterz[.]com/nawBVBlSWH7iu7T[.]scr`                  |
| **Executable Path**   | `C:\ProgramData\nawBVBlSWH7iu7T.scr`                                                            |

---

## Additional Notes

### **Key Observations:**

- **Full Path of the Downloaded Executable:**  
  `hxxp[://]52575815-38-20200406120634[.]webstarterz[.]com/nawBVBlSWH7iu7T[.]scr`

- **Auto-Execution Function:**  
  `AutoOpen`

- **HTTP Method Used:**  
  `GET`

- **COM Objects Utilized:**
  - `ADODB.Stream` (to handle binary data and save the downloaded file)
  - `WinHttp.WinHttpRequest.5.1` (to send HTTP requests)
