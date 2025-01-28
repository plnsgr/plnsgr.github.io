---
title: "SnakeKeylogger"
date: 2025-1-28
categories: [Malware Analysis]
tags: [Malware Analysis]
---

## Executive Summary

## Case Details
| Sample information: | 
|---|
File Name |
File Size |
File Type |
MD5 |
SHA1 |
SHA256 |
|---|

## Case Specific Requirements
> Machine
> Tools uses

## Static Analysis
While using OLEVBA, the Macro was present in this docm and the code was shown.
![img1](assets/1-SnakeKeylogger/image2.png)
The code was designed to execute upon opening a document on the AutoOpen, automates downloading and executing a file. It retrieves an executable file `nawBVBlSWH7iu7T.scr` from a specified URL using HTTP requests and saves it to the `C:\ProgramData` directory. If the file is successfully downloaded, it is executed immediately. The script employs `WinHttp.WinHttpRequest` for downloading and `ADODB.Stream` for saving the file, which is a common technique in malware delivery via macros.

## Dynamic Analysis
Open the `Wireshark` to check if any connection was found, and the C2 was shown.
![img2](assets/1-SnakeKeylogger/image3.png)
Alternative was to `Fakenet` and the result also display the C2 and also the GET request
![img3](assets/1-SnakeKeylogger/image4.png)
The program will save to `C:\ProgramData\nawBVBlSWH7iu7T.scr`
![img4](assets/1-SnakeKeylogger/image5.png)

## IOC
| IOC: | 
|---|
hxxp[://]52575815-38-20200406120634[.]webstarterz[.]com/nawBVBlSWH7iu7T[.]scr | URL
C:\ProgramData\nawBVBlSWH7iu7T.scr | Excutable Path
|---|

## Additional Notes
Full path of the downloaded executable include File name
•	hxxp[://]52575815-38-20200406120634[.]webstarterz[.]com/nawBVBlSWH7iu7T[.]scr|
Auto-execution function used in the malicious document to automatically execute the malicious code
•	AutoOpen|
HTTP method is used
•	GET|
COM object is used to handle binary data and save the downloaded file
•	ADODB.Stream|
Object is used to send HTTP requests
•	WinHttp.WinHttpRequest.5.1|
