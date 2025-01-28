---
title: "Bubar Parlimen"
date: 2025-1-28
categories: [Malware Analysis]
tags: [Malware Analysis]
---

## Executive Summary

The provided VBA code contains a malicious macro that leverages Windows API functions like `LoadLibrary`, `GetProcAddress`, and `CallWindowProc` to execute encoded payloads. It defines functions to decode Base64-encoded data and dynamically loads additional binary components using the `ADODB.Stream` object. The payload appears embedded in the code as a long Base64 string and is processed during the `Document_Open` event, suggesting that it executes automatically upon opening the document. This behavior indicates it is likely intended for malicious purposes, such as downloading or executing additional payloads.

---

## Case Details

### **Sample Information**

| **Attribute**         | **Value**                                                                                      |
|-----------------------|------------------------------------------------------------------------------------------------|
| **File Name**         | `bubarparlimen.docx`                                                                           |
| **File Size**         | 215 KB                                                                                         |
| **File Type**         | Microsoft Office Word Document (DOCX)                                                          |
| **MD5**               | `afbe00e755a2cf963f0eedbb4e310198`                                                             |
| **SHA1**              | `a55bd3f15ce743c9cda7bec05afe50b9aefa4683`                                                     |
| **SHA256**            | `ab541df861c6045a17006969dac074a7d300c0a8edd0a5815c8b871b62ecdda7`                             |
|-----------------------|------------------------------------------------------------------------------------------------|
| **File Name**         | `RemoteLoad.dotm   `                                                                           |
| **File Size**         | 24 KB                                                                                          |
| **File Type**         | Microsoft Office Word Macro-Enabled Template (DOTM)                                            |
| **MD5**               | `8114e5e15d4086843cf33e3fca7c945b`                                                             |
| **SHA1**              | `5f7f0b1419448c5fe1a8051ac8cb2cf7b95a3ffa`                                                     |
| **SHA256**            | `145daf50aefb7beec32556fd011e10c9eaa71e356649edfce4404409c1e8fa30`                             |

---

## Case-Specific Requirements

### **Environment**
- **Operating System:** Windows

### **Tools Used**
- **OLEDUMP**  
- **OLEVBA**  

---

## Static Analysis

Open the `.docx` as archive and go into `word\_rels\settings.xml.rels`. 

![img1](assets/2-BubarParlimen/image6.png)

Document of `settings.xml.rels` may be designed to load or use an external template from an online source which is the URL points to a file on GitHub. It could be indicative of the document attempting to fetch and execute content from that URL.

![img2](assets/2-BubarParlimen/image7.png)

![img3](assets/2-BubarParlimen/image8.png)

The file `RemoteLoad.dotm` was analyzed using `oledump.py`, revealing the presence of embedded VBA macros in the document. The macros are stored within `word/vbaProject.bin`, indicating potential malicious functionality.
Stream list:
-	A1 (PROJECT): Metadata related to the VBA project.
-	A2 (PROJECTwm): Additional metadata for project window manager settings.
-	A3 (VBA/ThisDocument): Contains the main VBA macro script associated with the document's behavior.
-	A4 (VBA/_VBA_PROJECT): Internal configuration or references for the VBA project.
-	A5 (VBA/dir): Directory structure of the VBA project, including references to other streams or modules.

The presence of the M flag for A3 (VBA/ThisDocument) indicates that the macro is active and likely contains the primary logic for executing malicious tasks, such as downloading and executing files as observed in the sample behavior. The structure suggests a well-defined VBA project crafted for automation

1.	Windows API Declarations:
-	`FreeLibrary`, `LoadLibrary`, `GetProcAddress`, and `CallWindowProc` functions are declared using kernel32 and user32 libraries for dynamic library manipulation.

![img4](assets/2-BubarParlimen/image9.png)

2.	Constants for Bit Masks and Powers:
-	Several constants like `clOneMask`, `clHighMask`, `cl2Exp6`, etc., are defined to manipulate and extract specific bits.

![img5](assets/2-BubarParlimen/image10.png)

3.	MyDecode and AES Function:
-	Replaces custom encoded placeholders ("`uPCgt131`", "`Jc34DSga`") with Base64 padding characters (== and =), then decodes using AES. Converts Base64-encoded strings to their decoded form using byte-level operations and bit masks.

![img6](assets/2-BubarParlimen/image11.png)

Additional decoded:

![img7](assets/2-BubarParlimen/image12.png)

![img8](assets/2-BubarParlimen/image13.png)

4.	Document_Open Event:
-	Executes automatically when the document is opened and then constructs a large encoded string (`lgstr`), decodes it, and saves it to a temporary file in the PUBLIC directory.

![img9](assets/2-BubarParlimen/image14.png)

![img10](assets/2-BubarParlimen/image15.png)

![img11](assets/2-BubarParlimen/image16.png)

5.	Use of External Libraries and Objects:
-	Uses `Microsoft.XMLDOM` and `ADODB.Stream` to handle encoded data and save it as a file.

![img12](assets/2-BubarParlimen/image17.png)

6.	Encoded Payload:
-	Large Base64 string (`lgstr`) is embedded, representing a binary file or script likely executed later.

![img13](assets/2-BubarParlimen/image18.png)

- The extracted decode file from base64 found that it was PE32 executable for MS Windows of dll program.

![img14](assets/2-BubarParlimen/image19.png)

- Checking the hash to `Virustotal`

![img15](assets/2-BubarParlimen/image20.png)

7.	File Write Operations:
-	The decoded content from lgstr is saved to a temporary file sl1.tmp and sl2.tmp.

![img16](assets/2-BubarParlimen/image21.png)

![img17](assets/2-BubarParlimen/image22.png)


---

## Indicators of Compromise (IOCs)

## Indicators of Compromise (IOCs)

| **IOC**                                                | **Type**                 |
|--------------------------------------------------------|--------------------------|
| `Wininet.dll`                                          | Executable File Name     |
| `Urlmon.dll`                                           | Executable File Name     |
| `utfc.dll`                                             | Executable File Name     |
| `KERNEL32.dll`                                         | Executable File Name     |
| `UrlDownloadToFile.dll`                                | Executable File Name     |
| `LogiMail.dll`                                         | Executable File Name     |
| `LogiMailApp.exe`                                      | Executable File Name     |
| `\Microsoft\Office\LogiMail.dll`                      | Registry                 |
| `\Microsoft\Office\LogiMailApp.exe`                   | Registry                 |
| `hxxps[://]armybar[.]hopto[.]org/LogiMail[.]dll`       | URL                      |
| `hxxps[://]armybar[.]hopto[.]org/LogiMailApp[.]exe`    | URL                      |
| `925f404b0207055f2a524d9825c48aa511199da95120ed7aafa52d3f7594b0c9` | Hash (SHA256)           |
| `ccbdda7217ba439dfb6bbc6c3bd594f8`                    | Hash (MD5)               |
| `610919bfae5a4e5fa7ca150a17c6f03659a43fd8`            | Hash (SHA1)              |


---

## Additional Notes

- **Domain Name of the C2 Infrastructure:**  
  `hxxps[://]armybar[.]hopto[.]org/`

- **Auto-Execution Function:**  
  `Document_Open`

- **Base64-Decoded Path for Malicious DLL:**  
  `LogiMail.dll`

- **URL for Downloading Malicious Executable:**  
  `hxxps[://]armybar[.]hopto[.]org/LogiMailApp[.]exe`

- **Function Used to Execute the Downloaded File:**  
  `CreateObject`

- **Function Used to Decode Base64 Strings:**  
  `AES`
