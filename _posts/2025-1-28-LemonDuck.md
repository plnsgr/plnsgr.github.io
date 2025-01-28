---
title: "LemonDuck"
date: 2025-1-28
categories: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
tags: [Malware Analysis,Malware-Analysis-and-Reversing-Workshop]
---

## Executive Summary

A sophisticated powershell script attack leveraging scheduled tasks, WMI (Windows Management Instrumentation), and RSA encryption to maintain persistence on compromised systems. The script downloads an executable from a hardcoded URL, validates it using RSA, and executes it under hidden PowerShell commands. It creates and schedules tasks at regular intervals (every 60 or 120 minutes) to ensure continuous execution, often running with elevated privileges or SYSTEM account. Additionally, it interacts with WMI to execute commands, including obfuscated PowerShell scripts, and modifies system settings such as disabling compression via the Windows registry. The attack is persistent, with randomized task names and continuous re-execution, making it difficult to detect or remove without proper monitoring.

---

## Case Details

### **Sample Information**

| **Attribute**         | **Value**                                                                                      |
|-----------------------|------------------------------------------------------------------------------------------------|
| **File Name**         | `lemonduck_powershell.txt`                                                                     |
| **File Size**         | 18 KB                                                                                          |
| **File Type**         | Text Document (TXT)                                           |
| **MD5**               | `006d9997a8c148a8e962aaca7238a2ef`                                                             |
| **SHA1**              | `ae9aff7ac11edfce5c8974ad20411ce6cdde358`                                                     |
| **SHA256**            | `581f3802aa8be8ba749b626c93116fc2470a2fdbb56ef1cf39c20473356978e`                             |

---

## Case-Specific Requirements

### **Environment**
- **Operating System:** Windows

### **Tools Used**
- **PSUNVEIL**  
- **ProcMon**  
- **FakeNet**

---

## Static Analysis

Decode base64 to plaintext (Using PSUNVEIL)

![img1](assets/3-LemonDuck/image23.png)

Decode till the end point of the most readable text.

![img2](assets/3-LemonDuck/image24.png)

Dynamic Variable Initialization:
-	`$v='?rep_'+(Get-Date -Format 'yyyyMMdd')`: This sets the variable $v to a string that includes the current date, formatted as rep_yyyyMMdd.

![img3](assets/3-LemonDuck/image25.png)

Web Download and RSA Validation:
-	`$tmps`: This defines a PowerShell function a($u) that takes a URL as input and attempts to download data from it using Net.WebClient.

![img4](assets/3-LemonDuck/image26.png)

- DownloadData($u) retrieves the data from the URL and checks if the size is larger than 173 bytes. If it is, it verifies the data using RSA public key encryption and SHA-1 hash. If the data is valid, it executes the code.
-	RSA public key and Exponent: The script uses hardcoded RSA parameters to decrypt and verify downloaded data.
-	
![img5](assets/3-LemonDuck/image27.png)

Administrator Check:
-	`$sa=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")`: Checks if the script is running with administrative privileges.

![img6](assets/3-LemonDuck/image28.png)

Random String Generator Function:
-	getRan(): This function generates a random alphanumeric string with a length between 6 to 12 characters, based on random numbers and letters.

![img7](assets/3-LemonDuck/image29.png)

Task Scheduler:
-	The script creates tasks in Windows Task Scheduler using schtasks command. The goal is to establish persistence by creating scheduled tasks to run at regular intervals (every 120 minutes).

![img8](assets/3-LemonDuck/image30.png)

-	It tries to get an existing task with the name $uniq_name, and if it doesn't exist, it creates new scheduled tasks.

![img9](assets/3-LemonDuck/image31.png)

-	It uses schtasks /create /ru system /sc MINUTE /mo 120 /tn $uniq_name /F /tr "$uniq_name" to create tasks.


WMI (Windows Management Instrumentation) Event Subscription Persistence:
-	The script attempts to create WMI Event Filters and Consumers, which would trigger PowerShell scripts based on system events. It uses a __InstanceModificationEvent filter that monitors the Win32_PerfFormattedData_PerfOS_System class for any modifications.

![img10](assets/3-LemonDuck/image32.png)

-	If the event filter does not already exist, it creates a new event subscription and triggers the PowerShell code when the event occurs. It also uses Set-WmiInstance to bind the WMI filter to a command execution consumer, which would run a PowerShell script in response to system events.

![img11](assets/3-LemonDuck/image33.png)

Command Execution via WMI:
-	The script runs a PowerShell command in a hidden manner via WMI by creating a WMI consumer object that executes commands using cmd.exe with the PowerShell script embedded in the command line /c powershell -w hidden -c $wmicmd

![img12](assets/3-LemonDuck/image34.png)

Registry Manipulation:
-	The script attempts to modify a registry key : `(HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\DisableCompression)` . The registry above used to disable file compression, likely to prevent detection or ensure the integrity of files it might deploy.

![img13](assets/3-LemonDuck/image35.png)

URL Generation and Execution:
•	The URL is built dynamically: `hxxp[://]U1U2/a[.]jsp?v=rep_YYYYMMDD?COMPUTERNAME*USERNAME*UUID*RANDOM`. The URI and is intended to send the content to the C2 server

---

## Dynamic Analysis

Checking the Process Tree on the ProcMon and find out that the powershell will create another task.
 

Using `FakeNet` can see the GET request from domain:
 
Open up the `Task Scheduler`, get to see Task name of dmk8BpC with the Details section of powershell function running, need to export to see the full command.
 
Export:
 
Open as any Editor tools such as notepad but in these case uses `Notepad++`
 
Can see the powershell code execute command.
 
The another task will start the domain of `t[.]pp6r1[.]com` every `02:00:00`
 


---

## Indicators of Compromise (IOCs)

| **IOC**                                                                                   | **Type**              |
|-------------------------------------------------------------------------------------------|-----------------------|
| `t[.]pp6r1[.]com`                                                                         | URL                   |
| `2mWo17uXvG1BXpmdgv8v/3NTmnNubHtV62fWrk4jPFI9wM3NN2vzTzticIYHlm7K3r2mT/YR0WDciL818pLubLgum30r0Rkwc8ZSAc3nxzR4iqef4hLNeUCnkWqulY5C0M85bjDLCpjblz/2LpUQcv1j1feIY6R7rpfqOLdHa10=` | RSA Public Key        |
| `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\DisableCompression`      | Registry              |
| `Hxxp[://]U1U2/a[.]jsp?v=rep_YYYYMMDD?COMPUTERNAME*USERNAME*UUID*RANDOM`   

---

## Additional Notes

| **Description**                                      | **Details**           |
|------------------------------------------------------|-----------------------|
| **Common Program Used to Execute Malicious Commands on PowerShell** | `IEX`                 |
| **C2 Server in the Script Used to Send Victim's Information**       | `t[.]pp6r1[.]com`     |
| **Variable in the Script Used as a Unique Identifier**             | `$uniq_name`          |

