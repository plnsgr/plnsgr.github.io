---
title: "Concept of PE Injection"
date: 2025-02-28
categories: [Reverse]
tags: [Reverse]
image: assets/logo/ida-ascii-art.png
---

# Portable Executable Injection

high level overview of the unpacking routine and the PE injection routine:

![](https://file.notion.so/f/f/2b1ea456-18af-403c-953f-e1f8e610fc0e/c54b9ddf-6aee-4e82-be94-99e74cd12cb1/e27d1b393a3e3634.gif?table=block&id=20126e60-5e7e-803c-a072-c4030a8f8ca5&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&expirationTimestamp=1779969600000&signature=kDS6ADz_7iROx_nVU93W8E6f59pWt9iWky2hPyDIu9k)

---

# List of Process Injection Technique

---

## **1. CLASSIC DLL INJECTION VIA CREATEREMOTETHREAD AND LOADLIBRARY**

This technique is one of the most common techniques used to inject malware into another process. The malware writes the path to its malicious **dynamic-link library (DLL) in the virtual address space** of another process, and ensures the **remote process loads it by creating a remote thread** in the target process.

![](https://file.notion.so/f/f/2b1ea456-18af-403c-953f-e1f8e610fc0e/64b185f6-bd34-4768-a9c9-673da138d051/process-injection-techniques-blogs-dll-injection.gif?table=block&id=20126e60-5e7e-8078-9a66-dd81335cab9a&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&expirationTimestamp=1779969600000&signature=0Rqkagq3uFM1kQBUtAR2FaLRv_6Qbbp9kDcRjQJV6Hw)

Before the malware can inject itself into a process (such as `svchost.exe`), it first needs to find a suitable target. To do this, it scans running processes using three Application Program Interfaces (APIs): `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next`.

| API | Description |
| --- | --- |
| `CreateToolhelp32Snapshot` | generates a snapshot of all active processes or specific modules in memory. |
| `Process32First` | extracts details about the first process in that snapshot. |
| `Process32Next` | iterates through the remaining processes, allowing the malware to search for its target. |

Once it identifies the right process, the malware obtains its handle using the `OpenProcess` API.

As illustrated in Figure 1, the malware then calls `VirtualAllocEx` to allocate space within the target process's memory, where it writes the path to its DLL using `WriteProcessMemory`. To execute malicious code within another process, the malware employs APIs such as `CreateRemoteThread`, `NtCreateThreadEx`, or `RtlCreateUserThread`. The last two methods are undocumented. Regardless of which API is used, the main objective is to pass the address of `LoadLibrary` to force the remote process to execute the malicious DLL.

Security software commonly flags the `CreateRemoteThread` API because it requires a malicious DLL to be stored on disk, making it more likely to be detected. Since sophisticated attackers aim to evade detection, they often avoid this method. The screenshot below shows an instance of malware named Rebhip utilizing this technique.

![***Figure 1:*** *Rebhip worm performing a typical DLL injection*  
***Sha256:*** *07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365*](https://www.notion.so/image/attachment%3A724c56cd-82d1-4cb4-9990-b18fcfb9e175%3Aimage.png?table=block&id=20126e60-5e7e-800d-80ed-f1b4ed2cc7ba&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

| **Phase** | **Step** | **API/Action** |
| --- | --- | --- |
| **1. Find a Target Process** | Scan active processes | `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next` |
|  | Identify a suitable process (e.g., `svchost.exe`) | Selection logic based on process name, privileges, etc. |
|  | Obtain a handle to the target process | `OpenProcess` |
| **2. Prepare Memory** | Allocate memory in the target process | `VirtualAllocEx` |
|  | Write the path to the malicious DLL into the allocated memory | `WriteProcessMemory` |
| **3. Execute Malicious Code** | Use remote thread creation APIs to execute `LoadLibrary` | `CreateRemoteThread` (common, detectable) |
|  |  | `NtCreateThreadEx` (undocumented, stealthier) |
|  |  | `RtlCreateUserThread` (undocumented alternative) |
|  | Pass address of `LoadLibrary` to load the malicious DLL | Used as parameter for thread entry point |
| **4. Achieve Code Execution** | DLL is loaded in the context of the remote process | Remote process executes the DLL's entry point |
|  | Malicious functions are executed inside the hijacked process | Code runs with the permissions of the target process |

---

## 2. **PORTABLE EXECUTABLE INJECTION (PE INJECTION)**

Instead of using `LoadLibrary`, PE injection involves directly copying malicious code (a full PE file) into the memory of a target process and executing it. This avoids dropping a DLL on disk, making it stealthier.

- **Memory Setup**: Malware allocates memory in a target process using `VirtualAllocEx` and writes its PE code using `WriteProcessMemory`.
- **Execution**: It runs the code via `CreateRemoteThread` or a small shellcode.
- **Relocation Challenge**: Since the injected PE loads at a new base address, malware must fix hardcoded addresses. It does this by parsing the **relocation table** and adjusting offsets dynamically (often using nested loops).
- **Indicators**: Analysts often see two nested `for` loops and an `and 0x0fff` instruction before `CreateRemoteThread`—a sign of address relocation handling.

![](https://file.notion.so/f/f/2b1ea456-18af-403c-953f-e1f8e610fc0e/5d1d05d3-6c1f-4073-946a-3913fe5ff28b/process-injection-techniques-blogs-pe-injection.gif?table=block&id=20126e60-5e7e-80d1-a003-cc1139be8b1f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&expirationTimestamp=1779969600000&signature=_G9NyQlaz-G6nE-yCuQGnCqgXqAWhETvjbBOiMmMmQs)

This method is fileless like **Reflective DLL Injection** and **Memory Module**:

- **Reflective DLL Injection**: The DLL maps itself into memory without needing Windows APIs.
- **Memory Module**: Similar, but the loader handles memory mapping.

These in-memory methods are stealthier as they don’t rely on `LoadLibrary` or `CreateRemoteThread`.

![**Figure 2**: Example structure of the loops for PE injection prior to calls to CreateRemoteThread  
**Sha256**: ce8d7590182db2e51372a4a04d6a0927a65b2640739f9ec01cfd6c143b1110da](https://www.notion.so/image/attachment%3A4c7dc965-8988-42f1-86e3-46cb1423389b%3Aimage.png?table=block&id=20126e60-5e7e-8043-97dd-fe22147c6aaf&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

| **API / Function** | **Purpose** |
| --- | --- |
| `VirtualAllocEx` | Allocates memory in the remote (target) process |
| `WriteProcessMemory` | Writes the malicious PE code into the allocated memory |
| `CreateRemoteThread` | Starts execution of the injected code in the remote process |
| *(Custom Shellcode)* | Alternative method to trigger execution instead of using Windows APIs |
| *(Relocation Logic)* | Not an API, but malware often parses the PE **relocation table** manually |
| `LoadLibrary` (mentioned) | Common in other techniques, but **not used** in PE injection itself |

> Note: PE injection avoids using LoadLibrary by injecting full PE code, not a DLL path.

---

## 3. **PROCESS HOLLOWING (A.K.A PROCESS REPLACEMENT AND RUNPE)**

**Process Hollowing** is a stealthy technique where malware creates a legitimate process (like `svchost.exe`), **but replaces its code** with malicious code **before it runs**.

![](https://file.notion.so/f/f/2b1ea456-18af-403c-953f-e1f8e610fc0e/9c5d5090-e95b-4c98-b6bf-d162c26f441e/process-injection-techniques-blogs-runpe.gif?table=block&id=20126e60-5e7e-807c-937a-ded477e47472&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&expirationTimestamp=1779969600000&signature=dEz69wyGw7beQgBgZSKHUuQjjsgvAf56Fr4r0K-EFBw)

### **How It Works – Step by Step:**

1. **Create a Suspended Process**:

Malware creates a legitimate process in a **suspended** state using `CreateProcess` with the `CREATE_SUSPENDED` flag. This means the process doesn’t start running yet.

1. **Unmap Legitimate Code**:

It removes (unmaps) the original code of that process using `ZwUnmapViewOfSection` or `NtUnmapViewOfSection`.

1. **Allocate Memory for Malicious Code**:

It allocates new memory inside the target process using `VirtualAllocEx`.

1. **Inject Malicious Code**:

The malware writes its own executable sections into the target process using `WriteProcessMemory`.

1. **Redirect Execution to Malicious Code**:

It modifies the process’s thread to point to its new malicious entry point using `SetThreadContext`.

1. **Resume the Process**:

Finally, it calls `ResumeThread` to start execution — but now, the “legitimate” process is running the malware's code.

![**Figure 3**: Ransom.Cryak performing process hollowing  
**Sha256**: eae72d803bf67df22526f50fc7ab84d838efb2865c27aef1a61592b1c520d144](https://www.notion.so/image/attachment%3A43e750ee-19ac-4456-8cc4-abcc35b2940b%3Aimage.png?table=block&id=20126e60-5e7e-8039-824f-fc03cc4d93e4&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **API Table for Process Hollowing**

| **API / Function** | **Purpose** |
| --- | --- |
| `CreateProcess` | Creates a new process in a suspended state |
| `ZwUnmapViewOfSection` | Unmaps the original code section from the process (variant of `NtUnmap...`) |
| `NtUnmapViewOfSection` | Same as above (often used interchangeably) |
| `VirtualAllocEx` | Allocates new memory in the target process |
| `WriteProcessMemory` | Writes the malicious executable into the allocated memory |
| `SetThreadContext` | Points the thread's start address to the malicious entry point |
| `ResumeThread` | Resumes the suspended thread to start execution |

---

## 4. **THREAD EXECUTION HIJACKING (A.K.A SUSPEND, INJECT, AND RESUME (SIR))**

**Thread Execution Hijacking** is a stealthy injection technique where malware **modifies an existing thread** in a legitimate process, rather than creating a new thread or process.

This helps the malware avoid detection, since thread creation and process spawning are often flagged by security tools.

![](https://file.notion.so/f/f/2b1ea456-18af-403c-953f-e1f8e610fc0e/14141020-a083-4c47-b464-eba720dbbb1f/process-injection-techniques-blogs-hijack.gif?table=block&id=20126e60-5e7e-8097-87b0-d9c15b288e99&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&expirationTimestamp=1779969600000&signature=XqxTRH8vRKSrkCZQyNYEipVijcecoKx79nmIwF3l36c)

### **How It Works – Flow Summary**

1. **Find a Thread in a Target Process**

Malware enumerates threads using `CreateToolhelp32Snapshot` and `Thread32First`.

1. **Open and Suspend the Target Thread**

It opens the thread with `OpenThread` and suspends it using `SuspendThread`.

1. **Inject Malicious Code into the Process**

Malware allocates memory using `VirtualAllocEx` and writes the payload using `WriteProcessMemory`.

1. **Change the Thread’s Execution Flow**

It changes the thread's **EIP** (instruction pointer) to point to the malicious code using `SetThreadContext`.

1. **Resume the Thread**

Finally, `ResumeThread` is called to let the hijacked thread execute the injected code.

> Note: If the thread is suspended during a sensitive operation (like a system call), malware may wait or retry to avoid crashing the system.

![***Figure 4:*** *A generic trojan is performing thread execution hijacking*  
***Sha256:*** *787cbc8a6d1bc58ea169e51e1ad029a637f22560660cc129ab8a099a745bd50e*](https://www.notion.so/image/attachment%3Ae356d574-deb6-4a58-8ed0-0dec7e1575a7%3Aimage.png?table=block&id=20126e60-5e7e-800d-9ac4-f9cb1d665a3f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **API Table for Thread Execution Hijacking**

| **API / Function** | **Purpose** |
| --- | --- |
| `CreateToolhelp32Snapshot` | Captures a snapshot of the system’s threads |
| `Thread32First` | Begins iterating through the thread list |
| `OpenThread` | Opens a handle to a specific thread |
| `SuspendThread` | Suspends the thread so it can be hijacked safely |
| `VirtualAllocEx` | Allocates memory in the remote process |
| `WriteProcessMemory` | Writes shellcode or DLL path to the allocated memory |
| `SetThreadContext` | Changes the thread's execution pointer (EIP) to redirect to the malicious code |
| `ResumeThread` | Resumes the thread, which now executes the injected payload |

---

## **5. HOOK INJECTION VIA SETWINDOWSHOOKEX**

**Hook injection** is a technique where malware sets a **Windows hook** to load its **malicious DLL** when a specific event (like a keystroke or mouse click) happens in a target thread.

This method lets malware execute in the context of a legitimate process **without directly creating threads or injecting shellcode**.

### **Step-by-Step How It Works**

1. **Locate Target Thread (Optional)**

Malware can search for a specific thread using `CreateToolhelp32Snapshot` and `Thread32Next`.

1. **Prepare the Malicious DLL**
  - Load the malicious DLL into memory using `LoadLibrary`.
  - Get the address of the hook function inside the DLL using `GetProcAddress`.
1. **Set the Hook**
  - Use `SetWindowsHookEx` to register a hook for an event (e.g., keyboard or mouse input).
  - Specify the thread to hook into — malware often chooses a **specific thread** to reduce detection.
1. **Trigger the Hook**
  - When the event occurs (like a keystroke), Windows calls the malicious function in the DLL.
  - The malware now executes **inside the context of the hooked process**.

![***Figure 5:*** *Locky Ransomware using hook injection*  
***Sha256:*** *5d6ddb8458ee5ab99f3e7d9a21490ff4e5bc9808e18b9e20b6dc2c5b27927ba1*](https://www.notion.so/image/attachment%3A3c14da05-e99e-4700-843c-5e991192477a%3Aimage.png?table=block&id=20126e60-5e7e-8085-84f3-e3349ca8fbb3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **API Table for Hook Injection**

| **API / Function** | **Purpose** |
| --- | --- |
| `CreateToolhelp32Snapshot` | Takes a snapshot of threads (used to find a target thread) |
| `Thread32Next` | Iterates through the thread list |
| `LoadLibrary` | Loads the malicious DLL into memory |
| `GetProcAddress` | Gets the address of the hook function inside the DLL |
| `SetWindowsHookEx` | Installs the hook that triggers the DLL function when an event occurs |

---

## **6. INJECTION AND PERSISTENCE VIA REGISTRY MODIFICATION (E.G. APPINIT\_DLLS, APPCERTDLLS, IFEO)**

Appinit\_DLL, AppCertDlls, and IFEO (Image File Execution Options) are all registry keys that malware uses for both injection and persistence. The entries are located at the following locations:

| **Technique** | **Registry Key Location** |
| --- | --- |
| AppInit\_DLLs | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls` |
| AppCertDlls | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` |
| IFEO | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<Target>` |

### AppInit\_DLLs

Malware can insert the location of their malicious library under the Appinit\_Dlls registry key to have another process load their library. Every library under this registry key is loaded into every process that loads User32.dll. User32.dll is a very common library used for storing graphical elements such as dialog boxes. Thus, when a malware modifies this subkey, the majority of processes will load the malicious library. Figure 6 demonstrates the trojan Ginwui relying on this approach for injection and persistence. It simply opens the Appinit\_Dlls registry key by calling RegCreateKeyEx, and modifies its values by calling RegSetValueEx.

![***Figure 6:*** *Ginwui modifying the AppIniti\_DLLs registry key*  
***Sha256:*** *9f10ec2786a10971eddc919a5e87a927c652e1655ddbbae72d376856d30fa27c*](https://www.notion.so/image/attachment%3Ac603d319-fa00-4052-a135-daca5b9599a7%3Aimage.png?table=block&id=20126e60-5e7e-8021-8164-fe4c8159aa81&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### AppCertDlls

This approach is very similar to the AppInit\_DLLs approach, except that DLLs under this registry key are loaded into every process that calls the Win32 API functions CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, CreateProcessWithTokenW, and WinExec.

### Image File Execution Options (IFEO)

IFEO is typically used for debugging purposes. Developers can set the “Debugger Value” under this registry key to attach a program to another executable for debugging. Therefore, whenever the executable is launched the program that is attached to it will be launched. To use this feature you can simply give the path to the debugger, and attach it to the executable that you want to analyze. Malware can modify this registry key to inject itself into the target executable. In Figure 7, Diztakun trojan implements this technique by modifying the debugger value of Task Manager.

![***Figure 7:*** *Diztakun trojan modifying IFEO registry key*  
***Sha256:*** *f0089056fc6a314713077273c5910f878813fa750f801dfca4ae7e9d7578a148*](https://www.notion.so/image/attachment%3Aeb339c43-5e8c-4ccd-91fe-6c2106c79250%3Aimage.png?table=block&id=20126e60-5e7e-806a-b0d5-c1504b936a52&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **API Table for Registry-Based Injection**

| **API / Function** | **Purpose** |
| --- | --- |
| `RegCreateKeyEx` | Opens or creates a registry key |
| `RegSetValueEx` | Sets a registry value (e.g., path to malicious DLL or debugger) |
| *(CreateProcess family)* | Triggers AppCertDlls injection indirectly |
| *(User32.dll load)* | Triggers AppInit\_DLLs injection indirectly |
| *(Executable launch)* | Triggers IFEO debugger replacement |

---

## **7. APC INJECTION AND ATOMBOMBING**

**APC Injection** allows malware to queue a function to run in the context of another thread. When that thread enters an *alertable state* (e.g., while waiting or sleeping), the malware’s code gets executed.

**AtomBombing** is a stealthier variation of APC injection where malware uses **Windows atom tables** to store and inject code into another process, bypassing common security tools.

---

### **Step-by-Step: APC Injection**

1. **Identify a Target Thread in Alertable State**

Malware looks for threads calling functions like `SleepEx`, `WaitForSingleObjectEx`, etc.

1. **Get Handle to the Target Thread**

Use `OpenThread` to get access to that thread.

1. **Inject Code via APC Queue**
  - Malware queues its code (e.g., `LoadLibrary` to load a malicious DLL) to that thread using `QueueUserAPC`.
  - Once the thread becomes alertable, it executes the malware's function.

### **Step-by-Step: AtomBombing**

1. **Store Payload in Atom Table**

Malware stores shellcode or DLL path in a **global atom table**, which is used by Windows to share small strings across processes.

1. **Write into Target Memory**

Instead of using `WriteProcessMemory`, the malware retrieves the data from the atom table within the target process.

1. **Queue APC with Malicious Function**

Like in standard APC injection, malware uses `QueueUserAPC` to call the malicious function (e.g., `LoadLibraryA`).

1. **Code Executes When Thread Becomes Alertable**

### **APIs Used in APC Injection & AtomBombing**

| **API / Function** | **Purpose** |
| --- | --- |
| `OpenThread` | Opens a handle to the target thread |
| `QueueUserAPC` | Queues the malicious function to the target thread's APC queue |
| `LoadLibraryA` | Common function pointer used in APC to load a malicious DLL |
| `SleepEx`, `WaitForSingleObjectEx`, etc. | Cause a thread to enter **alertable state**, allowing queued APCs to run |
| `GlobalAddAtom`, `GlobalGetAtomName` *(AtomBombing)* | Add/retrieve malicious data into/from atom table |

![***Figure 8:*** *Almanahe performing APC injection*  
***Sha256:*** *f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad*](https://www.notion.so/image/attachment%3A0d787833-97ce-414a-9fe2-77a699f5d958%3Aimage.png?table=block&id=20126e60-5e7e-8069-8748-e74c97dae3f2&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

---

## **8. EXTRA WINDOW MEMORY INJECTION (EWMI) VIA SETWINDOWLONG**

EWMI is a stealthy code injection method that targets **extra window memory** (EWM) of windows like `Shell_TrayWnd` (part of `explorer.exe`). Malware uses this small memory space to hijack function pointers and redirect execution to malicious code stored in a shared memory section.

---

### **Step-by-Step: EWMI**

1. **Write Shellcode to Shared Memory Section**
  - Malware either creates or maps a **shared memory section** into both its own and `explorer.exe`'s memory.
  - Writes the malicious code (shellcode) into that shared memory region.
1. **Modify Extra Window Memory of Target Window (**`Shell_TrayWnd`**)**
  - Calls `GetWindowLong` to read current function pointer (at a certain offset).
  - Calls `SetWindowLong` to overwrite the pointer to now point to the shellcode.
1. **Trigger Execution**
  - Calls `SendNotifyMessage` to send a message to `Shell_TrayWnd`.
  - That message indirectly triggers the execution of the shellcode by calling the pointer set in the EWM.

![](https://www.notion.so/image/attachment%3A26b43555-8e00-4a9a-b895-304e5799fb03%3Aimage.png?table=block&id=20126e60-5e7e-80cb-b2dc-ebe11ec28021&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![***Figure 9:*** *PowerLoader injecting into extra window memory of shell tray window*  
***Sha256:*** *5e56a3c4d4c304ee6278df0b32afb62bd0dd01e2a9894ad007f4cc5f873ab5cf*](https://www.notion.so/image/attachment%3A8b270265-3ea0-4a0d-8bbc-72563e4e3b12%3Aimage.png?table=block&id=20126e60-5e7e-80bd-ade9-fa9639a27c0c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **APIs Used in EWMI**

| **API / Function** | **Purpose** |
| --- | --- |
| `NtMapViewOfSection` | Maps a shared memory section into the address space of both processes |
| `GetWindowLong` | Retrieves a value from the extra window memory of a target window |
| `SetWindowLong` | Modifies a value (e.g., function pointer) in the extra window memory |
| `SendNotifyMessage` | Triggers the execution of the pointer in EWM by sending a window message |

---

## **9. INJECTION USING SHIMS**

**Shims** are normally used by Microsoft to make older software compatible with newer versions of Windows. They let Windows apply “fixes” (like compatibility adjustments) to programs. However, **malware can abuse this feature** to **inject code or persist** by telling Windows to always load a **malicious DLL** when a specific executable (like `chrome.exe`) runs.

---

### **Step-by-Step: Shim Injection**

1. **Create Malicious Shim Database (.sdb)**
  - The malware creates an `.sdb` file with a malicious "fix" (like `InjectDLL`) that forces a specific app (e.g., Chrome) to load a malicious DLL.
1. **Install Shim**
  - Malware installs this `.sdb` database using the tool `sdbinst.exe`.
1. **Trigger Application**
  - When the targeted app (like Chrome) is launched, the **Shim Engine** kicks in, finds the `.sdb`, and loads the **malicious DLL** automatically—without needing traditional injection methods.

![***Figure 10:*** *SDB used by Search Protect for injection purposes*  
***Sha256:*** *6d5048baf2c3bba85adc9ac5ffd96b21c9a27d76003c4aa657157978d7437a20*](https://www.notion.so/image/attachment%3A98f71ea0-e544-4ec5-9a73-b6489c65b9be%3Aimage.png?table=block&id=20126e60-5e7e-80c5-945d-f1a21f0914c7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **APIs / Tools / Features Used in Shim Injection**

| **Tool / Feature / API** | **Purpose** |
| --- | --- |
| `sdbinst.exe` | Installs the `.sdb` shim database into the system |
| **Shim Engine (internal)** | Built into Windows; automatically applies shims when executables are launched |
| `InjectDLL` (Shim fix) | Loads a specified DLL into the target executable |
| `DisableNX`, `DisableSEH` | Other shim "fixes" often used by malware to weaken protections |

> Shim-based injection is stealthy and does not require runtime API calls like `CreateRemoteThread` or `WriteProcessMemory`. It's handled entirely by Windows during process startup.

---

## **10. IAT HOOKING AND INLINE HOOKING (A.K.A USERLAND ROOTKITS)**

Malware can secretly change how Windows functions work by intercepting API calls in two main ways:

- **IAT Hooking** (Import Address Table): The malware changes function pointers in the **Import Address Table** of a process, so when the process tries to call a standard API (e.g., `CreateFile`), it ends up calling the malware’s function instead.
- **Inline Hooking**: Instead of altering pointers, the malware **directly modifies the first few bytes of the actual API function** in memory, replacing them with a jump to its own code. This intercepts execution even if the API is called directly.

---

### **Step-by-Step: How Hooking Works**

### **IAT Hooking:**

1. Malware locates the target process’s **Import Address Table (IAT)**.
1. Finds a specific imported API (e.g., `CreateWindowEx`).
1. Replaces the function pointer with its own malicious function address.
1. When the process calls the API, it executes malware’s function instead.

### **Inline Hooking:**

1. Malware finds the memory location of the **target API** (e.g., `CreateWindowEx`) in system DLLs.
1. Overwrites the **first few instructions** (usually 5 bytes) with a **JMP instruction** to its own malicious code.
1. API call is now redirected to malicious logic.

---

![***Figure 11:*** *FinFisher performing IAT hooking by changing where CreateWindowEx points to*  
***Sha256:*** *f827c92fbe832db3f09f47fe0dcaafd89b40c7064ab90833a1f418f2d1e75e8e*](https://www.notion.so/image/attachment%3A909e41d5-da1d-4cba-976f-3afeafa701c8%3Aimage.png?table=block&id=20126e60-5e7e-8048-ab40-e4129ac1f7fe&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **APIs / Concepts Used in Hooking Techniques**

| **API / Concept** | **Purpose / Usage** |
| --- | --- |
| `CreateWindowEx` | Common target function shown in FinFisher's IAT hook |
| `VirtualProtect` / `NtProtectVirtualMemory` | Used to change memory protection before modifying code or IAT |
| `GetProcAddress` | Locates original function address to hijack or preserve original call |
| `ReadProcessMemory` / `WriteProcessMemory` | May be used to read/write into the IAT or DLL memory |
| `IMAGE_IMPORT_DESCRIPTOR` | PE structure used to navigate the Import Address Table |
| `jmp` (assembly instruction) | Used in **inline hooking** to redirect execution flow |
