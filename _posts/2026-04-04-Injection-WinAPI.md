---
title: "Injection WinAPI"
date: 2026-04-04
categories: [Reverse,Malware Analysis]
tags: [Reverse,Malware Analysis]
image: assets/logo/ida-ascii-art.png
---

This is a note to easily set a breakpoint in the future.

## Classic Process Injection

> inject the legitimate process

- Obtain handle to a target process
  - CreateToolHelp32Snapshot
  - OpenProcess
  - NtQuerySystemInformation
- Allocate new memory region at target process
  - VirtualAllocEx
  - NtAllocateVirtualMemory
- Write payload into newly allocated memory
  - WriteProcessMemory
  - NtWriteVirtualMemory
- Create new remote thread
  - CreateRemoteThread
  - NtCreateThreadEx

### API calls

Kernel32.dll:

- CreateToolHelp32Snapshot
- Process32First
- Process32Next
- Thread32First
- Thread32Next
- OpenProcess
- WriteProcessMemory
- VirtualProtectEx
- Open Thread

Ntdll.dll:

- NtQuerySystemInformation
- NtAllocateVirtualMemory
- NtWriteVirtualMemory

---

## APC Code Injection

*earlybird*

> Legitimate Process - Sleep(..,true)

- Find the process to inject our payload
  - CreateToolHelp32Snapshot
  - NtQuerySystemInformation
- Find all the threads in that process
  - Thread32First
  - Thread32Next
- Allocate memory in that process
  - VirtualAllocEx
  - NtAllocateVirtual Memory
- Write the payload into that allocated memory
  - WriteProcessMemory
  - NtWriteVirtualMemory
- Put the APC function in the queue for all threads
  - QueueUserAPC
  - NtQueueUserAPC
- APC function here points to our shellcode

---

## Section Mapping

> ![](https://www.notion.so/image/attachment%3Af46337cc-aa8c-4842-bd53-5802633f0b56%3Aimage.png?table=block&id=33726e60-5e7e-8055-b13c-f639c3df81ff&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Af46337cc-aa8c-4842-bd53-5802633f0b56%3Aimage.png?table=block&id=33726e60-5e7e-8055-b13c-f639c3df81ff&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

- Create a new section with full RWX page protection
  - NtCreateSection
- Map a view of section to local process (injector) with RW page protection
  - NtMapViewOfSection
- Map a view of section to target process with RX page protection
  - NtMapViewOfSection
- Write a payload to a view mapped to a local process
  - memcpy
- Create a remote thread with a base address of view mapped to remote process
  - CreateRemoteThread
  - NtCreateThreadEx
  - RtlCreateUserThread

---

## **Module Stomping**

> ![](https://www.notion.so/image/attachment%3Af5391fb1-886f-41ec-8c0a-a69a3dcb63c5%3Aimage.png?table=block&id=33726e60-5e7e-80b3-bb0b-fabc79314a6c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Af5391fb1-886f-41ec-8c0a-a69a3dcb63c5%3Aimage.png?table=block&id=33726e60-5e7e-80b3-bb0b-fabc79314a6c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

- Open a target process and get handle to the target process
  - OpenProcess
  - NtOpenProcess
- Load the target module in the target process
  - VirtualAllocEx
  - WriteProcessMemory
  - CreateRemoteThread
- Write the payload at the entrypoint address of the loaded module
  - WriteProcessMemory
- Create a thread to execute the payload
  - CreateRemoteThread

### API

- Kernel32.dll:  
OpenProcess, ReadProcessMemory, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx, CreateRemote Thread
- Psapi.dll:  
EnumProcess Modules, GetModuleFileNameEx
- Ntdll.dll:  
NtAllocateVirtualMemory

---

## Process Hollowing

> ![](https://www.notion.so/image/attachment%3Aebf14329-3d35-4215-b1ca-ae3331434c2e%3Aimage.png?table=block&id=33726e60-5e7e-8085-b785-f07c81dacbdf&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Aebf14329-3d35-4215-b1ca-ae3331434c2e%3Aimage.png?table=block&id=33726e60-5e7e-8085-b785-f07c81dacbdf&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

- Create target process in suspended mode
  - CreateProcessA
- Get Image Base Address of the target process
  - NtQueryInformationProcess
  - ReadProcess Memory
- Hollow/Unmap target image
  - ZwUnmapViewOfSection
- Allocate new memory in target process for the payload
  - VirtualAllocEx
- Copy all the payload section to the allocated memory in target process
  - WriteProcessMemory
- Get Context of target process
  - GetThreadContext
- Set the entrypoint of payload in respective context
  - EAX for x86
  - RCX for x64
- Apply the Context of target process
  - SetThreadContext
- Resume main thread of target process
  - ResumeThread

### API

- Kernel32.dll:  
CreateProcessA, ReadProcess Memory, WriteProcess Memory, Get ThreadContext, Set ThreadContext, Resume Thread
- Ntdll.dll:  
NtQueryInformation Process, NtUnmap View Of Section/ZwUnmap View Of Section

---

## **Process Doppleganging**

> ![](https://www.notion.so/image/attachment%3A1dfc4f45-38d6-474e-8f99-0e72ff4222af%3Aimage.png?table=block&id=33726e60-5e7e-8058-9c98-ff3520f252b7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A1dfc4f45-38d6-474e-8f99-0e72ff4222af%3Aimage.png?table=block&id=33726e60-5e7e-8058-9c98-ff3520f252b7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Steps of Doppelganging can be broken down into 4 steps:

1. Transact: process a legitimate file into the NTFS transaction and then overwrite it with a malicious payload file
  1. CreateTransaction,
  1. CreateFileTransactedA
1. Load: Create a memory section from the payload and load the malicious code
  1. NtCreateSection
1. Rollback: Rollback the transaction i.e., removing malicious code so that no data left on the disk
  1. RollbackTransaction
1. Animate: Bringing Doppelganging to life. Create a process from the previously created memory section (step 2). The memory section contains malicious code and never written to the disk.
  1. NtCreateProcessEx
  1. NtCreateThreadEx

### API

- KtmW32.dll:  
Create Transaction, Rollback Transaction
- Kernel32.dll:  
Create File TransactedA, Write File
- Ntdll.dll:  
NtCreate Section, NtCreateProcessEx, NtCreate ThreadEx

---

## **Transacted Hollowing**

> ![](https://www.notion.so/image/attachment%3A00b74f4e-a44f-4999-9ad2-e8ae2c210b24%3Aimage.png?table=block&id=33726e60-5e7e-800a-932b-d78c5095e3ee&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=980&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A00b74f4e-a44f-4999-9ad2-e8ae2c210b24%3Aimage.png?table=block&id=33726e60-5e7e-800a-932b-d78c5095e3ee&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=980&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

> ![](https://www.notion.so/image/attachment%3A67ded431-a64c-4fcf-8a6d-02341bb39321%3Aimage.png?table=block&id=33726e60-5e7e-809d-a657-d8ac9801489d&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A67ded431-a64c-4fcf-8a6d-02341bb39321%3Aimage.png?table=block&id=33726e60-5e7e-809d-a657-d8ac9801489d&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

- Create NTFS transaction object
  - CreateTransaction
- Open/Create target file for transaction
  - CreateFileTransactedA
- Create an image section from transacted file
  - NtCreateSection
- Rollback the transaction
  - RollbackTransaction
- Create a new target process in suspended mode
  - CreateProcessA
- Map an image section into the target process
  - NtMapViewOfSection
- Update entrypoint in target process with payload entrypoint
  - GetThreadContext
  - SetThreadContext
- Update image base address at target process PEB with newly mapped image base address
  - NtQueryInformationProcess
  - WriteProcessMemory
- Resume the thread
  - NtResumeThread

### API

- Kernel32.dll:  
CreateFile TransactedW, Write File, CreateProcess W, Resume Thread, Get ThreadContext, Set ThreadContext, Resume Thread
- Ntdll.dll:  
NtQueryInformationProcess, NtCreate Transaction, NtCreateSection, NtRollback Transaction, NtMap View Of Section

---

## **Process Herpaderping**

> ![](https://www.notion.so/image/attachment%3A6233fbd6-f9ef-4afc-9484-fc0b2072563e%3Aimage.png?table=block&id=33726e60-5e7e-809a-82ad-da2ae12a47d3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A6233fbd6-f9ef-4afc-9484-fc0b2072563e%3Aimage.png?table=block&id=33726e60-5e7e-809a-82ad-da2ae12a47d3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

- Create a temp/decoy file
  - CreateFileA
- Write payload into that file (do not close the temp file handle after writing payload into it)
  - WriteFile
- Create an image section from that file
  - NtCreateSection
- Create a process using the newly created section
  - NtCreateProcessEx
- Modify the temp file
  - SetFilePointer
  - WriteFile
- Setup process parameters
  - RtICreateProcessParametersEx
- Create new thread
  - NtCreateThreadEx
- Close temp file handle
  - Close Handle

### API

- Kernel32.dll:  
CreateFileW, Write File, SetFilePointer, CloseHandle
- Ntdll.dll:  
NtOpenFile, NtSetInformationFile, NtCreate Section, NtCreateProcessEx, NtCreateProcess ParametersEx, NtCreate ThreadEx

---

## **Process Ghosting**

> ![](https://www.notion.so/image/attachment%3Adc1c33d7-ee4c-4469-bcf6-2aed09cd2ca6%3Aimage.png?table=block&id=33726e60-5e7e-8052-a5f1-eb28edfdbf75&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Adc1c33d7-ee4c-4469-bcf6-2aed09cd2ca6%3Aimage.png?table=block&id=33726e60-5e7e-8052-a5f1-eb28edfdbf75&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1150&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

- Open/Create new dummy file
  - CreateFileA
- Put the file into delete-pending state using API NtSetinformationFile
  - FileDispositionInformation information class is used here
- Write payload buffer into delete-pending file
  - WriteFile
- Create an image section with the delete-pending file
  - NtCreateSection
- Close delete-pending file handle
  - CloseHandle
- Create a process with newly created image section using API NtCreateProcessEx
- Update/fix process parameters
  - RtlCreateProcessParametersEx
- Create a new thread
  - NtCreateThreadEx

### API

- Kernel32.dll:  
WriteFile, CloseHandle
- Ntdll.dll:  
NtOpenFile, NtSetInformationFile, NtCreateSection, NtCreateProcessEx, NtCreateProcessParametersEx, NtCreate ThreadEx

---
