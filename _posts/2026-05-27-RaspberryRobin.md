---
title: "Raspberry Robin DLL Loader"
date: 2026-05-27
categories: [Malware Analysis]
tags: [Malware Analysis]
---

# Raspberry Robin DLL Loader

## Report Summary

| Field | Finding |
| --- | --- |
| Report date | 2026-05-27 |
| Submitted artifact | `05c6f53118d363ee80989ef37cad85ee1c35b0e22d5dcebd8a6d6a396a94cb65.dll` |
| Classification | Raspberry Robin DLL loader component |

## Executive Summary

The supplied file is a 32-bit Windows DLL attributable to **Raspberry Robin**. Attribution is high confidence because its exact SHA-256 hash appears in Zscaler ThreatLabz's published indicator table as a Raspberry Robin DLL. Static inspection indicates that this artifact is a packed or encrypted loader stage rather than a transparently readable final payload.

The DLL contains two very large, high-entropy data sections, sparse imported functionality, runtime API/string reconstruction, anti-debug handling, and code that allocates executable memory, rebuilds a Portable Executable (PE) image in memory, and transfers control through a computed target. These characteristics are consistent with a staged malware loader intended to obstruct static inspection and reveal its effective payload only during runtime.

No separately extractable secondary dropper, valid nested PE file, or valid embedded archive was recovered from the DLL at rest. The file does, however, include loader code capable of producing or transferring execution to an opaque in-memory stage. A controlled unpacking/detonation phase would be required to recover that stage for independent hashing and full component analysis.

For injection technique classification, the local DLL demonstrates **in-memory PE reconstruction/manual loading** into executable memory. Zscaler ThreatLabz reports that newer Raspberry Robin core payloads perform **early-bird Asynchronous Procedure Call (APC) process injection** using `NtQueueApcThread`, with candidate target processes including `cleanmgr.exe`, `rundll32.exe`, and `dllhost.exe`. ThreatLabz also reports that older Raspberry Robin versions used process hollowing.

## Scope and Methodology

Static examination included:

- Cryptographic hashing and PE file identification.
- PE header, section, import, export, debug-path, and data-directory review.
- Entropy measurement of raw sections.
- Printable string review and targeted indicator searches.
- Static disassembly of the entry path, anti-debug routines, API resolution logic, and in-memory PE construction logic.
- Validation of candidate embedded `MZ`/`PE` and archive signatures in raw bytes.
- Correlation with primary public reporting from Zscaler ThreatLabz and technique definitions from MITRE ATT&CK.

## Sample Identification

| Attribute | Value |
| --- | --- |
| Original filename | `05c6f53118d363ee80989ef37cad85ee1c35b0e22d5dcebd8a6d6a396a94cb65.dll` |
| File size | 5,353,472 bytes |
| File format | PE32 Windows DLL, GUI subsystem |
| Architecture | Intel x86 / 32-bit |
| Preferred image base | `0x10000000` |
| Linker timestamp | `2025-01-24 08:45:59 UTC` (untrusted PE metadata) |
| Digital signature | Not signed |
| Debug/PDB path | `o:\dir_for_builds\bldObjDir_67939ff4_616ca95a0_e24df0062\loader.cpp.bc.obj.pdb` |
| MD5 | `4ef38f237262847fd20783186b1579e0` |
| SHA-1 | `30f8eca869263bcf4c76acd013fd126039ff8c4a` |
| SHA-256 | `05c6f53118d363ee80989ef37cad85ee1c35b0e22d5dcebd8a6d6a396a94cb65` |

The submitted filename is identical to the sample's SHA-256 hash followed by the `.dll` extension.

## Attribution Assessment

Zscaler ThreatLabz published the exact SHA-256 value of the submitted DLL in its August 2025 reporting on Raspberry Robin, labelling the indicator as a **Raspberry Robin DLL**. This exact-hash match provides a stronger attribution basis than behavioral similarity alone.

Local static observations are also compatible with the attributed family:

- The DLL presents as a loader with limited clear-text imports while reconstructing capabilities at runtime.
- Large opaque/high-entropy regions obstruct extraction of a clear-text payload.
- Code reconstructs and transfers execution to a PE image in memory.
- Anti-analysis and dynamic API-resolution behavior matches the loader-oriented design reported for Raspberry Robin.

**Assessment:** The supplied DLL is a malicious Raspberry Robin loader-stage artifact with high confidence.

## PE Structure and Packing Assessment

### Section Analysis

| Section | Raw Offset | Raw Size | Entropy | Permissions | Assessment |
| --- | ---: | ---: | ---: | --- | --- |
| `.text` | `0x001000` | 24,576 | 3.8642 | Read / Execute | Loader code and obfuscated entry path |
| `.rdata` | `0x007000` | 4,096 | 2.1903 | Read | Imports, exports, strings, constants |
| `.data` | `0x008000` | 53,248 | 4.0355 | Read / Write | Runtime data and encoded resolution material |
| `hK6` | `0x015000` | 184,320 | 7.9732 | Read / Write | High-entropy opaque data; consistent with encrypted/packed material or decoy content |
| `.CRT` | `0x042000` | 5,042,176 | 7.9999 | Read | Near-maximum entropy; dominates the file and is consistent with encrypted/packed material or filler |
| `.rsrc` | `0x511000` | 4,096 | 1.0206 | Read | Resource data |
| `.reloc` | `0x512000` | 36,864 | 4.4607 | Read | Base relocation data |

Overall raw-file entropy is approximately `7.9848`, driven by the opaque `hK6` and `.CRT` sections. Their size and entropy strongly indicate that meaningful payload material, configuration, or masking data is unavailable in readable form at rest.

### Notable PE Properties

| Property | Observation | Significance |
| --- | --- | --- |
| DEP/NX compatibility | Not enabled as reported by PE inspection | Executable-memory behavior is less constrained by image policy |
| Relocations | Reported absent in image metadata, although a `.reloc` section is present | Inconsistent metadata is typical of unusual or deliberately shaped loaders |
| Overlay | No overlay detected | Opaque content is carried within PE sections rather than appended data |
| TLS callbacks | None identified | Entry behavior is concentrated in normal execution paths |
| Export surface | Single unusual exported name forwarding to `kernel32.WriteFile` | Provides a benign-looking proxy/forwarder facade |

### Export Observation

The DLL exports a single unusual name, `QbetdeiolralhwIe`, under the library identity `dyayt27.dll`. Its export target is the forwarder string `kernel32.WriteFile`. The export surface does not explain the malicious behavior; the effective loader logic is present in internal execution paths.

## Imported Functionality

Only a small import set is visible statically:

| Library | Imports Observed |
| --- | --- |
| `ADVAPI32.dll` | `GetPrivateObjectSecurity` |
| `KERNEL32.dll` | `GetModuleFileNameW`, `LoadLibraryExW`, `GetFileType`, `LoadLibraryExA`, `PostQueuedCompletionStatus`, `FindClose`, `FreeConsole`, `RtlUnwind`, `TerminateProcess`, `GetCurrentProcess`, `UnhandledExceptionFilter`, `SetUnhandledExceptionFilter`, `IsDebuggerPresent` |
| `RASAPI32.dll` | `RasEnumEntriesW` |

The visible import table does not contain typical payload allocation or remote-injection APIs such as `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, or `NtQueueApcThread`. This does not indicate their absence from runtime behavior: static disassembly shows API material being decoded/resolved during execution, which deliberately prevents meaningful functionality from being represented by the ordinary import table.

## Static Behavioral Analysis

### Obfuscated Initial Execution

The DLL entry point is located at virtual address `0x10001304`. The initial code contains extensive low-value repeated instructions and then reaches an indirect-looking trampoline:

![img](assets/raspberryrobin/1.png)

```asm
0x10001340  call fcn.1000130f

fcn.1000130f:
0x10001317  lea eax, [0x100010a3]
0x1000131d  push eax
0x1000131e  ret
```

This `push`/`ret` transfer enters hidden loader logic at `0x100010a3` while making straightforward control-flow recovery less obvious.

![img](assets/raspberryrobin/2.png)

### Loader and Anti-Analysis Behavior

The recovered loader path references the strings `SElf.eXe` and UTF-16 `TEstapp.exe`, and invokes `LoadLibraryExA`/`LoadLibraryExW` around these constructed names. The naming and unusual case pattern are consistent with decoy or environment-oriented loading logic rather than normal application functionality.

![img](assets/raspberryrobin/3.png)

Additional code invokes:

- `IsDebuggerPresent`.
- `SetUnhandledExceptionFilter` and `UnhandledExceptionFilter`.
- `TerminateProcess` using the current process handle.
- Other unusual imported calls including `PostQueuedCompletionStatus`, `GetPrivateObjectSecurity`, and `FreeConsole`.

The `IsDebuggerPresent` and exception/termination path provides direct evidence of anti-debug behavior. Some of the remaining unusual API use may form anti-emulation, decoy, or loader housekeeping logic; no dynamic validation was performed.

![img](assets/raspberryrobin/4.png)

### In-Memory PE Reconstruction

Static disassembly establishes a memory-resident payload transfer sequence:

- A routine scans memory for `MZ` (`0x5A4D`) and then verifies a `PE` (`0x00004550`) signature through the `e_lfanew` header field.
- Another routine reconstructs an executable image in allocated memory, explicitly writing an `MZ` header, an `e_lfanew` offset of `0xC0`, and a `PE` signature.
- Encoded string/API material is transformed at runtime and passed to a resolver.
- A resolved function is invoked with arguments equivalent to:

```c
allocation_function(NULL, 0x6000, 0x1000, 0x40);
```

The arguments strongly match `VirtualAlloc(NULL, 0x6000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)`, although the API name is dynamically resolved rather than directly imported.

- Control is finally passed through a computed function address (`call eax`) after the in-memory image preparation.

**Direct static conclusion:** The submitted DLL implements an obfuscated, in-process loader that builds or maps a PE-compatible stage into executable memory and transfers control to it.

## Other Dropper or Payload Determination

The supplied file was reviewed for additional statically recoverable components.

| Candidate Component | Result | Assessment |
| --- | --- | --- |
| Second valid PE file embedded in raw DLL bytes | Not recovered | Numerous random `MZ` byte pairs occur in high-entropy content, but only the outer DLL validates as a PE structure |
| Embedded ZIP archive | Not identified | No ZIP signature located |
| Embedded CAB archive | Not identified | No CAB signature located |
| Embedded 7-Zip archive | Not identified | No 7-Zip signature located |
| Candidate GZIP bytes | Validation failed | Byte match does not decompress as valid GZIP and is consistent with random high-entropy data |
| Runtime-decoded/in-memory stage | Evidenced by loader code, not statically extracted | Requires controlled runtime unpacking or emulation for independent analysis |

### Determination

No separate, readable secondary **dropper** can be extracted and analyzed as an independent file from the submitted DLL using static inspection alone. The DLL itself should be treated as a loader/dropper-stage component because it prepares an opaque in-memory execution stage.

ThreatLabz family research reports that Raspberry Robin payload structures may contain decoy and core components and may retrieve later payloads. Those family capabilities should not be interpreted as proof that an additional clear-text dropper is physically present in this specific file without successful unpacking.

## Injection Technique Assessment

### Behavior Demonstrated by This Sample

The submitted wrapper directly demonstrates **in-process in-memory PE reconstruction/manual loading**:

- Runtime resolution of sensitive functionality.
- Likely `VirtualAlloc` allocation of read/write/execute memory.
- PE header reconstruction in the allocated region.
- Computed transfer of execution into the reconstructed stage.

This is consistent with reflective-style/manual PE loading. Static analysis of the wrapper does **not** establish a remote victim process, a remote memory write, or an APC queue operation in this file's readable outer-layer code.

### Family-Documented Injection Behavior

Zscaler ThreatLabz documents the following Raspberry Robin core behavior:

| Variant Context | Technique | Documented Targets / Mechanism | Confidence for Supplied Outer DLL |
| --- | --- | --- | --- |
| Newer Raspberry Robin core versions | Early-bird APC process injection | Targets may include `cleanmgr.exe`, `rundll32.exe`, or `dllhost.exe`; execution is scheduled using `NtQueueApcThread` | Family-attributed; not independently visible before unpacking this DLL |
| Older Raspberry Robin versions | Process hollowing | Suspended `rundll32.exe` or `dllhost.exe` is mapped with malicious content and resumed | Historical family context; not directly confirmed here |

### Injection Conclusion

The most precise answer is:

1. **Directly observed in the submitted DLL:** executable-memory allocation and in-memory PE reconstruction followed by execution transfer.
2. **Reported for the associated Raspberry Robin core stage:** early-bird APC injection using `NtQueueApcThread` in newer variants.
3. **Reported historically for older Raspberry Robin stages:** process hollowing.

## Indicators of Compromise and Hunt Leads

### File Indicators

| Indicator Type | Value |
| --- | --- |
| SHA-256 | `05c6f53118d363ee80989ef37cad85ee1c35b0e22d5dcebd8a6d6a396a94cb65` |
| SHA-1 | `30f8eca869263bcf4c76acd013fd126039ff8c4a` |
| MD5 | `4ef38f237262847fd20783186b1579e0` |
| File type | 32-bit Windows DLL |
| Public classification | Raspberry Robin DLL |

### Static String and Metadata Leads

| Type | Value | Relevance |
| --- | --- | --- |
| Debug path | `o:\dir_for_builds\bldObjDir_67939ff4_616ca95a0_e24df0062\loader.cpp.bc.obj.pdb` | Build artifact / clustering lead |
| Export library identity | `dyayt27.dll` | Unusual loader metadata |
| Export name | `QbetdeiolralhwIe` | Unique forwarding-export lead |
| Export forwarder | `kernel32.WriteFile` | Benign-looking forwarding facade |
| ASCII string | `SElf.eXe` | Loader-path string |
| UTF-16 string | `TEstapp.exe` | Loader-path string |

## MITRE ATT&CK Mapping

| Technique | ID | Basis | Confidence |
| --- | --- | --- | --- |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Near-maximum entropy sections, encoded/runtime-resolved material, and obfuscated control flow | High, locally evidenced |
| Debugger Evasion | [T1622](https://attack.mitre.org/techniques/T1622/) | `IsDebuggerPresent` and exception/termination handling in executable code | High, locally evidenced |
| Process Injection: Asynchronous Procedure Call | [T1055.004](https://attack.mitre.org/techniques/T1055/004/) | ThreatLabz reports newer Raspberry Robin core performs early-bird APC injection using `NtQueueApcThread` | Family-attributed; requires unpacking to verify for this instance |
| Process Injection: Process Hollowing | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | ThreatLabz reports this technique in older Raspberry Robin versions | Historical family context only |

The local in-memory PE mapping behavior is recorded as a loader capability rather than asserted as a specific cross-process ATT&CK injection sub-technique, because no remote target-process interaction was statically established in the submitted outer layer.

## Defensive Considerations

- Treat the sample hash and matching artifacts as confirmed malicious indicators.
- Quarantine hosts or removable media containing this DLL pending incident-response review.
- Hunt for execution chains involving anomalous DLL loading followed by memory allocations marked executable and PE-like image reconstruction in private memory.
- Where Raspberry Robin activity is suspected, investigate anomalous suspended or early-stage execution involving `cleanmgr.exe`, `rundll32.exe`, and `dllhost.exe`, with particular attention to APC-queue and memory-allocation telemetry.
- Retain any additional files, execution telemetry, or memory images from affected systems to support unpacking and payload recovery.

## Conclusion

The supplied DLL is a high-confidence Raspberry Robin loader artifact and should be handled as malicious. Its static structure and disassembly demonstrate an intentionally concealed loader that reconstructs and executes a PE stage in memory. No separate clear-text dropper was statically recovered from the file. For the wider Raspberry Robin operation, published research identifies early-bird APC injection using `NtQueueApcThread` in newer core variants, with process hollowing documented in older versions; extracting this sample's runtime stage would be necessary to verify which core behavior it carries.

## Sources

### Public Research

1. Zscaler ThreatLabz, **Tracking Updates to Raspberry Robin**, 2025-08-06. Exact SHA-256 identification and newer-variant technical context: [https://www.zscaler.com/fr/blogs/security-research/tracking-updates-raspberry-robin](https://www.zscaler.com/fr/blogs/security-research/tracking-updates-raspberry-robin)
2. Zscaler ThreatLabz, **Unraveling Raspberry Robin's Layers: Analyzing Its Obfuscation Techniques and Execution Methods**, 2023-12-11. Loader structure and injection-method discussion: [https://www.zscaler.com/fr/blogs/security-research/unraveling-raspberry-robin-s-layers-analyzing-obfuscation-techniques-and](https://www.zscaler.com/fr/blogs/security-research/unraveling-raspberry-robin-s-layers-analyzing-obfuscation-techniques-and)
3. MITRE ATT&CK, **Process Injection: Asynchronous Procedure Call (T1055.004)**: [https://attack.mitre.org/techniques/T1055/004/](https://attack.mitre.org/techniques/T1055/004/)
4. MITRE ATT&CK, **Process Injection: Process Hollowing (T1055.012)**: [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)
5. MITRE ATT&CK, **Obfuscated Files or Information (T1027)**: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)
6. MITRE ATT&CK, **Debugger Evasion (T1622)**: [https://attack.mitre.org/techniques/T1622/](https://attack.mitre.org/techniques/T1622/)
