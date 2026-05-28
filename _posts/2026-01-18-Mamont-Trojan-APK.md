---
title: "Mamont - Trojan APK Analysis"
date: 2026-01-18
categories: [Malware Analysis]
tags: [Malware Analysis]
image: assets/logo/ida-ascii-art.png
---

# Information

| SHA256 hash: | c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64 |
| --- | --- |
| SHA1 hash: | 4d44166162cf6a16c1daffa7d40f1c5b0c47b3ca |
| MD5 hash: | 9273aa2e465996dde7ad912424f06be2 |
| File name: | Фото-2025.08.10.apk |
| File size: | 1'484'158 bytes |
| First seen: | 2025-12-28 15:17:05 UTC |
| Last seen: | *Never* |
| File type: | apk |
| MIME type: | application/zip |

## virustotal

![](https://www.notion.so/image/attachment%3Af7c5f4e9-3d1d-47e6-ab1a-80201ebc805f%3Aimage.png?table=block&id=2ec26e60-5e7e-802d-bc03-ed242eae1ee7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Sample:

reference: [bazaar.abuse.ch](https://bazaar.abuse.ch/sample/c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64/)

reference: [VirusTotalVirusTotal](https://www.virustotal.com/gui/file/c6f2553734e73ffbafab7acba0194ad545cdce3364e60e2014f37b0e49e1ab64)

---

# Introduction

Mobile trojan malware in the form of APK files has become one of the most common threats to Android users. The malware disguises itself as a legitimate application to trick users into installation. Once installed, it operates in the background to steal sensitive information, send stolen data through Telegram channels, and possibly perform remote control tasks. The report highlights the significance of mobile malware, the risks associated with messaging apps like Telegram, and the methodology used to analyze the sample.

## Executive Summary

The analyzed APK appears as a standard Android app but contains hidden malicious code. Its true function is to connect to Telegram channels for exfiltration and control. The malware requests unnecessary permissions such as access to contacts, storage, messages, and network. These permissions allow it to interact with the device covertly, making it highly dangerous for both personal and organizational users. Attackers modify or embed malicious code into legitimate-looking apps. Users unknowingly install them, granting permissions that allow the malware to operate in the background. The motive goal is to stealing messages,contact,camera, OTP that can lead to loss of personal privacy.

---

# Tools

tools that will be used throughout this analysis:

1. Detect It Easy (DIE)
1. JADX
1. Android Studio
1. Burp Suite

---

# Analysis

## Observation

The analyzed APK is an Android application built primarily with Kotlin, incorporating native C/C++ libraries for multiple architectures (ARM, ARM64, x86, x86\_64). It was compiled using Android SDK (API 21–36) and Android NDK r25c. The main executable code resides in `classes.dex`, targeting the Dalvik VM for 32-bit devices. Additionally, the APK includes compressed resources such as `publicsuffixes.gz` and native shared libraries (`libandroidx.graphics.path.so`) for both 32-bit and 64-bit platforms, indicating broad device compatibility. Here highlighted version on how the compilation structed of this apk:

- **Platform:** Android (Universal, supports multiple architectures)
- **Language:** Kotlin & C/C++ (via Android NDK)
- **Build Tools:** Android SDK (API 21–36), Android NDK r25c
- Arch list: arm64-v8a, armeabi-v7a, x86, x86\_64

![](https://www.notion.so/image/attachment%3Ac8206fb4-593f-4c9a-ae73-2c9eec3433dd%3Aimage.png?table=block&id=2ec26e60-5e7e-80c7-a805-dc303469c9e1&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## Static Analysis

Using jadx. headed to central configuration of Android application which is **AndroidManifest.xml**. This is to understanding the defining permissions, components, and intent filters. Checking it first allows analysts to quickly identify suspicious permissions, potentially malicious activities, and the app’s intended behavior before deeper code inspection.

![](https://www.notion.so/image/attachment%3A69d3b832-cf3b-4903-9036-7dbd6a100e86%3Aimage.png?table=block&id=2ec26e60-5e7e-8029-a3da-cecb65ba025a&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1280&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Resources/AndroidManifest.xml

The APK requests excessive permissions beyond normal app behavior and defines numerous exported services and receivers that can handle SMS, MMS, and notifications. Combined with obfuscated component names and Firebase integration, this strongly suggests the APK is designed for data exfiltration, remote control, and persistent monitoring of the device

permission:

![](https://www.notion.so/image/attachment%3Aa17a0e59-ffbe-4ff3-a2b8-f929bd0e3e45%3Aimage.png?table=block&id=2ec26e60-5e7e-806e-8561-c8a628279997&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ae7af8298-2855-4d6a-94d4-f2d48fbe6034%3Aimage.png?table=block&id=2ec26e60-5e7e-809c-94d0-f99af5114c21&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

services:

![](https://www.notion.so/image/attachment%3A5fb643c6-e2c9-49b0-b1a2-d4a315351af3%3Aimage.png?table=block&id=2ec26e60-5e7e-80cd-bdbd-f531f1e439ab&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

**Critical Permissions Requested** *(potentially malicious or privacy-sensitive)*

- SMS: `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `SMS_SENT`, `SMS_DELIVERED`
- Contacts & Accounts: `READ_CONTACTS`, `WRITE_CONTACTS`, `GET_ACCOUNTS`
- Phone state: `READ_PHONE_STATE`, `READ_PHONE_NUMBERS`, `CALL_PHONE`
- System/Network: `INTERNET`, `ACCESS_NETWORK_STATE`, `QUERY_ALL_PACKAGES`, `RECEIVE_BOOT_COMPLETED`, `WAKE_LOCK`
- Notifications & Foreground: `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE`

**Activity**

entrypoint of the application start (main function) on the activity section which located on `chimera.best.panel.FQEndmTHnhCpoUnvNq`

![](https://www.notion.so/image/attachment%3A55fa17bf-4fb0-40f4-aece-650d81b09e8a%3Aimage.png?table=block&id=2ec26e60-5e7e-8076-b872-d7478eac00c2&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1370&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Main Activity

**Location:** `sources\chimera.best.panel\FQEndmTHnhCpoUnvNq.java`

The presented source code is heavily obfuscated, making direct reading difficult. The decoding process taking abit time than trying to fully deobfuscate every class and method.

![](https://www.notion.so/image/attachment%3Ae551b4aa-0e3e-4e75-9581-5b7d61772027%3Aimage.png?table=block&id=2ec26e60-5e7e-80bf-81f9-f51e0924d83d&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

notice the function call of `qJMbAezHp.ujkitozmfsyqth`

![](https://www.notion.so/image/attachment%3Aeb3e0867-1cf1-4d31-87f9-cf0caa632f9e%3Aimage.png?table=block&id=2ec26e60-5e7e-802e-bcab-c11ec995b49f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

**FQEndmTHnhCpoUnvNq.java** serves as the primary entry point and orchestrator for this Android banking trojan. Upon launch, the Activity establishes communication with a command-and-control server to retrieve critical configuration parameters, including the attacker's phone number (RETRANSMITTER\_PHONE\_NUMBER) and a whitelist of targeted financial applications (PUSH\_WHITELIST\_KEYS). The malware implements a 17-second timeout loop waiting for this configuration; if the C2 server is unreachable, the application deliberately crashes to avoid detection through behavioral analysis.  
Once configured, the Activity initializes a full-screen WebView with aggressive permissions (JavaScript enabled, file access, DOM storage) to display attacker-controlled phishing pages that mimic legitimate banking interfaces. Simultaneously, it requests elevation to default SMS application status using platform-appropriate APIs (RoleManager for Android 10+ or legacy Telephony intents for older versions), granting complete access to intercept, read, and send SMS messages—particularly targeting two-factor authentication codes from financial institutions.  
The implementation employs user retention techniques including back button hijacking that prevents easy exit from the phishing interface, file upload capabilities for document exfiltration, and persistent permission prompting until SMS access is granted. This combination of credential phishing, SMS interception, and C2-driven configuration creates a sophisticated attack vector targeting Russian-speaking users of banking applications listed in the decoded strings (Sberbank, Tinkoff, Alfa Bank, VTB, etc.).

### SMS/Notification Interception

**Location:** `sources\acMDegCzSEifNwxeufPp\OPnEFgTiSobaaZMQyA.java`

Handles SMS forwarding to attacker's number

![](https://www.notion.so/image/attachment%3Adfe6a783-fc4f-47b0-b403-3b5828448502%3Aimage.png?table=block&id=2ee26e60-5e7e-806d-bfc0-d1b9a8431f78&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Configuration/Storage Manager

**Location:** `sources\pTUpXgpd\knhWGwDvyVUGmiCIdfq.java`

This class stores, updates, and limits daily usage/heartbeat records per key in Android SharedPreferences, keeping only recent dates and tracking counts. Flow will be explain in below:

**Flow:**

- It saves dates (per UTC day) for each key.
- It keeps a global daily marker to avoid duplicate actions in one day.
- It limits total stored events (max 30) and removes the oldest when full.
- It cleans old dates and returns pending records when needed.

![](https://www.notion.so/image/attachment%3Ae931efbb-b416-41ca-a14f-8d091051deed%3Aimage.png?table=block&id=2ee26e60-5e7e-80fa-84d4-e0bcd10cdfec&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ab2f723ca-b962-4766-a012-af99ff6924ee%3Aimage.png?table=block&id=2ee26e60-5e7e-8023-8cba-d81f4ff0b677&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

**Location:** `sources\pTUpXgpd\nwnQKTUGhGInbImg.java`

This class initializes a shared preferences helper, stores device info (model and Android version), and exposes saved app configuration values like client ID and web view URL.

![](https://www.notion.so/image/attachment%3A3b3f992e-3d8f-4d5f-8069-5da35f23037a%3Aimage.png?table=block&id=2ee26e60-5e7e-80d6-ba80-cdb48d5ac821&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### WebView File Upload Handler

**Location:** `sources\mdQPPWonHAmHwOYj\nwnQKTUGhGInbImg.java`

This class handles file upload requests from a WebView by opening the Android file picker and returning the selected file to the web page. Flow process:

- It replaces any old file callback.
- It launches the system file chooser.
- It sends the chosen file back to the WebView.

![](https://www.notion.so/image/attachment%3Aeb475407-3925-4a26-a157-b3f99b5d01d9%3Aimage.png?table=block&id=2ee26e60-5e7e-8097-890e-ee5c8ded5dee&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### String Decoder/Obfuscation \[I STOPPED HERE\]

**Location:** `sources\SGfdSCgRDRfmflGigM\qJMbAezHp.java`

ujkitozmfsyqth() method used everywhere from encryption string. This class use to decodes all base64 obfuscated strings

![](https://www.notion.so/image/attachment%3Ae0001b55-2d04-45e2-9140-b94d58d88dd1%3Aimage.png?table=block&id=2ec26e60-5e7e-806b-9b67-cf46c6180590&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### **Firebase Messaging Service**

**Location:** `sources\com\google\firebase\messaging\FirebaseMessagingService.java`

Receives remote commands from attackers.

![](https://www.notion.so/image/attachment%3Ada434aa4-92bc-4f4c-91bb-d799f632d312%3Aimage.png?table=block&id=2ee26e60-5e7e-804e-932e-d5b46738dbd3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Encrypted method

now the encryption headed to `TJsCxHfLdliFyglAE.nwnQKTUGhGInbImg.liatbvahhplwimctf` to parse the str and str2 to decode base64 first then parse the original text. and then XOR both text and return it back to UTF8.

Concept:

![](https://www.notion.so/image/attachment%3Af283c24e-3acc-4368-8693-7ac61d9134ba%3Aimage.png?table=block&id=2ec26e60-5e7e-8024-8aa9-f20ce71fbb42&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A154851e5-67da-467f-9416-c9116aeaafc0%3Aimage.png?table=block&id=2ec26e60-5e7e-80a7-8163-f7b5e46c9388&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Source code/ghruvjqZJCdxlWe/knhWGwDvyVUGmiCIdfq

more cipher can be seen. an alternating transposition that combine both cipher into one

![](https://www.notion.so/image/attachment%3Ac96c79b7-9d05-4e9a-9b67-21bddb6d960c%3Aimage.png?table=block&id=2ed26e60-5e7e-8007-a300-d35ac994ff79&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ad87a00ea-44c1-4125-bca0-5e6b71ef9455%3Aimage.png?table=block&id=2ed26e60-5e7e-80bf-b502-e2b2df27c0c7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1390&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Concept:

![](https://www.notion.so/image/attachment%3A9588f9ed-c39a-4aea-b07e-11bf3adb6931%3Aimage.png?table=block&id=2ed26e60-5e7e-809a-8e0a-c0fc8f2c5098&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Export source code:

to extract all the encrypted text

![](https://www.notion.so/image/attachment%3A6cf2e29d-d5d8-46ca-b884-23f3ce7be67d%3Aimage.png?table=block&id=2ec26e60-5e7e-8012-9003-c15fc669aa90&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=880&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

save location

![](https://www.notion.so/image/attachment%3Ab877bc78-6dc6-4be6-9327-4928b865a466%3Aimage.png?table=block&id=2ec26e60-5e7e-8066-b2b3-c46339fc37a5&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=760&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

```
λ grep -r --no-filename -o "qJMbAezHp.ujkitozmfsyqth([^)]*)" . > collectedtext.txt
```

![](https://www.notion.so/image/attachment%3Ac0887aed-aec1-4c6c-b2ec-2c6aa93e5294%3Aimage.png?table=block&id=2ec26e60-5e7e-80cf-82ec-e676d9250fc1&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1370&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

trying to read the few file. we already extracted all the encrypted text. next we need to decode all of it

![](https://www.notion.so/image/attachment%3Ac7a99e13-5838-4f51-8438-3bde626a4029%3Aimage.png?table=block&id=2ec26e60-5e7e-80eb-b606-f3708f06a417&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Decoding

taking the encrypted text

making a simple script to quicken the analysis process taking a few steps which is

- Collecting pattern of `ujkitozmfsyqth\("([^"]+)",\s*"([^"]+)"\)` using regex
- Removing `\n` is required for valid Base64 decoding
- XOR string hiding used across the APK

script:

```
import base64
import re

def xor_bytes(a, b):
    return bytes(a[i] ^ b[i % len(b)] for i in range(len(a)))

pattern = re.compile(r'ujkitozmfsyqth\("([^"]+)",\s*"([^"]+)"\)')

with open("collectedtext.txt", "r") as f:
    for line in f:
        m = pattern.search(line)
        if not m:
            continue

        enc1 = m.group(1).replace("\\n", "")
        enc2 = m.group(2).replace("\\n", "")

        b1 = base64.b64decode(enc1)
        b2 = base64.b64decode(enc2)

        dec = xor_bytes(b1, b2)

        try:
            out = dec.decode("utf-8")
        except:
            out = dec

        print(f"{enc1}:{enc2} = {out}")
```

output:

IP:

![](https://www.notion.so/image/attachment%3A697e4c2d-76bb-43ad-b63f-7c533d283b3e%3Aimage.png?table=block&id=2ec26e60-5e7e-8052-a5b9-c571c04ef9be&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=970&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Aac3e986c-adec-457c-9baf-4f3762736b76%3Aimage.png?table=block&id=2ec26e60-5e7e-80f0-9f1b-cf4160734e8f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A9ec1aaa5-fa68-4056-a3cb-f24c2eb0e13a%3Aimage.png?table=block&id=2ec26e60-5e7e-80e4-a57d-c7e3bc2cd40d&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

URL:

![](https://www.notion.so/image/attachment%3Ad6f5336c-b895-4444-8755-a7444c04aaff%3Aimage.png?table=block&id=2ec26e60-5e7e-80be-82fd-dcc2440b1587&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A83d5d822-8024-441a-89fd-7ddb98de3d34%3Aimage.png?table=block&id=2ec26e60-5e7e-8038-9e3c-fb9b266f644f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Add0da6c9-1c1c-49eb-9f34-02cd6182f826%3Aimage.png?table=block&id=2ec26e60-5e7e-80b4-9663-e3c74ac9bed7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Telegram and Firebase URL:

![](https://www.notion.so/image/attachment%3A1031652f-a074-4add-91a0-af2acde65459%3Aimage.png?table=block&id=2ec26e60-5e7e-80b4-a7ca-d25d691d7b8c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A8eaff0ac-c853-447a-b983-fedd4b8c1bea%3Aimage.png?table=block&id=2ec26e60-5e7e-8006-a459-cd7f48ada933&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A40b9d319-b71d-46ba-a449-6308cbbe6f9f%3Aimage.png?table=block&id=2ec26e60-5e7e-805c-8707-c164945631ea&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

## Dynamic Analysis

setup burp and android emulator. proxy and port must be the same. in this sample using 311337 port with hostname of 127.0.0.1

![](https://www.notion.so/image/attachment%3A6138883a-ea0b-45e6-acd2-0b62b4634bed%3Aimage.png?table=block&id=2ed26e60-5e7e-8039-b83c-c9cdaed38104&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

install the application on mobile. it will shows an photo logo

![](https://www.notion.so/image/attachment%3A87add6bf-dec8-4d32-9f64-4937c26dcfa6%3Aimage.png?table=block&id=2ed26e60-5e7e-80e9-b2e3-c844170e5a81&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=810&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

permission:

![](https://www.notion.so/image/attachment%3A5eb3d0e2-b82e-41eb-8ef2-682c618560c8%3Aimage.png?table=block&id=2ed26e60-5e7e-8098-92c2-f02cf81aca18&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=780&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ac1f58bd9-55aa-444a-9100-38ba475df5c2%3Aimage.png?table=block&id=2ed26e60-5e7e-80f5-b512-c12c9e5215a1&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=830&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

on app battery usage. click open:

![](https://www.notion.so/image/attachment%3A7ad45c94-c2e9-4800-b8ea-a7064ea17afe%3Aimage.png?table=block&id=2ed26e60-5e7e-804f-b124-efada56d63af&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=820&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

and the url will be triggered:

![](https://www.notion.so/image/attachment%3A2a58726c-e5a8-4e42-9220-2ef744285e95%3Aimage.png?table=block&id=2ed26e60-5e7e-8001-96bf-ff75b92d6d4c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A3ec0c3ec-09cc-441a-95dc-1a7104d088b4%3Aimage.png?table=block&id=2ed26e60-5e7e-80fa-b531-d51b00a4b26b&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A908f5cc3-3f8c-42ea-89a2-6053ab32940c%3Aimage.png?table=block&id=2ed26e60-5e7e-801f-ab72-fff0a3013a5a&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Checking back the `gettingData` and `event` on our collected decode process found it exist from the file:

![](https://www.notion.so/image/attachment%3Ad5eb3207-0376-4316-aeb7-54a2e3562b5a%3Aimage.png?table=block&id=2ed26e60-5e7e-806e-b6ec-eac816c05fdc&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=950&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

this is where the encrypted of the operation stored the encrypted text:

![](https://www.notion.so/image/attachment%3Ac89d8ef5-a2a6-460f-ab67-13343b65fd40%3Aimage.png?table=block&id=2ed26e60-5e7e-80f1-874f-ca15f94b531d&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

the function that make POST request:

![](https://www.notion.so/image/attachment%3Aa17f6cc2-16fc-4f09-be3e-6c92f5d2923a%3Aimage.png?table=block&id=2ed26e60-5e7e-8070-b03e-c4316b6db2c3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

---

# **Conclusion**

The Trojan APK analyzed exploits Telegram as a covert communication channel. It demonstrates how social engineering, combined with legitimate-looking apps, can bypass user awareness and security mechanisms. Awareness of permission misuse and network behavior monitoring is crucial for preventing such threats.
