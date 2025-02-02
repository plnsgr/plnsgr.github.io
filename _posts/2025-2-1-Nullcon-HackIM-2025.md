---
title: "Nullcon HackIM CTF 2025"
date: 2025-2-1
categories: [CTF]
tags: [CTF]
image: assets/CTF/nullcon-2025/nullcon-sponsor-banner.jpg
---

# flag checker

| **Description**                          |
|------------------------------------------|
| All you need to do is to guess the flag! |

---

## Observation

Running in **IDA** , upon entering the text, it will check on `sub_127A` to see the input return value. Below is `main function`:

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[40]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the flag: ");
  fgets(s, 35, stdin);
  s[strcspn(s, "\n")] = 0;
  if ( (unsigned int)sub_127A(s) )
    puts("Correct!");
  else
    puts("Incorrect!");
  return 0LL;
}
```

Below is `sub_127A` ,first the code will check the length (**strlen(a) != 34**), and then it go to `sub_11E9`. Lastly, the validation start with not equal (**!=**) condition of `bytes_2020[i]` will check if the input was correct each bytes:

```c
__int64 __fastcall sub_127A(const char *a1)
{
  int i; // [rsp+1Ch] [rbp-34h]
  char v3[40]; // [rsp+20h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( strlen(a1) != 34 )
    return 0LL;
  sub_11E9(a1, v3);
  for ( i = 0; i <= 33; ++i )
  {
    if ( v3[i] != byte_2020[i] )
      return 0LL;
  }
  return 1LL;
}
```

`sub_11E9`, looks like the formula start here, it takes two memory addresses, **a1** (input) and **a2** (output). It loop for **34 times**, processing each byte from **a1** by first **XORing** it with **0x5A**. Then, it performs a **bitwise** transformation on the stored byte by rotating it right by **5 bits and left**.:

```
_BYTE *__fastcall sub_11E9(__int64 a1, __int64 a2)
{
  _BYTE *result; // rax
  int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 33; ++i )
  {
    *(_BYTE *)(i + a2) = (*(_BYTE *)(i + a1) ^ 0x5A) + i;
    result = (_BYTE *)(i + a2);
    *result = (*result >> 5) | (8 * *result);
  }
  return result;
}
```


Looking at the *.rodata section* of the `byte_2020`, and array was stored in hex. we can change it to decimal and start decode:

Before:

```assembly
.rodata:0000000000002020 ; _BYTE byte_2020[34]
.rodata:0000000000002020 byte_2020       db 0F8h, 0A8h, 0B8h, 21h, 60h, 73h, 90h, 83h, 80h, 0C3h
.rodata:0000000000002020                                         ; DATA XREF: sub_127A+63↑o
.rodata:0000000000002020                 db 9Bh, 80h, 0ABh, 9, 59h, 0D3h, 21h, 0D3h, 0DBh, 0D8h
.rodata:0000000000002020                 db 0FBh, 49h, 99h, 0E0h, 79h, 3Ch, 4Ch, 49h, 2Ch, 29h
.rodata:0000000000002020                 db 0CCh, 0D4h, 0DCh, 42h
```

After:

```
.rodata:0000000000002020 ; _BYTE byte_2020[34]
.rodata:0000000000002020 byte_2020       db 248, 168, 184, 33, 96, 115, 144, 131, 128, 195, 155
.rodata:0000000000002020                                         ; DATA XREF: sub_127A+63↑o
.rodata:0000000000002020                 db 128, 171, 9, 89, 211, 33, 211, 219, 216, 251, 73, 153
.rodata:0000000000002020                 db 224, 121, 60, 76, 73, 44, 41, 204, 212, 220, 66
```

---

## Solution

Original Process: The C function sub_11E9 applies the following steps to each byte:
1. XORs the byte with 0x5A
2. Adds the current index
3. Rotates the resulting byte (right by 5 bits, left by 3 bits)

Reverse Process: To reverse the transformation here how it done:
1. Reverses the bitwise rotation
2. Subtracts the index value
3. **XOR** with **0x5A** to restore the original byte

Code:

```python
def rev(e):
    return bytes(((b << 5 & 0xFF | b >> 3) - i & 0xFF) ^ 0x5A for i, b in enumerate(e))

e = [248,168,184,33,96,115,144,131,128,195,155,128,171,9,89,211,33,211,219,216,251,73,153,224,121,60,76,73,44,41,204,212,220,66]

print(rev(e).decode())
```

---

### **Execution**
```bash
┌──(myenv)(osiris㉿ALICE)-[~/Downloads/CTF/nullcon/rev/flag_check]
└─$ python sol.py
ENO{R3V3R53_3NG1N33R1NG_M45T3R!!!}
```


---

# scrambled

| **Description**                          |
|------------------------------------------|
| I am so close to finding the secret of immortality, however the code has been lost for ages. |
| I managed to get all the parts back and even got to know that the key to success is one bite of the forbidden fruit (the scrambled eggs!). |
| Can you help me to decipher the rest? |


**main.py**:

```python
import random

def encode_flag(flag, key):
    xor_result = [ord(c) ^ key for c in flag]
    chunk_size = 4
    chunks = [xor_result[i:i+chunk_size] for i in range(0, len(xor_result), chunk_size)]
    seed = random.randint(0, 10)
    random.seed(seed)
    random.shuffle(chunks)
    scrambled_result = [item for chunk in chunks for item in chunk]
    return scrambled_result, chunks

def main():
    flag = "REDACTED"
    key = REDACTED
    scrambled_result, _ = encode_flag(flag, key)
    print("result:", "".join([format(i, '02x') for i in scrambled_result]))

if __name__ == "__main__":
    main()
```

**output.txt**:

```
result: 1e78197567121966196e757e1f69781e1e1f7e736d6d1f75196e75191b646e196f6465510b0b0b57
```

---

---

## Obversation
The `main.py` script scrambles the flag by:
1. **XOR** each character with a key.
2. Splitting the result into chunks of **4 bytes**.
3. Shuffling the chunks using a **random seed**.

---

## Solution
To decode the scrambled flag, the solution script:
1. Converts the scrambled hex output back into **bytes**.
2. Reverses the shuffling using brute force on the **seed (range 0-10)**.
3. **XORs each byte** with the key to retrieve the original flag.

```python
import random

def decode_flag(scrambled_result, key, seed):
    chunk_size = 4
    chunks = [scrambled_result[i:i+chunk_size] for i in range(0, len(scrambled_result), chunk_size)]
    random.seed(seed)
    shuffled_indices = list(range(len(chunks)))
    random.shuffle(shuffled_indices)
    unshuffled_chunks = [None] * len(chunks)
    for i, idx in enumerate(shuffled_indices):
        unshuffled_chunks[idx] = chunks[i]
    unshuffled_result = [item for chunk in unshuffled_chunks for item in chunk]
    flag = ''.join([chr(c ^ key) for c in unshuffled_result])
    return flag

def main():
    scrambled_hex = "1e78197567121966196e757e1f69781e1e1f7e736d6d1f75196e75191b646e196f6465510b0b0b57"
    scrambled_result = [int(scrambled_hex[i:i+2], 16) for i in range(0, len(scrambled_hex), 2)]
    key = 42
    for seed in range(11):
        try:
            flag = decode_flag(scrambled_result, key, seed)
            if flag.startswith('ENO{'):
                print(f"Seed: {seed}, Flag: {flag}")
                break
        except Exception as e:
            print(f"Error with seed {seed}: {e}")
            continue

if __name__ == "__main__":
    main()
```

---

### **Execution**
```bash
┌──(myenv)(osiris㉿ALICE)-[~/Downloads/CTF/nullcon/rev/scramble]
└─$ python solution.py
Seed: 10, Flag: ENO{5CR4M83L3D_3GG5_4R3_1ND33D_T45TY!!!}
```


