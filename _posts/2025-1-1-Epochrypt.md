---
title: "Epochrypt - Advent Of CTF"
date: 2025-01-01 00:00:00 -0800
categories: CTF AoCTF
tags: crypto
---

# CTF

It's time to test out Tibel Elf's new encryption method. He says once you encrypt it, you can't unencrypt it. Sureeee... Connect with `nc ctf.csd.lol 3551`.

Attachment main.py:

```python
#!/usr/local/bin/python
import time
import base64 as b64
from pwn import xor

def epochrypt(enc):
    bits = bytes([(b + 3) % 256 for b in enc])
    based = b64.b64encode(bits)
    epc = str(int(time.time())).encode()
    final = xor(based, epc)
    print(final.hex())


def menupage():
    print("Epochrypt v1.0")
    print("\"The Dynamic Encryption Method\"")
    print("------------------------------------")
    print("1. Encrypt Text")
    print("2. View Encrypted Flag")
    print("3. Check Flag")
    print("4. Exit Program")


try:
    while True:
        menupage()
        option = input("Enter option here: ")
        if option == "1":
            textToEncrypt = input("Enter String: ")
            epochrypt(textToEncrypt.encode())
            exit(0)
        if option == "2":
            with open("/app/flag.txt", "rb") as file:
                flag = file.read()
            epochrypt(flag)
            exit(0)
        if option == "3":
            checkFlag = input("Enter flag here to check: ")
            with open("/app/flag.txt", "rb") as file:
                flag = file.read()
                if flag in (checkFlag + "\n").encode():
                    print("Correct! You got it, now go submit that thang.")
                    exit(0)
                else:
                    print("*BUZZ* That ain't it bud :(")
                    exit(0)
        if option == "4":
            print("bye bye!")
            exit(0)

except KeyboardInterrupt:
    print("CTRL + C detected, Quitting program...")
```

# Solution

When we connect to netcat, we get the flag encrypted:
```
jstr$ nc ctf.csd.lol 3551
Epochrypt v1.0
"The Dynamic Encryption Method"
------------------------------------
1. Encrypt Text
2. View Encrypted Flag
3. Check Flag
4. Exit Program
Enter option here: 2
6b59695b555a540b6a647f5e667157597954700757707a0666607e0b5b025c7677640e0a
```

the way the code works is that it shifts bytes by 3, encodes the bytes using base64, XORs with the epoch time and outputs the string in hex.

to reverse that, we have to decode the hex, try to guess XOR using the current epoch times to save time, decode using base64, shift bytes and output the text. 

But since there might be many different outputs from XOR bruteforcing, we have to check the patterns.

the patterns are:
1. the output must include `{ }`
2. the output must include only numbers, letters and underscore. (Since that is the the format the CTF is using for the flags)

This is the code I've wrote that reverses the process.

``` python
import time
import base64 as b64
from pwn import xor
import re
def reverse_epochrypt(enc_hex, start_epoch, end_epoch):
    enc = bytes.fromhex(enc_hex)
    valid_flags = []
    for epoch in range(start_epoch, end_epoch):
        epc = str(epoch).encode()
        try:
            bits = b64.b64decode(xor(enc, epc) + b"=" * ((4 - len(xor(enc, epc)) % 4) % 4)) 
            flag = bytes([(b - 3) % 256 for b in bits]).decode()
            if re.match(r"^[A-Za-z0-9_{}]+$", flag) and "{" in flag and "}" in flag:
                valid_flags.append((flag, epoch))
        except Exception:
            pass 
    return valid_flags

if __name__ == "__main__":
    enc_hex = "6b59695b555a560560647f5e667157597b5a7a0757707a0666607c0551025c7677640e0a"
    start_epoch = int(time.time()) - 86400
    end_epoch = int(time.time()) + 3600
    flags = reverse_epochrypt(enc_hex, start_epoch, end_epoch)
    for flag, epoch in flags:
        print(f"{flag} . {epoch}")
```

Now let's run it !

```
jstr$ python main.py
csd{d6J0_M4d30xy_4N_6xf}
 . 1735375040
csd{d6JP_M4d30vy_4N_6xF}
 . 1735375042
csd{d2F0_M4d3o8y_4N_2lf}
 . 1735375430
csd{d2FP_M4d3o6y_4N_2lF}
 . 1735375432
csd{d2J0_M4d3pxy_4N_2xf}
 . 1735375440
csd{d2JP_M4d3pvy_4N_2xF}
 . 1735375442
csd{d4F0_M4d3O8y_4N_4lf}
 . 1735375630
csd{d4FP_M4d3O6y_4N_4lF}
 . 1735375632
csd{d4J0_M4d3Pxy_4N_4xf}
 . 1735375640
csd{d4JP_M4d3Pvy_4N_4xF}
 . 1735375642
csd{d3F0_M4d3_8y_4N_3lf}
 . 1735375730
csd{d3FP_M4d3_6y_4N_3lF}
 . 1735375732
```

Due to XOR bruteforcing, we got multiple answers. so we have to find out which one is correct. We can do this either by using the app, since it has option 3 which checks the flag, or just take a look at the text and find out which one is close to human words (I'm a lazy person, so i chose number 2)

the flag that looked most like human text was `csd{d3F0_M4d3_8y_4N_3lf}` since it decrypts to `Defo_Made_By_An_Elf` and that fits the description of the ctf. but just in case let's test is using the app.

```
jstr$ nc ctf.csd.lol 3551
Epochrypt v1.0
"The Dynamic Encryption Method"
------------------------------------
1. Encrypt Text
2. View Encrypted Flag
3. Check Flag
4. Exit Program
Enter option here: 3
Enter flag here to check: csd{d3F0_M4d3_8y_4N_3lf}
Correct! You got it, now go submit that thang.
```

flag is : `csd{d3F0_M4d3_8y_4N_3lf}`
