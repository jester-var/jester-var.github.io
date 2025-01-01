---
title: "Logical exclusivity - Advent Of CTF"
date: 2025-01-01 00:00:00 -0800
categories: CTF AoCTF
tags: crypto
---

# CTF

rotten bxgxnnxngs

```
64 6e 63 74 7f 4c 7a 37 7b 3c 50 37 3c 36 3e 59 79 3e 59 36 3a 50 37 3a 37 43 3b 37 72
```

# Solution

This looks like hex, so lets use cyberchef.

the following string gives `dnctLz7{<P7<6>Yy>Y6:P7:7C;7r` after decoding. 
This doesn't really look like anything so lets use magic with intensive mode to find any clues.

One of the outputs, `XOR({'option':'Hex','string':'f'},'Standard',false)` Gives us `kal{pCu8t3_8391Vv1V95_858L48}`, Which looks really similar to the flag format, `csd{}`.

Since the letters are different, they are probably encrypted by ROT, so let's run ROT13 Brute.

One of the answers from the brutes starts with csd, so it is the flag.

flag: `csd{hUm8l3_8391Nn1N95_858D48}`

