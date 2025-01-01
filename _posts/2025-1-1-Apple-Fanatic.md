
# CTF

Welcome to the bunker, agent. We’ve evaluated your performance in solving (and guessing) our formative challenges and are excited to offer you a trial position at Elves Intelligence.

It appears that a _secret society_ has become interested in our immense data on the world’s children—including names, birthdates, likes, dislikes, and social security numbers. (Don’t ask me why we store their social security numbers in plain text.)

Here at Elves Intelligence, we stop our threats at the source. The best defense is a good offense. (Usually?)

A member of the secret society dropped a note in Santa’s presents sack overnight. Somehow, they got past our sleeping elf watching the security cameras. Thankfully, the person didn’t seem to know [OPSEC](https://en.wikipedia.org/wiki/Operations_security) and included their personal website on the note. The note read:

> We will be watching you.  
> - The Secret Society of K.U.N.A.L  
> [https://apple-fanatic.csd.lol/](https://apple-fanatic.csd.lol/)

The only thing they’ve taken with them is an apple from the sack of presents. Weird.

Our top SOC elves gathered two pieces of information from their initial observation of the site:

1. This person seems to like apples. Like, a lot.
2. The person claims a flag is intricately hidden on the site under a name that no one will be able to guess.

Good luck, agent. Santa is watching.

---

_**You are only allowed to test in the scope `https://apple-fanatic.csd.lol/*`.** Blind brute-force request sending (e.g. using tools like DirBuster) can trigger Cloudflare rate limits. Do not attempt to bypass Cloudflare limits. Therefore, if you wish to brute-force, please limit your wordlists or attack scope._

# Solution

when we go to the website, we can see the following text at the bottom of the page:

```
Fun fact: I love apples so much, I am Apple's biggest supporter. You will never see me use a Windows or Linux system (ew). _Especially not for creating this site :^)_
```

This tells us that the website is based on Mac, which will help us a lot.

After taking a look at the source code of the website, we can see an interesting directory:

```html
<script src="/my-secret-vault-of-scripts-n-files/ai-script.js"></script>
```

The thing about Apple based devices Is that when you create a folder , a file `.DS_Store` appears . This file stores metadata of the files inside of the folder. So, if we can get this file, we can find what files are there.

To do this, we can go to this link:

```
https://apple-fanatic.csd.lol/my-secret-vault-of-scripts-n-files/.DS_Store
```

on linux, we can just run `xxd .DS_Store` to look at the data of the file. on windows you can use HxD. 

this is how to find the information using `Xdd`

While running xdd, we can see the following part of the output:
```
00000140: ffff 0000 0000 002b 0074 0068 0065 002d  .......+.t.h.e.-
00000150: 0062 0069 0072 0074 0068 002d 0064 0061  .b.i.r.t.h.-.d.a
00000160: 0074 0065 002d 006f 0066 002d 006d 0079  .t.e.-.o.f.-.m.y
00000170: 002d 0062 0065 006c 006f 0076 0065 0064  .-.b.e.l.o.v.e.d
00000180: 002d 0061 0070 0070 006c 0065 002d 0074  .-.a.p.p.l.e.-.t
00000190: 0072 0065 0065 002e 0074 0078 0074 496c  .r.e.e...t.x.tIl
000001a0: 6f63 626c 6f62 0000 0010 0000 011d 0000  ocblob..........
``` 

we can get out the `the-birth-date-of-my-beloved-apple-tree.txt` from this text.

now lets take a look at `https://apple-fanatic.csd.lol/my-secret-vault-of-scripts-n-files/the-birth-date-of-my-beloved-apple-tree.txt`


the text we see is:

```
😔 csd{5H3_w45_80RN_0N_7H3_d4y_0f_Chr157M4Z}
```

Flag: `csd{5H3_w45_80RN_0N_7H3_d4y_0f_Chr157M4Z}`



