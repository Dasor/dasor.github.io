---
layout: single
title: Impossible Password hackthebox writeup
excerpt: "Simple yet didactic reverse engineering challenge"
date: 2022-12-15
classes: wide
header:
  teaser: /assets/images/ImpossiblePass/ghidra.svg
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - writeup
tags:
  - hackthebox
  - challenge
  - reverse engineering
---

![](/assets/images/ImpossiblePass/ghidra.svg)

## Introduction

In this post I will solve the htb challenge *Imposible Password*, I thought this challenge was fairly simple yet also illustrates a really good example of how to crack a binary with password protection. Think about it as if you were cracking an old game that required a key.

## Solving the challenge

Once we unzip the main file, we are presented with a binary that waits for user input

```shell
[dasor@archlinux ~/htb/impossible_pass]$ file Imposible_Password.zip
Imposible_Password.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
[dasor@archlinux ~/htb/impossible_pass]$ chmod +x impossible_password.bin
[dasor@archlinux ~/htb/impossible_pass]$ ./impossible_password.bin
* test
[test]
[dasor@archlinux ~/htb/impossible_pass]$
```

The first command that is usually executed in this situation is `strings` since it will print all the human-readable strings inside the binary.

```shell
[dasor@archlinux ~/htb/impossible_pass]$ strings impossible_password.bin
/lib64/ld-linux-x86-64.so.2
libc.so.6
exit
srand
__isoc99_scanf
time
putchar
printf
malloc
strcmp
__libc_start_main
__gmon_start__
GLIBC_2.7
GLIBC_2.2.5
UH-x
UH-x
=1
[]A\A]A^A_
SuperSeKretKey
%20s
[%s]
;*3$"
GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-11)
...
```

We can see the string `SuperSeKretKey` let's try using it as a password.

```shell
[dasor@archlinux ~/htb/impossible_pass]$ ./impossible_password.bin
* SuperSeKretKey
[SuperSeKretKey]
** test
[dasor@archlinux ~/htb/impossible_pass]$
```

Ok, it seems the program needs two passwords but at least we have the first one. Another essential command to reverse engineer binaries is `ltrace` which will trace the library calls while the program is running.

```shell
[dasor@archlinux ~/htb/impossible_pass]$ ltrace ./impossible_password.bin
__libc_start_main(0x40085d, 1, 0x7ffefb240eb8, 0x4009e0 <unfinished ...>
printf("* ")                                                                     = 2
__isoc99_scanf(0x400a82, 0x7ffefb240d80, 0, 0* SuperSeKretKey
)                                   = 1
printf("[%s]\n", "SuperSeKretKey"[SuperSeKretKey]
)                                               = 17
strcmp("SuperSeKretKey", "SuperSeKretKey")                                       = 0
printf("** ")                                                                    = 3
__isoc99_scanf(0x400a82, 0x7ffefb240d80, 0, 0** test
)                                   = 1
time(0)                                                                          = 1671114169
srand(0xc99d3985, 10, 0xc81f9274, 0)                                             = 1
malloc(21)                                                                       = 0x1572ac0
rand(0x1572ac0, 21, 0, 0x1572ac0)                                                = 0x1f83b2cc
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac0, 94)                              = 0x728007
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac1, 94)                              = 0x3e769da8
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac2, 94)                              = 0x4797801b
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac3, 94)                              = 0x32bedf67
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac4, 94)                              = 0x268f26f3
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac5, 94)                              = 0x50ea5aee
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac6, 94)                              = 0xb1483c0
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac7, 94)                              = 0x60d065c
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac8, 94)                              = 0xb50a4e8
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ac9, 94)                              = 0x18831f05
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572aca, 94)                              = 0x70ae13ae
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572acb, 94)                              = 0x5dac08fc
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572acc, 94)                              = 0x31bf401c
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572acd, 94)                              = 0x1730730b
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ace, 94)                              = 0x48284c98
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572acf, 94)                              = 0x3b065243
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ad0, 94)                              = 0x55911dca
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ad1, 94)                              = 0x1d6e072d
rand(0x7f167363b780, 0x7ffefb240ce4, 0x1572ad2, 94)                              = 0x2fe0733c
strcmp("test", "aP;>r:/sy_(=E5~kJc6e")                                           = 19
+++ exited (status 19) +++
```

Once you execute the command it will wait until you input something as the normal program does. However, once we input the second password a bunch of `rand()` functions appear, this means the second password is being generated at runtime. For someone inexperienced, this may seem impossible to crack, but there is a tool that can help us with this. Is the famous reverse engineering tool developed by the **NSA** called `ghidra`.

But before getting our hands dirty I'm going to tell you the plan. So `ghidra` is going to give us both the assembly code and the C code however, both codes are going to be hard to understand since they come directly from the binary i.e. the code has been decompiled.

Next, we are going to search for the comparison of our inputted string and the randomly generated and we are going to change it so the program thinks all keys except the one being generated are correct.

Ok, now let me work you through the process. First, start a new ghidra project and then go to File→Import File and choose the binary. Secondly double-click the binary in the GUI, and the program will ask you if you want to analyze, just accept and use the default values. Now you should have something like this.

![](/assets/images/ImpossiblePass/ghidra1.png)

Next is to search for the code section that contains what we are searching for. This is easy just open the folder called Functions in the Symbol Tree and then go one by one until the decompiled code on the left side looks more or less like what we are looking for. In this case, the function is called `FUN_0040085d`, I know this for sure since In the decompiled C code I can see the **SuperSeKretKey**. By scrolling down a bit we found two if statements exactly what we are looking for.

![](/assets/images/ImpossiblePass/ghidra2.png)

Now to change the if condition you have to know a little bit about assembly. If you click on the statement it will redirect you to the assembly code. In assembly and it is always represented as two instructions a *TEST* and a *jump* in this case **JNZ**. (Make sure you clicked on the second if since we already have the password for the first one).

![](/assets/images/ImpossiblePass/ghidra3.png)

Nevertheless, we only care about the jump statement. **JNZ** means **Jump if not zero** so if we change this to **JZ** meaning **Jump if zero** all the passwords except the one generated would be valid. For a quick reference about jumps, you can look [at this webpage](http://unixwiz.net/techtips/x86-jumps.html).

Now to change the jump hover over the JNZ line right click and choose Patch Instruction then change the instruction. Then go to file Export Program and choose the ELF format. Lastly, let's see if what we did worked.

```shell
[dasor@archlinux ~/htb/impossible_pass]$ ./cracked.bin
* SuperSeKretKey
[SuperSeKretKey]
** a
HTB{...}
```

And the challenge is done! As a side note, I think this challenge is super fun and simple and it also showcases the importance of learning the basics of assembly. As a college student, I've heard many complaints about having to learn assembly but as seen in this post it is a really powerful tool.
