---
title: 'BKSEC CTF TTV 2025 Writeups'
description: 'Writeups for all the CTF challenges I solved during BKSEC CTF TTV 2025'
date: 2025-03-02
tags: ['ctf', 'forensics', 'reverse engineering']
image: './banner.png'
---

## Forensics
### introduction2mem4
#### Challenge description
digital forensics go br br

bksec-ttv-2025-challenge1.zip

Password: BKSEC{c96e9c82629dc849a6913037b322874f93806cee572762b97e879626af9c7396}

Author: teebow1e
#### Thought pocess
After unzipping the file we got a memory dump

![image](https://hackmd.io/_uploads/BJj-bRxskx.png)

**Our first question is:**

![image](https://hackmd.io/_uploads/BJmoZRgske.png)

Let's use `volatility3` to analyze the dump to get the answer.

![image](https://hackmd.io/_uploads/rJ6bfCgokg.png)

`The answer is "10"`

**Second Question:**

![image](https://hackmd.io/_uploads/ByrBMCxsyx.png)

Using the same `windows.info` function we could see the system time is "2025-02-20 15:05:26+00:00". This is GMT+0 so convert to Vietnam time which is GMT+7.

`The answer is "2025-02-20 22:05:26"`

**Third Question:**

![image](https://hackmd.io/_uploads/Syp0MRxj1l.png)

Using `windows.pslist (or windows.pstree)` we could see the list of process that is running and output it to a .txt file.

![image](https://hackmd.io/_uploads/HJ4OQCxiyx.png)

Upon inspecting the `pstree.txt`, we could see there are two suspicious file in `/Documents`

![image](https://hackmd.io/_uploads/HJ2gECljJl.png)

`svcost.exe/8144` and `flag2.exe/5228`, after trying both we got the answer

`The answer is "svcost.exe/8144"`

**Fourth Question:**

![image](https://hackmd.io/_uploads/B1P-8Axi1x.png)

Use the same `pstree.txt` to check `svcost.exe` PPID which is `wscript.exe/8268`

`The answer is "wscript.exe/8268"`

**Fifth Question:**

![image](https://hackmd.io/_uploads/ryjDUCxskg.png)

Still using the `pstree.txt` we gonna find a phrase that's gonna be our answer.

![image](https://hackmd.io/_uploads/H1MaIRgi1e.png)

`The answer is "BKSEC{d0_n0t_p4sS_s3cr3TZ_0n_th3_cmDljn3}"`

**Sixth Question:**

![image](https://hackmd.io/_uploads/Sy6kP0xokl.png)

Using the function `windows.netscan` and output it to netscan.txt we could find the answer. 

![image](https://hackmd.io/_uploads/BkerwRgjJe.png)

Remember that `svcost.exe/8144` is our target. Opening `netscan.txt` we could find the ip:port that the target is connected to.

![image](https://hackmd.io/_uploads/r19twCxj1g.png)

`The answer is "103.69.97.144:31337"`

**Final Question:**

![image](https://hackmd.io/_uploads/rklnvRljJe.png)

At the third question we found 2 suspicious file. There is one called `flag2.exe`.

We could use procdump to see what `flag2.exe` is hiding

![image](https://hackmd.io/_uploads/rk0FOAgike.png)

Use `strings` to find what's inside `flag2.exe.img` 

![image](https://hackmd.io/_uploads/HJmCd0lsye.png)

We got the second part of the flag (lol cuz it's flag2.exe duh) 

Doing the same with `svcost.exe` doesn't provide us with the first part of the flag. 

Let's use `windows.filescan` to see what files do we have

![image](https://hackmd.io/_uploads/BklTFRlskg.png)

Use `grep` to find if there is any flag left

![image](https://hackmd.io/_uploads/r1UkcCxjJx.png)

Jackpot ! A flag1.txt ! But we can't dump the file ! Let's just use `strings` on the dump and `grep` for our flag.

![image](https://hackmd.io/_uploads/BkwDcCxokx.png)

Boom ! Combine the two and we got our final answer :3 

`The answer is "BKSEC{l00k_ljk3_w3_h4v3_a_n3w_vol4tilitY_m4st3r_c0mjn9_in2_t0wn}"`

### The worst scenario
#### Challenge description
bksec-ttv-2025-challenge2.zip

pass: BKSEC{752484b9920b2b4b72e196690d925c32288832fe285990aa6bb4fa8276b0be41}

Author: teobi
#### Thought process
Upon unzipping the file we got access.log (fat af) and SQLLog.log

![image](https://hackmd.io/_uploads/rJCwoCljye.png)

**First Question:**

![image](https://hackmd.io/_uploads/ryeF60goyl.png)

The access.log has tons of entries and not all of them are one-liner. So we could use 

`grep -c '^[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}' access.log` 

which will only count the line that has timestamp. 

![image](https://hackmd.io/_uploads/Sk8K0Rgs1e.png)

`The answer is "18397627"`

**Second Question**

![image](https://hackmd.io/_uploads/B1Ln0Rejyg.png)

The timestamp is first collumm of the log so we could use something like

`cut -d' ' -f1 access.log | sort | uniq -c | sort -nr | head -n 10`

which will only take the first field seperated by a ' ' then sorted it in ascending order. Then display the count of unique timestamp then sorted it in descending order.

![image](https://hackmd.io/_uploads/rJQhkkZike.png)

`The answer is "21-02-2023"`

**Third Question**

![image](https://hackmd.io/_uploads/rkQWlJZsJx.png)

Open the access.log and we got the answer ( can't be more obvious, right ?)

![image](https://hackmd.io/_uploads/HJLQx1boyx.png)

`The answer is "10.0.9.4"`

**Fourth Question**

![image](https://hackmd.io/_uploads/H1pIlkWs1l.png)

Finally, we got to use SQLLog.log. Inspecting the file could see this line.

![image](https://hackmd.io/_uploads/S1YTl1bjJe.png)

`The answer is "WIN-BSDM40BT0A0"`

**Fifth Question**

![image](https://hackmd.io/_uploads/H1w-Z1-jkg.png)

Hmm, tricky one. 

![image](https://hackmd.io/_uploads/rkwrfy-j1g.png)

We could try something like this to check how many request are sent in access.log that have any kind of exploit ( or just try everything :D lol)

`Still not very sure if this is the author's thought on "the right track" :P `

`The answer is "sql_injection"`

**Sixth Question**

![image](https://hackmd.io/_uploads/HyYimJbsyg.png)

We indicated that sql_injection was the exploit. We could use that too see which is the endpoint. Using the same command as before

`grep -E "SELECT|INSERT|UPDATE|DELETE|UNION|OR" access.log`

We could see the many of the request was sent to `/GetBookName.aspx`

![image](https://hackmd.io/_uploads/SJtREk-o1x.png)

`The answer is "/GetBookName.aspx"`

**Seventh Question**

![image](https://hackmd.io/_uploads/H1-Mrkbi1e.png)

Using the above image, we could see that the attacker is using `sql_map` and the `User-Agent` is also in there.

`The answer is "sqlmap/1.7.2.16#dev+(https://sqlmap.org)"`

**Eight Question**

![image](https://hackmd.io/_uploads/H1ItrJZskg.png)

Hmmm, `xss` doesn't work here so maybe we need to look somewhere else to find.

The attack begins at 20-02-2023. In the SQLLog.log (post 20-02-2023) we could see these 2 lines.

![image](https://hackmd.io/_uploads/HkSdIyWoyx.png)

This mean the SQL database allow xp_cmdshell. Just search on Google "mitre xp_cmdshell" we could find this website. 

https://attack.mitre.org/techniques/T1505/001/

Thus giving us the ID

`The answer is "T1505.001"`

**Ninth Question**

![image](https://hackmd.io/_uploads/HkjQPy-jkl.png)

In the eight question we know the attacker can use `xp_cmdshell`, we could check does the access.log has any entries that have `xp_cmdshell`

![image](https://hackmd.io/_uploads/HJ9Fw1Wi1g.png)

Look closely, we could see `ngrok` is present. Google searched `ngrok` could somewhat told us that the attacker could be using this to hide from us.

`The answer is "ngrok"`

**Final Question**

![image](https://hackmd.io/_uploads/SJHD_J-ikg.png)

Database question ! Let's check the SQLLog.log first too see what databases we have on our hand.

After inspecting, there are: `Credit, tbl_data, CryptoBox, password and portal`.

Reading the question we could indicate the timestamp we are looking at is `24-02-2023`.

Let's check if the database is accessed in access.log

![image](https://hackmd.io/_uploads/SJ4_t1bskg.png)

Interesting ! Only 3 database has been accessed. But if we look closely, only `portal and Credit` is injected with drop database. Thus indicating us these 2 are the one affected.

`The answer is "Credit,portal"`

## Reverse Engineering
### JACK
#### Thought process
We got a .apk file, using `jadx` we could decompile it to java
 
![image](https://hackmd.io/_uploads/rka8YIZjJg.png)

Use `strings` on everyfile of the decompiled .apk and `grep` for "BKSEC" we got

![image](https://hackmd.io/_uploads/rypZjL-s1x.png)

Two libs file. Using IDA on one of the two (choose the x64 lol, only gods know what eabi is)

![image](https://hackmd.io/_uploads/rJbOsU-j1e.png)

Of course this is not the flag, we could see what function using this with `xrefs graph to`

![image](https://hackmd.io/_uploads/SJBioUZi1l.png)

Check the `Java_com_example_myapplication_MainActivity_stringFromJNI`
Pseudocode by pressing `F5`

![image](https://hackmd.io/_uploads/B13Z0Ibiyg.png)

We got a function called `doSomethings`, checking on it and we got this function 

![image](https://hackmd.io/_uploads/S1IGn8bsyg.png)

After cross referencing with the main function, we could rename all the variables to see what we are dealing with

![image](https://hackmd.io/_uploads/Byla2UbiJe.png)

This is a `XOR` function that XOR each byte of `nemo` with each byte of `fakeflag` (repeatedly if the length of nemo > lenght of fakeflag)

We got `fakeflag` and `len` so we must find `nemo`. Checking with the main function we could indicated that `nemo` is `xmmword_5F0`. Double click on it and we got `nemo`

![image](https://hackmd.io/_uploads/SkYIAUZskl.png)

So now we just need to XOR these two

`nemo: 0, 0, 0, 0, 0, 0, 0x29, 0, 0x52, 0x2F, 0x38, 5, 0x5C, 0x31, 0x29, 0x5C, 0x1F, 0x3D, 0x19, 0x1E, 0x55, 0, 2, 8, 0xC, 0`

`fakeflag: BKSEC{gh3_gh3_v1p_pr0_zay}`

![image](https://hackmd.io/_uploads/HJzCJvZoJg.png)

`The answer is "BKSEC{Nhap_mon_mobile_xiu}"`

## Binary Exploit
### ret2libc
#### Thought process
We got a `bof` and `libc.so.6` file. Use IDA to decompile the bof.

![image](https://hackmd.io/_uploads/S1yy-vWo1g.png)

`main` function ask for input using `fgets` and called `sub_401303` function.

![image](https://hackmd.io/_uploads/BJ6JZvZokl.png)

`sub_401303` print out our name and ask for another input but this time using `gets` thus allowing buffer overflow. `v2` is set at `112` bytes. So we could indicated our padding now including `v2` and `rbp` which result in `120`

Using `checksec` on bof

![image](https://hackmd.io/_uploads/BJjaVwWiJe.png)

NX is enabled so maybe we could use `ROP` too. So we must find `binsh`, `ret` and `pop rdi ; ret` address by using the `libc.so.6` file given to us.

We could use format string to find the libc address. 

WIP :P