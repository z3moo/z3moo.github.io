---
title: 'BYUCTF-2025 Writeups'
description: 'All the challenges I solved during BYUCTF-2025, especially forensics'
date: 2025-05-18
tags: ['Writeups', 'Forensics', 'Reverse', 'CTF' ]
image: './banner.webp'
---

## Forensics 
### Are You Looking Me Up?
#### Description 
![alt text](<../../../assets/images/BYUCTF-2025/Are You Looking Me Up.png>)
_Are You Looking Me Up?_

--> Files here <--

#### Thought Process
Let's examine a few lines from the log file.

```bash
┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/for/Are You Looking Me Up]
└─$ cat logs.txt | head -n 20
2025-05-06T14:49:32+00:00 155,,,c0dbc3f4f934c1cb95f41a1f3d23a189,vtnet0,match,pass,in,4,0x0,,128,23413,0,none,17,udp,72,172.16.0.10,172.16.0.1,53829,53,52
2025-05-06T14:49:32+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,41412,0,none,17,udp,72,172.16.0.10,8.8.8.8,53829,53,52
2025-05-06T14:49:32+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,9674,0,DF,6,tcp,52,172.16.0.10,4.149.227.78,65308,443,0,S,3208345317,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:32+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,63011,0,DF,6,tcp,52,172.16.0.10,52.183.205.142,65309,443,0,S,2199077471,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:32+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,21701,0,DF,6,tcp,52,172.16.0.10,13.95.31.18,65310,443,0,S,3089797986,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:32+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,52240,0,DF,6,tcp,52,172.16.0.10,13.69.239.74,65311,443,0,S,1512276322,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:33+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,63030,0,DF,6,tcp,52,172.16.0.10,52.183.205.142,65312,443,0,S,710496243,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:33+00:00 155,,,c0dbc3f4f934c1cb95f41a1f3d23a189,vtnet0,match,pass,in,4,0x0,,128,23414,0,none,17,udp,80,172.16.0.10,172.16.0.1,53269,53,60
2025-05-06T14:49:33+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,40646,0,DF,6,tcp,52,172.16.0.10,209.209.4.232,65313,80,0,S,71362922,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:33+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,21719,0,DF,6,tcp,52,172.16.0.10,13.95.31.18,65314,443,0,S,648020988,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:34+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,128,52254,0,DF,6,tcp,52,172.16.0.10,13.69.239.74,65315,443,0,S,2912397937,,64240,,mss;nop;wscale;nop;nop;sackOK
2025-05-06T14:49:34+00:00 21,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,block,in,4,0x0,,64,22178,0,DF,17,udp,268,192.168.1.20,255.255.255.255,50924,10001,248
2025-05-06T14:49:35+00:00 144,,,4fecac63b6446ce80c3df5c947ca3aa1,vtnet0,match,pass,in,4,0x0,,64,16715,0,DF,6,tcp,60,172.16.96.57,216.239.32.106,49153,53,0,S,1179500,,29200,,mss;sackOK;TS;nop;wscale
2025-05-06T14:49:36+00:00 155,,,c0dbc3f4f934c1cb95f41a1f3d23a189,vtnet0,match,pass,in,4,0x0,,64,22309,0,DF,1,icmp,84,172.16.0.70,172.16.0.1,datalength=64
2025-05-06T14:49:36+00:00 146,,,5c6fe00c82fd64877509b3fc99e38d2c,vtnet0,match,pass,in,4,0x0,,64,60244,0,DF,17,udp,76,172.16.96.10,23.94.221.138,42556,123,56
2025-05-06T14:49:37+00:00 155,,,c0dbc3f4f934c1cb95f41a1f3d23a189,vtnet0,match,pass,in,4,0x0,,64,44534,0,DF,17,udp,56,172.16.0.70,172.16.0.1,39158,53,36
2025-05-06T14:49:39+00:00 155,,,c0dbc3f4f934c1cb95f41a1f3d23a189,vtnet0,match,pass,in,4,0x0,,64,19821,0,DF,6,tcp,64,172.16.0.5,172.16.0.1,51892,53,0,S,1336358162,,64240,,mss;sackOK;TS;nop;wscale;tfo;nop;nop
2025-05-06T14:49:39+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,64,31526,0,DF,6,tcp,60,172.16.0.5,172.67.69.190,38496,443,0,S,1535450510,,64240,,mss;sackOK;TS;nop;wscale
2025-05-06T14:49:39+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,64,53856,0,DF,6,tcp,60,172.16.0.5,172.67.69.190,38512,443,0,S,4087106031,,64240,,mss;sackOK;TS;nop;wscale
2025-05-06T14:49:39+00:00 164,,,75a2b136446ad166a85f3150b40b7d1e,vtnet0,match,pass,in,4,0x0,,64,60169,0,DF,6,tcp,60,172.16.0.5,104.26.10.102,58628,443,0,S,2650452426,,64240,,mss;sackOK;TS;nop;wscale
```
From this log, we can identify which column contains the IP addresses we need to analyze. By determining which IP appears most frequently, we should have our answer.

```bash
┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/for/Are You Looking Me Up]
└─$ cat logs.txt | awk -F',' '$0 ~ /,53,/ {print $20}' | sort | uniq -c | sort -nr
 133444 172.16.0.1
  73490 216.239.32.106
  41183 172.16.96.1
   3614 8.8.8.8
    215 172.16.16.1
    206 172.16.64.1
    130 172.18.0.1
     17 216.239.38.106
     16 216.239.36.106
     15 216.239.34.106
     15 172.16.4.1
      4 199.7.83.42
      4 198.41.0.4
      4 13.107.237.2
      4 13.107.237.1
      3 13.107.238.2
      2 199.180.182.53
      2 192.5.6.30
      2 192.33.14.30
      2 170.247.170.2
      2 13.107.238.1
      2 1.1.1.1
      1 67.202.13.158
      1 50.205.57.38
      1 255.255.255.255
      1 239.255.255.250
      1 23.192.228.231
      1 23.168.136.132
      1 206.226.67.233
      1 204.79.197.1
      1 199.7.91.13
      1 199.26.61.9
      1 199.26.60.53
      1 198.51.44.7
      1 193.0.14.129
      1 192.58.128.30
      1 192.36.148.17
      1 192.26.92.30
      1 185.125.190.56
      1 172.67.69.190
      1 131.253.21.1
```

Code explanation: 
This command processes the log file to identify the most common DNS server IP addresses:

1. `cat logs.txt` - Reads the contents of the log file
2. `awk -F','` - Uses awk with comma as field separator to process each line
3. `$0 ~ /,53,/` - Filters for lines containing port 53 (DNS traffic)
4. `{print $20}` - Extracts the 20th field from each line, which contains destination IP addresses
5. `sort` - Sorts all IP addresses alphabetically
6. `uniq -c` - Counts occurrences of each unique IP address
7. `sort -nr` - Sorts numerically in reverse order, showing most frequent IPs first

The output lists IP addresses by frequency, revealing patterns in the network traffic that could help identify unusual connections or potential security issues. 

-> The flag is `byuctf{172.16.0.1}`
### Mine Over Matter
#### Description 
![alt text](<../../../assets/images/BYUCTF-2025/Mine Over Matter.png>)
_Mine Over Matter_

--> Files Here <--

#### Thought Process
We were given network logs similar to the `Are You Looking Me Up?` challenge. Instead of focusing on specific ports, I needed to analyze the network protocols used by each host.

Most cryptocurrency mining operations use TCP for reliable connections to mining pools, so I filtered by TCP protocol:

```bash
┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/for/Mine over matter]
└─$ grep ",tcp," logs.txt | awk -F',' '{print $19}' | sort | uniq -c | sort -nr
  88374 172.16.0.10
  76841 172.16.0.5
  42252 172.16.96.109
  36801 172.16.96.57
  # ... more IPs with fewer connections
```

TCP protocol is preferred for cryptocurrency mining because:
1. It provides reliable, ordered data transmission critical for mining operations
2. The Stratum mining protocol runs over TCP to ensure no mining work is lost
3. Mining pools require stable connections for consistent performance

The two hosts with abnormally high TCP traffic (172.16.0.10 and 172.16.0.5) showed patterns consistent with mining operations - maintaining persistent TCP connections and communicating with known mining infrastructure.

-> The flag is `byuctf{172.16.0.10_172.16.0.5}`

### Wimdows 
#### Wimdows 1
##### Desciprtion
![alt text](<../../../assets/images/BYUCTF-2025/Wimdows 1.png>)
##### Thought Process
#### Wimdows 2
##### Desciprtion
![alt text](<../../../assets/images/BYUCTF-2025/Wimdows 2.png>)
##### Thought Process
#### Wimdows 3
##### Desciprtion
![alt text](<../../../assets/images/BYUCTF-2025/Wimdows 3.png>)
##### Thought Process
#### Wimdows 4
##### Desciprtion
![alt text](<../../../assets/images/BYUCTF-2025/Wimdows 4.png>)
##### Thought Process
#### Wimdows 5
##### Desciprtion
![alt text](<../../../assets/images/BYUCTF-2025/Wimdows 5.png>)
##### Thought Process

## Reverse Engineering
### u
#### Description
![alt text](../../../assets/images/BYUCTF-2025/u.png)
--> Files Here <--
#### Thought process
We received a Python file, and opening it revealed a long line of code.

```python
ù,ú,û,ü,ũ,ū,ŭ,ů,ű,ų,ṳ,ṷ,ụ=chr,ord,abs,input,all,print,len,input,pow,range,list,dict,set;ù=[12838,1089,16029,13761,1276,14790,2091,17199,2223,2925,17901,3159,18135,18837,3135,19071,4095,19773,4797,4085,20007,5733,20709,17005,2601,9620,3192,9724,3127,8125];u,U=3,256;ṷ=ü();ʉ=ṳ(ụ([ű(u,û,U) for û in(ų(U))]))[u:ŭ(ù)+u];ṳ=zip;ṷ=[ú(û) for û in(ṷ)];assert(ŭ(ù)==ŭ(ṷ));assert(ũ([û*ü==ū for û,ü,ū in(ṳ(ʉ,ṷ,ù))]));
```

Reversing it could reveal our flag, so I created a script to decode it.

```python
# The target values 
targets = [12838, 1089, 16029, 13761, 1276, 14790, 2091, 17199, 2223, 2925,
           17901, 3159, 18135, 18837, 3135, 19071, 4095, 19773, 4797, 4085,
           20007, 5733, 20709, 17005, 2601, 9620, 3192, 9724, 3127, 8125]

# Calculate the powers of 3 
powers = [pow(3, i, 256) for i in range(256)]  
powers = powers[3:3+len(targets)]  # Only keep the ones we need

# Build the flag character by character
flag = ""
for i in range(len(targets)):
    # Try each printable ASCII character (32-126)
    for char_val in range(32, 127):
        if powers[i] * char_val == targets[i]:
            flag += chr(char_val)  
            break

print(flag)  
```

Code explanation:
The challenge gives us a Python script that's deliberately made hard to read. Here's what's going on:

1. **Confusing Variable Names**: The original code uses strange symbols (ù, ú, û, etc.) as variable names:
   - These symbols are assigned to normal Python functions like `chr`, `ord`, `input`
   - This trick makes the code very difficult to understand at first glance

2. **Hidden Array**: Inside this messy code is an array of numbers that holds our encoded flag

3. **How the Encoding Works**: The code uses a simple encoding trick:
   - Each letter of the flag is multiplied by a specific number
   - These numbers are just powers of 3 (limited to stay below 256)
   - The results of these multiplications are stored in the target array

```bash
┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/rev/u]
└─$ python solve.py
byuctf{u_are_good_with_math}
```
Running the script reveals the flag: `byuctf{u_are_good_with_math}`

### LLIR
#### Description 
![alt text](../../../assets/images/BYUCTF-2025/LLIR.png)

--> Files here <--
#### Thought process
The challenge is called `LLIR` which likely refers to [this](https://github.com/llir/llvm) GitHub repository and the `.ll` file format. This suggests we can use LLVM tools to solve this challenge.

We can use LLVM to convert the `.ll` file to `.bc` (LLVM bytecode) and solve it from there, or alternatively, use a tool called llvm-cbe to convert it to C code for easier reading.

```bash
┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/rev/LLDR]
└─$ llvm-as checker.ll -o checker.bc

┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/rev/LLDR]
└─$ ./llvm-cbe/build/tools/llvm-cbe/llvm-cbe checker.bc
```

After examining the converted `.c` file, I discovered a function called `checker_i_hardly_know_her` that could reveal the flag. I then wrote a script to solve for the flag values.

```python
from z3 import BitVec, Solver, sat

flag = [BitVec(f'f{i}', 8) for i in range(37)]
s = Solver()

for c in flag:
    s.add(c >= 32, c <= 126)

for i, ch in enumerate("byuctf"):
    s.add(flag[i] == ord(ch))
s.add(flag[6] == ord('{'))
s.add(flag[36] == ord('}'))

s.add(flag[4] == flag[14])
s.add(flag[14] == flag[17])
s.add(flag[17] == flag[23])
s.add(flag[23] == flag[25])
s.add(flag[9] == flag[20])
s.add(flag[10] == flag[18])
s.add(flag[11] == flag[15])
s.add(flag[15] == flag[24])
s.add(flag[24] == flag[31])
s.add(flag[31] == flag[27])
s.add(flag[13] == flag[26])
s.add(flag[16] == flag[29])
s.add(flag[19] == flag[28])
s.add(flag[28] == flag[32])
s.add(flag[22] == flag[28] * 2)
s.add(flag[33] == flag[32] + 1)
s.add(flag[34] == flag[32] + 4)
s.add(flag[30] == flag[7] + 1)
s.add(flag[8] == flag[7] - 32)
s.add(flag[9] + flag[20] == flag[31] + 3)
s.add(flag[0] == flag[31] + 3)
s.add(flag[10] == flag[7] + 6)
s.add(flag[8] == flag[9] + 27)
s.add(flag[12] == flag[13] - 1)
s.add(flag[13] == flag[10] - 3)
s.add(flag[10] == flag[16] - 1)
s.add(flag[16] == flag[14] - 1)
s.add(flag[35] == flag[5] - 2)
s.add(flag[5] == flag[21] - 1)
s.add(flag[21] == flag[22] - 1)

if s.check() == sat:
    m = s.model()
    output = ''.join([chr(m[c].as_long()) for c in flag])
    print("[+] Flag:", output)
```
```bash
┌──(d4nhwu4n㉿hide-and-seek)-[/mnt/e/CTF/BYUCTF2025/rev/LLDR]
└─$ python solve.py
[+] Flag: byuctf{lL1r_not_str41ght_to_4sm_458d}
```
Running the script revealed the flag: `byuctf{lL1r_not_str41ght_to_4sm_458d}`