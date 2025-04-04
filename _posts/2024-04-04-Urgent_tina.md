---
title: ASCIS 2024 Urgent Tina Write Up
date: 2025-04-04 00:00:00 + 0800
categories: [Writeups, ASCIS]
tags: [forensics]     

---
## Challenge Description: 
Our client is a pessimist, she is worried that if she does not pay the ransom in the next 8 hours, the hacker will not give her any more chance to get her data back. We are trying to reassure her because we believe that our talented experts can find the cause and restore her data in less than 8 hours.
Author: bquanman

## Thought process

We are given a `.pcca` and a `.DMP` file.

![Files Given](<../assets/img/UrgentTina/Files Given.png>)

Opening the `.pcap` file.

![Opened .pcap file](../assets/img/UrgentTina/2025-04-05_00-25.png)

Let's follow the TCP stream to check what was going on.

![alt text](../assets/img/UrgentTina/2025-04-05_00-28.png)

It's seem to be encoded hmmm, but we were given not only the `.pcap` file but a `.DMP` - a memory dump - maybe the encoded algorithm was in the memory dump. So let the `.pcap` there for now. And inspect the memory dump

