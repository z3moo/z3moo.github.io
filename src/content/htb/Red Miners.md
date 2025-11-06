---
title: 'Red Miners'
issuer: 'HackTheBox'
status: 'Completed'
category: 'Forensics'
difficulty: 'Very Easy'
date: '2025-07-16'
badge: null
certificateLink: null
tags: ['.sh']
---

## Description

![alt text](../../assets/images/HTB/Red_Miners/image.png)

## Thought process

Extracting the archive gave me a `.sh` file.

![alt text](<../../assets/images/HTB/Red_Miners/image copy.png>)

Opening the file suggested that this is a miner installed for a specific computer.

![alt text](<../../assets/images/HTB/Red_Miners/image copy 2.png>)

Scrolling through the file, I noticed a strange Base64 blob at the end of the script.

![alt text](<../../assets/images/HTB/Red_Miners/image copy 3.png>)

Decoding it yielded the first part of the flag.

![alt text](<../../assets/images/HTB/Red_Miners/image copy 4.png>)

I then searched the entire script for Base64 blobs and found three more.

![alt text](<../../assets/images/HTB/Red_Miners/image copy 5.png>)

![alt text](<../../assets/images/HTB/Red_Miners/image copy 6.png>)

![alt text](<../../assets/images/HTB/Red_Miners/image copy 7.png>)

Decoding all of these gave me the complete flag.

