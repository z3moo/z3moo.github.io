---
title: 'Extraterrestrial Persistence'
issuer: 'HackTheBox'
status: 'Completed'
category: 'Forensics'
difficulty: 'Very Easy'
date: '2025-07-22'
badge: null
certificateLink: null
tags: ['.sh']
---

## Description

![alt text](../../assets/images/HTB/Extraterrestrial_Persistence/image.png)

## Thought Process

Extracting the archive revealed a `.sh` file.

![alt text](<../../assets/images/HTB/Extraterrestrial_Persistence/image copy.png>)

Opening the file, I noticed a base64 blob at the end of the script.

![alt text](<../../assets/images/HTB/Extraterrestrial_Persistence/image copy 2.png>)

Decoding the blob yielded the flag.

![alt text](<../../assets/images/HTB/Extraterrestrial_Persistence/image copy 3.png>)