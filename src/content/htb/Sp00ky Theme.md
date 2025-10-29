---
title: 'Sp00ky Theme'
issuer: 'HackTheBox'
status: 'Completed'
category: 'Forensics'
difficulty: 'Very Easy'
date: '2025-07-16'
badge: null
certificateLink: null
tags: ['plasma', 'linux', 'backdoor']
---

## Description

![alt text](../../assets/images/HTB/Sp00ky-Theme/image.png)

## Thought process

I downloaded and extracted the archive. It contained a directory with many files, so I opened it in VS Code to inspect them.

![alt text](<../../assets/images/HTB/Sp00ky-Theme/image copy.png>)

Reading the `metadata.json`, I realized this is a plugin for KDE Plasma — a desktop environment similar to GNOME on Ubuntu — from the original repository.

The idea here is a backdoor is installed but we only have the source code. So we can do a quick search (Ctrl+Shift+F) with keyword such as `shell`, `bash`, `whoami`, ...

![alt text](<../../assets/images/HTB/Sp00ky-Theme/image copy 2.png>)

![alt text](<../../assets/images/HTB/Sp00ky-Theme/image copy 3.png>)

Reverse and decode the base64 blob

![alt text](<../../assets/images/HTB/Sp00ky-Theme/image copy 4.png>)

