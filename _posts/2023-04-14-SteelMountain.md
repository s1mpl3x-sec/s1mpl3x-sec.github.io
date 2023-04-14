---
layout: single
title: SteelMountain - TryHackMe (OSCP STYLE)
date: 2023-04-14
classes: wide
header:
  teaser: /assets/images/THM-SteelMountain/SteelMountain.png
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

```
sudo nmap -p- -sS --min-rate 5000 --open -T5 -vvv -n -Pn 10.10.178.153 -oG allPorts
```

